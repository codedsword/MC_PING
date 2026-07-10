/* SPDX-License-Identifier: MIT
 * mcproto.c - see mcproto.h for design notes.
 */

#include "mcproto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

/* ---------- internal socket helpers ---------- */

/* send()/recv() aren't guaranteed to move the whole buffer in one call.
 * Fine to ignore for a 20-byte handshake; not fine once payloads get
 * bigger, which is the whole reason this is a module now. */
static int send_all(int sock, const unsigned char *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, data + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int recv_all(int sock, unsigned char *data, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(sock, data + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1; /* peer closed early */
        got += (size_t)n;
    }
    return 0;
}

/* ---------- growable buffer ---------- */

int mc_buf_init(mc_buf_t *buf, size_t initial_cap) {
    if (initial_cap == 0) initial_cap = 64;
    buf->data = malloc(initial_cap);
    if (buf->data == NULL) return -1;
    buf->len = 0;
    buf->cap = initial_cap;
    return 0;
}

void mc_buf_free(mc_buf_t *buf) {
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

int mc_buf_reserve(mc_buf_t *buf, size_t additional) {
    if (buf->len + additional <= buf->cap) return 0;
    size_t new_cap = buf->cap == 0 ? 64 : buf->cap;
    while (new_cap < buf->len + additional) {
        if (new_cap > (SIZE_MAX / 2)) { new_cap = buf->len + additional; break; }
        new_cap *= 2;
    }
    unsigned char *p = realloc(buf->data, new_cap);
    if (p == NULL) return -1;
    buf->data = p;
    buf->cap = new_cap;
    return 0;
}

/* ---------- VarInt / VarLong encode (buffer form, no I/O) ---------- */

static int encode_varint(unsigned char *out, int32_t value) {
    int i = 0;
    uint32_t uval = (uint32_t)value;
    do {
        unsigned char temp = (unsigned char)(uval & 0x7F);
        uval >>= 7;
        if (uval != 0) temp |= 0x80;
        out[i++] = temp;
    } while (uval != 0);
    return i;
}

static int encode_varlong(unsigned char *out, int64_t value) {
    int i = 0;
    uint64_t uval = (uint64_t)value;
    do {
        unsigned char temp = (unsigned char)(uval & 0x7F);
        uval >>= 7;
        if (uval != 0) temp |= 0x80;
        out[i++] = temp;
    } while (uval != 0);
    return i;
}

/* ---------- writers ---------- */

int mc_write_varint(mc_buf_t *buf, int32_t value) {
    unsigned char tmp[5];
    int n = encode_varint(tmp, value);
    if (mc_buf_reserve(buf, (size_t)n) < 0) return -1;
    memcpy(buf->data + buf->len, tmp, (size_t)n);
    buf->len += (size_t)n;
    return 0;
}

int mc_write_varlong(mc_buf_t *buf, int64_t value) {
    unsigned char tmp[10];
    int n = encode_varlong(tmp, value);
    if (mc_buf_reserve(buf, (size_t)n) < 0) return -1;
    memcpy(buf->data + buf->len, tmp, (size_t)n);
    buf->len += (size_t)n;
    return 0;
}

int mc_write_string(mc_buf_t *buf, const char *s) {
    size_t slen = strlen(s);
    if (mc_write_varint(buf, (int32_t)slen) < 0) return -1;
    if (mc_buf_reserve(buf, slen) < 0) return -1;
    memcpy(buf->data + buf->len, s, slen);
    buf->len += slen;
    return 0;
}

int mc_write_u8(mc_buf_t *buf, uint8_t v) {
    if (mc_buf_reserve(buf, 1) < 0) return -1;
    buf->data[buf->len++] = v;
    return 0;
}

int mc_write_u16(mc_buf_t *buf, uint16_t v) {
    if (mc_buf_reserve(buf, 2) < 0) return -1;
    buf->data[buf->len++] = (unsigned char)((v >> 8) & 0xFF);
    buf->data[buf->len++] = (unsigned char)(v & 0xFF);
    return 0;
}

int mc_write_i32(mc_buf_t *buf, int32_t v) {
    if (mc_buf_reserve(buf, 4) < 0) return -1;
    uint32_t uv = (uint32_t)v;
    for (int i = 3; i >= 0; i--) buf->data[buf->len++] = (unsigned char)((uv >> (i * 8)) & 0xFF);
    return 0;
}

int mc_write_i64(mc_buf_t *buf, int64_t v) {
    if (mc_buf_reserve(buf, 8) < 0) return -1;
    uint64_t uv = (uint64_t)v;
    for (int i = 7; i >= 0; i--) buf->data[buf->len++] = (unsigned char)((uv >> (i * 8)) & 0xFF);
    return 0;
}

int mc_write_bool(mc_buf_t *buf, int v) {
    return mc_write_u8(buf, v ? 1 : 0);
}

int mc_write_bytes(mc_buf_t *buf, const void *data, size_t len) {
    if (mc_buf_reserve(buf, len) < 0) return -1;
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return 0;
}

int mc_write_uuid(mc_buf_t *buf, const unsigned char uuid[16]) {
    return mc_write_bytes(buf, uuid, 16);
}

/* ---------- reader ---------- */

void mc_reader_init(mc_reader_t *r, const unsigned char *data, size_t len) {
    r->data = data;
    r->len = len;
    r->pos = 0;
}

size_t mc_reader_remaining(const mc_reader_t *r) {
    return r->len - r->pos;
}

int mc_read_varint(mc_reader_t *r, int32_t *out) {
    int32_t value = 0;
    int position = 0;
    while (1) {
        if (r->pos >= r->len) return -1;
        unsigned char byte = r->data[r->pos++];
        value |= (int32_t)(byte & 0x7F) << position;
        if ((byte & 0x80) == 0) break;
        position += 7;
        if (position >= 32) return -1;
    }
    *out = value;
    return 0;
}

int mc_read_varlong(mc_reader_t *r, int64_t *out) {
    int64_t value = 0;
    int position = 0;
    while (1) {
        if (r->pos >= r->len) return -1;
        unsigned char byte = r->data[r->pos++];
        value |= (int64_t)(byte & 0x7F) << position;
        if ((byte & 0x80) == 0) break;
        position += 7;
        if (position >= 64) return -1;
    }
    *out = value;
    return 0;
}

int mc_read_string(mc_reader_t *r, char **out) {
    int32_t slen;
    if (mc_read_varint(r, &slen) < 0) return -1;
    if (slen < 0 || (size_t)slen > mc_reader_remaining(r)) return -1;
    char *s = malloc((size_t)slen + 1);
    if (s == NULL) return -1;
    memcpy(s, r->data + r->pos, (size_t)slen);
    s[slen] = '\0';
    r->pos += (size_t)slen;
    *out = s;
    return 0;
}

int mc_read_u8(mc_reader_t *r, uint8_t *out) {
    if (mc_reader_remaining(r) < 1) return -1;
    *out = r->data[r->pos++];
    return 0;
}

int mc_read_u16(mc_reader_t *r, uint16_t *out) {
    if (mc_reader_remaining(r) < 2) return -1;
    *out = (uint16_t)((r->data[r->pos] << 8) | r->data[r->pos + 1]);
    r->pos += 2;
    return 0;
}

int mc_read_i32(mc_reader_t *r, int32_t *out) {
    if (mc_reader_remaining(r) < 4) return -1;
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v = (v << 8) | r->data[r->pos + i];
    r->pos += 4;
    *out = (int32_t)v;
    return 0;
}

int mc_read_i64(mc_reader_t *r, int64_t *out) {
    if (mc_reader_remaining(r) < 8) return -1;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | r->data[r->pos + i];
    r->pos += 8;
    *out = (int64_t)v;
    return 0;
}

int mc_read_bytes(mc_reader_t *r, void *out, size_t len) {
    if (mc_reader_remaining(r) < len) return -1;
    memcpy(out, r->data + r->pos, len);
    r->pos += len;
    return 0;
}

/* ---------- connection ---------- */

int mc_connect(mc_conn_t *conn, const char *host, int port) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        return -1;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        int saved_errno = errno;
        freeaddrinfo(res);
        close(sock);
        errno = saved_errno;
        return -1;
    }
    freeaddrinfo(res);

    conn->sock = sock;
    return 0;
}

void mc_close(mc_conn_t *conn) {
    if (conn->sock >= 0) {
        close(conn->sock);
        conn->sock = -1;
    }
}

int mc_sock_read_varint(int sock, int32_t *out) {
    int32_t value = 0;
    int position = 0;
    unsigned char byte;
    while (1) {
        ssize_t n = recv(sock, &byte, 1, 0);
        if (n != 1) return -1;
        value |= (int32_t)(byte & 0x7F) << position;
        if ((byte & 0x80) == 0) break;
        position += 7;
        if (position >= 32) return -1;
    }
    *out = value;
    return 0;
}

/* ---------- framing ---------- */

int mc_send_packet(mc_conn_t *conn, int32_t packet_id, const mc_buf_t *payload) {
    unsigned char id_buf[5];
    int id_len = encode_varint(id_buf, packet_id);

    size_t payload_len = payload ? payload->len : 0;
    unsigned char len_buf[5];
    /* total_len must fit in int32_t per protocol; caller's job to keep
     * fabricated payloads sane, but guard the obviously-broken case. */
    if (payload_len > (size_t)INT32_MAX - (size_t)id_len) {
        errno = EMSGSIZE;
        return -1;
    }
    int32_t total_len = (int32_t)((size_t)id_len + payload_len);
    int len_len = encode_varint(len_buf, total_len);

    if (send_all(conn->sock, len_buf, (size_t)len_len) < 0) return -1;
    if (send_all(conn->sock, id_buf, (size_t)id_len) < 0) return -1;
    if (payload_len > 0 && send_all(conn->sock, payload->data, payload_len) < 0) return -1;
    return 0;
}

int mc_send_raw(mc_conn_t *conn, const unsigned char *data, size_t len) {
    return send_all(conn->sock, data, len);
}

int mc_recv_packet(mc_conn_t *conn, int32_t *out_id,
                    unsigned char **out_payload, int32_t *out_payload_len) {
    int32_t total_len;
    if (mc_sock_read_varint(conn->sock, &total_len) < 0) return -1;
    if (total_len < 0 || total_len > MC_MAX_PACKET_LEN) {
        errno = EMSGSIZE;
        return -1;
    }

    unsigned char *raw = malloc((size_t)total_len);
    if (raw == NULL) return -1;

    if (total_len > 0 && recv_all(conn->sock, raw, (size_t)total_len) < 0) {
        free(raw);
        return -1;
    }

    mc_reader_t r;
    mc_reader_init(&r, raw, (size_t)total_len);

    int32_t packet_id;
    if (mc_read_varint(&r, &packet_id) < 0) {
        free(raw);
        return -1;
    }

    size_t remaining = mc_reader_remaining(&r);
    unsigned char *payload = NULL;
    if (remaining > 0) {
        payload = malloc(remaining);
        if (payload == NULL) {
            free(raw);
            return -1;
        }
        memcpy(payload, raw + r.pos, remaining);
    }
    free(raw);

    *out_id = packet_id;
    *out_payload = payload;
    *out_payload_len = (int32_t)remaining;
    return 0;
}

/* ---------- handshake ---------- */

int mc_build_handshake(mc_buf_t *out, int32_t protocol_version,
                        const char *host, uint16_t port, int32_t next_state) {
    if (mc_write_varint(out, protocol_version) < 0) return -1;
    if (mc_write_string(out, host) < 0) return -1;
    if (mc_write_u16(out, port) < 0) return -1;
    if (mc_write_varint(out, next_state) < 0) return -1;
    return 0;
}

/* ---------- status ping convenience wrapper ---------- */

int mc_status_ping(const char *host, int port, int32_t protocol_version,
                    char **out_json) {
    mc_conn_t conn;
    if (mc_connect(&conn, host, port) < 0) return -1;

    mc_buf_t hs;
    if (mc_buf_init(&hs, 0) < 0 ||
        mc_build_handshake(&hs, protocol_version, host, (uint16_t)port, 1) < 0) {
        mc_buf_free(&hs);
        mc_close(&conn);
        return -1;
    }
    if (mc_send_packet(&conn, 0x00, &hs) < 0) {
        mc_buf_free(&hs);
        mc_close(&conn);
        return -1;
    }
    mc_buf_free(&hs);

    mc_buf_t empty;
    if (mc_buf_init(&empty, 1) < 0) {
        mc_close(&conn);
        return -1;
    }
    if (mc_send_packet(&conn, 0x00, &empty) < 0) {
        mc_buf_free(&empty);
        mc_close(&conn);
        return -1;
    }
    mc_buf_free(&empty);

    int32_t resp_id, payload_len;
    unsigned char *payload = NULL;
    if (mc_recv_packet(&conn, &resp_id, &payload, &payload_len) < 0) {
        mc_close(&conn);
        return -1;
    }
    mc_close(&conn);
    (void)resp_id; /* status response is always 0x00; nothing to branch on */

    mc_reader_t r;
    mc_reader_init(&r, payload, (size_t)payload_len);
    char *json;
    if (mc_read_string(&r, &json) < 0) {
        free(payload);
        return -1;
    }
    free(payload);

    *out_json = json;
    return 0;
}

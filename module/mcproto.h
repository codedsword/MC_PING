/* SPDX-License-Identifier: MIT
 *
 * mcproto - minimal Minecraft protocol primitives, split out as a
 * reusable module instead of living inline in a single CLI tool.
 *
 * Why this exists (vs. the original mc_ping.c internals):
 *   - Buffers are heap-growable (mc_buf_t), not a fixed 512-byte stack
 *     array. Fine for a status ping; not fine the moment you're crafting
 *     arbitrary or oversized packets for fuzzing/exploit work.
 *   - mc_send_raw() lets a caller hand this module a byte stream it
 *     built itself (wrong length prefix, truncated VarInt, garbage
 *     packet id, whatever) and put it on the wire completely untouched.
 *     That's the whole point of a fabrication module: the framing layer
 *     shouldn't get to "fix" what you deliberately made malformed.
 *   - Every read function is bounds-checked against the buffer/stream
 *     it's reading from. Server-supplied length fields are never trusted
 *     blindly (mc_recv_packet caps total packet length, mc_read_string
 *     caps against remaining reader bytes). That matters a lot more
 *     once this thing is pointed at servers/plugins you don't control.
 *   - No JSON, no status-response-specific logic in here at all. That
 *     stays in the consumer (see mc_ping.c). This module only knows
 *     VarInts, framing, and raw bytes.
 *
 * Linux only. Not thread-safe (each mc_conn_t/mc_buf_t/mc_reader_t is
 * independent though, so one per thread is fine).
 */

#ifndef MCPROTO_H
#define MCPROTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hard ceiling on a single incoming packet's declared length, enforced
 * by mc_recv_packet(). A malicious/garbled server can send any VarInt
 * it wants as the length prefix; without a cap that's a trivial
 * multi-megabyte malloc from an untrusted 5-byte input. Bump this if
 * you genuinely need to fabricate/receive bigger packets (e.g. large
 * NBT payloads), but do it deliberately, not by accident. */
#ifndef MC_MAX_PACKET_LEN
#define MC_MAX_PACKET_LEN (4 * 1024 * 1024)
#endif

/* ---------- growable write buffer ---------- */

typedef struct {
    unsigned char *data;
    size_t len;   /* bytes currently written */
    size_t cap;   /* allocated capacity */
} mc_buf_t;

int  mc_buf_init(mc_buf_t *buf, size_t initial_cap); /* 0 = use default */
void mc_buf_free(mc_buf_t *buf);
int  mc_buf_reserve(mc_buf_t *buf, size_t additional);

/* All write functions return 0 on success, -1 on allocation failure. */
int mc_write_varint(mc_buf_t *buf, int32_t value);
int mc_write_varlong(mc_buf_t *buf, int64_t value);
int mc_write_string(mc_buf_t *buf, const char *s);      /* VarInt len + UTF-8 bytes */
int mc_write_u8(mc_buf_t *buf, uint8_t v);
int mc_write_u16(mc_buf_t *buf, uint16_t v);
int mc_write_i32(mc_buf_t *buf, int32_t v);              /* big-endian */
int mc_write_i64(mc_buf_t *buf, int64_t v);               /* big-endian */
int mc_write_bool(mc_buf_t *buf, int v);
int mc_write_bytes(mc_buf_t *buf, const void *data, size_t len); /* no length prefix */
int mc_write_uuid(mc_buf_t *buf, const unsigned char uuid[16]);

/* ---------- cursor-based reader over an in-memory payload ---------- */

typedef struct {
    const unsigned char *data;
    size_t len;
    size_t pos;
} mc_reader_t;

void mc_reader_init(mc_reader_t *r, const unsigned char *data, size_t len);
size_t mc_reader_remaining(const mc_reader_t *r);

/* All read functions return 0 on success, -1 on truncated/invalid input. */
int mc_read_varint(mc_reader_t *r, int32_t *out);
int mc_read_varlong(mc_reader_t *r, int64_t *out);
int mc_read_string(mc_reader_t *r, char **out);   /* mallocs *out, caller frees */
int mc_read_u8(mc_reader_t *r, uint8_t *out);
int mc_read_u16(mc_reader_t *r, uint16_t *out);
int mc_read_i32(mc_reader_t *r, int32_t *out);
int mc_read_i64(mc_reader_t *r, int64_t *out);
int mc_read_bytes(mc_reader_t *r, void *out, size_t len);

/* ---------- connection ---------- */

typedef struct {
    int sock;
} mc_conn_t;

int  mc_connect(mc_conn_t *conn, const char *host, int port); /* 0/-1, perror-friendly errno */
void mc_close(mc_conn_t *conn);

/* Reads a single VarInt directly off the socket, one byte at a time.
 * Needed before a payload's length is known (i.e. before you have
 * anything to hand mc_reader_t). */
int mc_sock_read_varint(int sock, int32_t *out);

/* ---------- framing ---------- */

/* Sends [VarInt total_len][VarInt packet_id][payload]. Loops internally
 * until the whole thing is written (a single send() is not guaranteed
 * to flush everything, especially for larger fabricated payloads). */
int mc_send_packet(mc_conn_t *conn, int32_t packet_id, const mc_buf_t *payload);

/* Sends exactly the bytes given, completely unmodified: no length
 * prefix added, no packet id added. This is the escape hatch for
 * fabricating deliberately malformed packets. */
int mc_send_raw(mc_conn_t *conn, const unsigned char *data, size_t len);

/* Reads one full packet: length-prefix, packet id, and payload.
 * On success, *out_payload is a freshly malloc'd buffer of
 * *out_payload_len bytes (caller frees it) containing everything
 * after the packet id. Returns -1 on I/O error, truncation, or if the
 * declared length exceeds MC_MAX_PACKET_LEN. */
int mc_recv_packet(mc_conn_t *conn, int32_t *out_id,
                    unsigned char **out_payload, int32_t *out_payload_len);

/* ---------- protocol-specific helper (the only non-generic bit) ---------- */

/* Builds a Handshake (0x00) payload into an already-inited buf. */
int mc_build_handshake(mc_buf_t *out, int32_t protocol_version,
                        const char *host, uint16_t port, int32_t next_state);

/* ---------- status ping convenience wrapper ---------- */

/* Does the whole status-ping sequence in one call: connect, send
 * handshake, send status request, read the response, pull out the raw
 * JSON string. Owns the connection lifecycle (closes it before
 * returning, success or failure) so callers don't need mc_conn_t at all
 * for this common case.
 *
 * On success, mallocs *out_json (caller frees it) with the raw JSON
 * text and returns 0. Deliberately does NOT touch cJSON or parse
 * anything -- this module stays JSON-free, parsing is on the caller.
 *
 * Returns -1 on any connect/send/recv/protocol error. This is the one
 * call most callers want; use the primitives above directly for
 * anything more custom (fabrication, fuzzing, other packet types). */
int mc_status_ping(const char *host, int port, int32_t protocol_version,
                    char **out_json);

#ifdef __cplusplus
}
#endif

#endif /* MCPROTO_H */

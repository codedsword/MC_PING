/* SPDX-License-Identifier: MIT
 *  minimal Minecraft protocol client (handshake + status request) in C
 *  built this as a component for a bigger project. nore features will (probably) be addedin the future 
 *
 * I was lowkey too lazy to write my own json parser and shit so i used cJSON
 * packet framing, and the Handshake -> Status flow (no auth required).
 *
 * Only works on linux!!!!!!!!! windows support provably never
 * wrote this on my phone using termux so ive only tested it on that
 *
 * Build:  gcc -O2 -Wall -o mc_ping mc_ping.c -lcjson
 * Usage:  ./mc_ping [-h] [-o <file>] [-b] <host> <port> <protocol_version>
 *
 *   -h          Show help message
 *   -o <file>   Dump the raw status JSON response to <file>
 *   -b          Print the full favicon base64 string instead of just its length
 *
 * Protocol version examples:
 *   767  = 1.21
 *   765  = 1.20.4/1.20.5
 * Check minecraft.wiki/w/Protocol_version_numbers for the version you want.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>      
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <cjson/cJSON.h>

/* ---------- VarInt encode/decode ---------- */

/* Writes a VarInt into buf, returns number of bytes written */
static int write_varint(unsigned char *buf, int32_t value) {
    int i = 0;
    uint32_t uval = (uint32_t)value;
    do {
        unsigned char temp = (unsigned char)(uval & 0x7F);
        uval >>= 7;
        if (uval != 0) temp |= 0x80;
        buf[i++] = temp;
    } while (uval != 0);
    return i;
}

/* Reads a VarInt from a socket, one byte at a time cuz O(n) is tuff */
static int read_varint(int sock, int32_t *out) {
    int32_t value = 0;
    int position = 0;
    unsigned char byte;
    while (1) {
        if (recv(sock, &byte, 1, 0) != 1) return -1;
        value |= (int32_t)(byte & 0x7F) << position;
        if ((byte & 0x80) == 0) break;
        position += 7;
        if (position >= 32) return -1; /* VarInt too big */
    }
    *out = value;
    return 0;
}

/* ---------- Packet buffer helpers ---------- */

typedef struct {
    unsigned char data[512];
    int len;
} PacketBuf;

static void pb_write_varint(PacketBuf *pb, int32_t value) {
    pb->len += write_varint(pb->data + pb->len, value);
}

static void pb_write_string(PacketBuf *pb, const char *s) {
    int slen = (int)strlen(s);
    pb_write_varint(pb, slen);
    memcpy(pb->data + pb->len, s, (size_t)slen);
    pb->len += slen;
}

/* Fixed: Use uint16_t for guaranteed 16-bit behavior on all architectures */
static void pb_write_u16(PacketBuf *pb, uint16_t v) {
    pb->data[pb->len++] = (unsigned char)((v >> 8) & 0xFF);
    pb->data[pb->len++] = (unsigned char)(v & 0xFF);
}

/* Sends a packet: [VarInt length][VarInt packet_id][payload...] */
static int send_packet(int sock, int32_t packet_id, PacketBuf *payload) {
    unsigned char id_buf[5];
    int id_len = write_varint(id_buf, packet_id);

    unsigned char len_buf[5];
    int total_len = id_len + payload->len;
    int len_len = write_varint(len_buf, total_len);

    if (send(sock, len_buf, (size_t)len_len, 0) < 0) return -1;
    if (send(sock, id_buf, (size_t)id_len, 0) < 0) return -1;
    if (payload->len > 0 && send(sock, payload->data, (size_t)payload->len, 0) < 0)
        return -1;
    return 0;
}

/* ---------- Main ---------- */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-h] [-o <file>] [-b] <host> <port> <protocol_version>\n"
        "\n"
        "Minecraft server status pinger (handshake + status request).\n"
        "\n"
        "Options:\n"
        "  -h          Show this help message and exit\n"
        "  -o <file>   Dump raw status JSON response to <file>\n"
        "  -b          Print full favicon base64 instead of just its length\n"
        "\n"
        "Arguments:\n"
        "  host              Server hostname or IP address\n"
        "  port              Server port number (usually 25565)\n"
        "  protocol_version  Minecraft protocol version number\n"
        "\n"
        "Protocol version examples:\n"
        "  767  = 1.21       765  = 1.20.4/1.20.5\n"
        "  764  = 1.20.2     763  = 1.20/1.20.1\n"
        "\n"
        "See: minecraft.wiki/w/Protocol_version_numbers\n",
        prog);
}

int main(int argc, char **argv) {
    const char *dump_path = NULL;
    int show_favicon_full = 0;

    int opt;
    while ((opt = getopt(argc, argv, "ho:b")) != -1) {
        switch (opt) {
            case 'h': print_usage(argv[0]); return 0;
            case 'o': dump_path = optarg; break;
            case 'b': show_favicon_full = 1; break;
            default:  print_usage(argv[0]); return 1;
        }
    }

    if (argc - optind != 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *host = argv[optind];
    int port = atoi(argv[optind + 1]);
    int32_t protocol_version = (int32_t)atoi(argv[optind + 2]);

    /* --- resolve + connect --- */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));  /* Fixed: Explicit memset for portability */
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        perror("getaddrinfo");
        return 1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        perror("socket");
        freeaddrinfo(res);
        return 1;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        freeaddrinfo(res);  /* Fixed: Was missing, caused leak on error(found out thebhard way after my phone exploded) */
        close(sock);
        return 1;
    }
    freeaddrinfo(res);

    /* --- Handshake packet (packet ID 0x00) --- */
    PacketBuf hs = {0};
    pb_write_varint(&hs, protocol_version);
    pb_write_string(&hs, host);
    pb_write_u16(&hs, (uint16_t)port);
    pb_write_varint(&hs, 1); /* next_state = status */

    if (send_packet(sock, 0x00, &hs) < 0) {
        perror("send handshake");
        close(sock);
        return 1;
    }

    /* --- Status Request packet (packet ID 0x00, empty payload) --- */
    PacketBuf empty = {0};
    if (send_packet(sock, 0x00, &empty) < 0) {
        perror("send status request");
        close(sock);
        return 1;
    }

    /* --- Read Status Response (packet ID 0x00, contains JSON string) --- */
    int32_t packet_len;
    if (read_varint(sock, &packet_len) < 0) {
        fprintf(stderr, "failed to read response length\n");
        close(sock);
        return 1;
    }

    int32_t packet_id;
    if (read_varint(sock, &packet_id) < 0) {
        fprintf(stderr, "failed to read packet id\n");
        close(sock);
        return 1;
    }

    int32_t json_len;
    if (read_varint(sock, &json_len) < 0) {
        fprintf(stderr, "failed to read json length\n");
        close(sock);
        return 1;
    }

    char *json = malloc((size_t)json_len + 1);
    if (json == NULL) {
        fprintf(stderr, "malloc failed for json buffer\n");
        close(sock);
        return 1;
    }

    int received = 0;
    while (received < json_len) {
        int n = recv(sock, json + received, (size_t)(json_len - received), 0);
        if (n <= 0) {
            fprintf(stderr, "connection closed early\n");
            free(json);
            close(sock);
            return 1;
        }
        received += n;
    }
    json[json_len] = '\0';

    /* --- Optionally dump raw JSON to file --- */
    if (dump_path != NULL) {
        FILE *f = fopen(dump_path, "w");
        if (f == NULL) {
            perror("fopen");
        } else {
            fwrite(json, 1, (size_t)json_len, f);
            fclose(f);
            printf("Raw JSON written to %s\n", dump_path);
        }
    }

    /* --- Parse with cJSON --- */
    cJSON *root = cJSON_Parse(json);
    if (root == NULL) {
        const char *err = cJSON_GetErrorPtr();
        fprintf(stderr, "JSON parse error near: %s\n", err ? err : "unknown");
        free(json);
        close(sock);
        return 1;
    }

    /* version: { name, protocol } */
    cJSON *version = cJSON_GetObjectItemCaseSensitive(root, "version");
    if (cJSON_IsObject(version)) {
        cJSON *vname = cJSON_GetObjectItemCaseSensitive(version, "name");
        cJSON *vproto = cJSON_GetObjectItemCaseSensitive(version, "protocol");
        printf("Version: %s (protocol %d)\n",
               cJSON_IsString(vname) ? vname->valuestring : "?",
               cJSON_IsNumber(vproto) ? vproto->valueint : -1);
    }

    /* players: { online, max, sample: [{name, id}, ...] } */
    cJSON *players = cJSON_GetObjectItemCaseSensitive(root, "players");
    if (cJSON_IsObject(players)) {
        cJSON *online = cJSON_GetObjectItemCaseSensitive(players, "online");
        cJSON *max = cJSON_GetObjectItemCaseSensitive(players, "max");
        printf("Players: %d/%d\n",
               cJSON_IsNumber(online) ? online->valueint : -1,
               cJSON_IsNumber(max) ? max->valueint : -1);

        cJSON *sample = cJSON_GetObjectItemCaseSensitive(players, "sample");
        if (cJSON_IsArray(sample)) {
            cJSON *entry;
            cJSON_ArrayForEach(entry, sample) {
                cJSON *pname = cJSON_GetObjectItemCaseSensitive(entry, "name");
                if (cJSON_IsString(pname)) {
                    printf("  - %s\n", pname->valuestring);
                }
            }
        }
    }

    /* description (MOTD): either a plain string or a chat component object */
    cJSON *desc = cJSON_GetObjectItemCaseSensitive(root, "description");
    if (cJSON_IsString(desc)) {
        printf("MOTD: %s\n", desc->valuestring);
    } else if (cJSON_IsObject(desc)) {
        cJSON *text = cJSON_GetObjectItemCaseSensitive(desc, "text");
        printf("MOTD: %s\n",
               cJSON_IsString(text) ? text->valuestring : "(complex chat component)");
    }

    /* favicon: data:image/png;base64,<...> */
    cJSON *favicon = cJSON_GetObjectItemCaseSensitive(root, "favicon");
    if (cJSON_IsString(favicon)) {
        if (show_favicon_full) {
            printf("Favicon: %s\n", favicon->valuestring);
        } else {
            printf("Favicon: present (%zu bytes base64, use -b to print it)\n",
                   strlen(favicon->valuestring));
        }
    } else {
        printf("Favicon: none\n");
    }

    cJSON_Delete(root);
    free(json);
    close(sock);
    return 0;
}

// TODO: add base64 decode so icon can be viewed as a png without having to decode it manually


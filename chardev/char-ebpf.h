#ifndef CHAR_EBPF_H
#define CHAR_EBPF_H

#include "qemu/osdep.h"
#include "chardev/char.h"
#include "chardev/char-fe.h"
#include "chardev/char-fd.h"
#include "chardev/char-io.h"
#include "io/channel-buffer.h"
#include "io/net-listener.h"
#include "qemu/sockets.h"
#include "hw/misc/bpf_injection_msg.h"

#define CHARDEV_BPF_BUF_LEN 4096
#define CHARDEV_MIGRATION_BUF_LEN 1024 * 1024 // 1MB

#define MAX_SERVICES 10

#define CHAR_EBPF_DEBUG 1

#if CHAR_EBPF_DEBUG > 0
#define DBG(fmt, ...) do { \
        fprintf(stderr, "char-ebpf: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(fmt, ...)
#endif

struct eBPFChardev {
    FDChardev parent;
    uint32_t last_byte_read;
    QIONetListener *listener;
    SocketAddress *addr;
    uint8_t *buffer;
    QIOChannel *sockets[MAX_SERVICES];
    uint8_t *migration_buffer;
    uint64_t migration_byte_to_read_index;
    uint64_t migration_byte_to_write_index;
};
typedef struct eBPFChardev eBPFChardev;

struct eBPFChardev* get_ebpf_chardev(void);

#endif // CHAR_EBPF_H
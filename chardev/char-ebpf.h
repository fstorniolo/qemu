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

#if CHAR_EBPF_DEBUG > 1
#define DBG_V(fmt, ...) do { \
        fprintf(stderr, "newdev-pci: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG_V(fmt, ...) do {} while (0)
#endif


struct eBPFChardev {
    FDChardev parent;
    uint32_t last_byte_read;
    QIONetListener *listener;
    GSource *timer_src;
    SocketAddress *addr;
    uint8_t *buffer;
    QIOChannel *sockets[MAX_SERVICES];
    uint8_t *migration_buffer;
    uint64_t migration_byte_to_read_index;
    uint64_t migration_byte_to_write_index;

    QemuMutex mutex_migration;
    QemuCond cond_migration;
    bool ready_to_migrate;

};
typedef struct eBPFChardev eBPFChardev;

struct eBPFChardev* get_ebpf_chardev(void);
int write_bpf_program_into_channel(const uint8_t *buffer, int len);

#endif // CHAR_EBPF_H
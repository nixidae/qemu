/*
 * virtio-vsock with its host side in unix sockets, inside QEMU's process.
 *
 * vhost-vsock needs Linux's vhost; this device runs wherever QEMU does,
 * macOS with HVF included. The host side follows Firecracker's mapping:
 *
 *   host -> guest  connect to PATH, write "CONNECT <port>\n", read
 *                  "OK <host port>\n"; the stream is then the guest's port.
 *   guest -> host  the guest connects to CID 2 port P; the device
 *                  connects to the unix socket PATH_P.
 *
 * Stream sockets only. Flow control is virtio-vsock's credit scheme: the
 * device reads a host socket only while the guest has room for the data.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <sys/un.h>
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/iov.h"
#include "qemu/main-loop.h"
#include "qemu/sockets.h"
#include "qemu/units.h"
#include "hw/core/qdev-properties.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-vsock-unix.h"
#include "migration/vmstate.h"
#include "standard-headers/linux/virtio_config.h"
#include "standard-headers/linux/virtio_ids.h"
#include "standard-headers/linux/virtio_vsock.h"

#define VSOCK_HOST_CID      2
#define VSOCK_BUF_ALLOC     (256 * KiB)
#define VSOCK_READ_CHUNK    (16 * KiB)
#define VSOCK_QUEUE_SIZE    128
#define VSOCK_HDR_SIZE      sizeof(struct virtio_vsock_hdr)
#define VSOCK_LINE_MAX      32
/* Above any port a guest is likely to connect to, so the two never meet. */
#define VSOCK_HOST_PORT_BASE (1u << 30)

typedef enum {
    CONN_HOST_HANDSHAKE,    /* host connected; "CONNECT <port>" not read yet */
    CONN_GUEST_PENDING,     /* REQUEST sent to the guest; no answer yet */
    CONN_ESTABLISHED,
    CONN_DRAINING,          /* the guest is gone; to_host still goes out */
} VSockUnixState;

struct VSockUnixConn {
    QTAILQ_ENTRY(VSockUnixConn) next;
    VirtIOVSockUnix *s;
    int fd;
    VSockUnixState state;
    uint32_t local_port;        /* the host side, CID 2 */
    uint32_t peer_port;         /* the guest side */
    GString *line;              /* the handshake line */
    GByteArray *to_guest;       /* read from fd, not yet in the rx queue */
    GByteArray *to_host;        /* from the guest, not yet written to fd */
    uint32_t peer_buf_alloc;
    uint32_t peer_fwd_cnt;
    uint32_t tx_cnt;            /* payload bytes sent to the guest */
    uint32_t fwd_cnt;           /* guest payload bytes written to fd */
    uint32_t fwd_cnt_sent;      /* the fwd_cnt the guest last heard */
    bool host_eof;              /* read on fd returned 0 */
    bool eof_sent;              /* SHUTDOWN(SEND) queued for the guest */
    bool guest_send_done;       /* the guest sent SHUTDOWN(SEND) */
};

struct VSockUnixPkt {
    QTAILQ_ENTRY(VSockUnixPkt) next;
    struct virtio_vsock_hdr hdr;
};

static void vsock_rx_flush(VirtIOVSockUnix *s);
static void conn_update_handlers(VSockUnixConn *c);
static void conn_write(void *opaque);

static void trace_pkt(const char *dir, const struct virtio_vsock_hdr *h)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = getenv("VSOCK_UNIX_DEBUG") != NULL;
    }
    if (enabled) {
        fprintf(stderr, "vsock %s op=%u %u->%u len=%u flags=%u buf_alloc=%u "
                "fwd_cnt=%u\n", dir, le16_to_cpu(h->op),
                le32_to_cpu(h->src_port), le32_to_cpu(h->dst_port),
                le32_to_cpu(h->len), le32_to_cpu(h->flags),
                le32_to_cpu(h->buf_alloc), le32_to_cpu(h->fwd_cnt));
    }
}

static void hdr_init(struct virtio_vsock_hdr *h, VirtIOVSockUnix *s,
                     uint32_t src_port, uint32_t dst_port, uint16_t op,
                     uint32_t len, uint32_t flags, uint32_t fwd_cnt)
{
    memset(h, 0, sizeof(*h));
    h->src_cid = cpu_to_le64(VSOCK_HOST_CID);
    h->dst_cid = cpu_to_le64(s->guest_cid);
    h->src_port = cpu_to_le32(src_port);
    h->dst_port = cpu_to_le32(dst_port);
    h->len = cpu_to_le32(len);
    h->type = cpu_to_le16(VIRTIO_VSOCK_TYPE_STREAM);
    h->op = cpu_to_le16(op);
    h->flags = cpu_to_le32(flags);
    h->buf_alloc = cpu_to_le32(VSOCK_BUF_ALLOC);
    h->fwd_cnt = cpu_to_le32(fwd_cnt);
}

static void queue_ctrl(VirtIOVSockUnix *s, uint32_t src_port,
                       uint32_t dst_port, uint16_t op, uint32_t flags,
                       uint32_t fwd_cnt)
{
    VSockUnixPkt *p = g_new0(VSockUnixPkt, 1);

    hdr_init(&p->hdr, s, src_port, dst_port, op, 0, flags, fwd_cnt);
    QTAILQ_INSERT_TAIL(&s->ctrl, p, next);
}

static void conn_ctrl(VSockUnixConn *c, uint16_t op, uint32_t flags)
{
    queue_ctrl(c->s, c->local_port, c->peer_port, op, flags, c->fwd_cnt);
    c->fwd_cnt_sent = c->fwd_cnt;
}

static VSockUnixConn *conn_new(VirtIOVSockUnix *s, int fd,
                               VSockUnixState state)
{
    VSockUnixConn *c = g_new0(VSockUnixConn, 1);
#ifdef SO_NOSIGPIPE
    int one = 1;

    /* macOS has no MSG_NOSIGNAL: a write to a closed peer must not kill QEMU */
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    qemu_set_blocking(fd, false, NULL);
    c->s = s;
    c->fd = fd;
    c->state = state;
    c->line = g_string_new(NULL);
    c->to_guest = g_byte_array_new();
    c->to_host = g_byte_array_new();
    QTAILQ_INSERT_TAIL(&s->conns, c, next);
    return c;
}

static void conn_free(VSockUnixConn *c)
{
    qemu_set_fd_handler(c->fd, NULL, NULL, NULL);
    close(c->fd);
    QTAILQ_REMOVE(&c->s->conns, c, next);
    g_string_free(c->line, true);
    g_byte_array_unref(c->to_guest);
    g_byte_array_unref(c->to_host);
    g_free(c);
}

/*
 * The guest closed: a RST often arrives in the same batch as its last data,
 * so that data goes out to the host before the socket closes.
 */
static void conn_close_after_drain(VSockUnixConn *c)
{
    if (c->to_host->len == 0) {
        conn_free(c);
        return;
    }
    c->state = CONN_DRAINING;
    qemu_set_fd_handler(c->fd, NULL, conn_write, c);
}

/* Drop the connection; the guest hears RST if it knows the connection. */
static void conn_reset(VSockUnixConn *c)
{
    if (c->state == CONN_GUEST_PENDING || c->state == CONN_ESTABLISHED) {
        conn_ctrl(c, VIRTIO_VSOCK_OP_RST, 0);
    }
    conn_free(c);
}

static VSockUnixConn *conn_find(VirtIOVSockUnix *s, uint32_t local_port,
                                uint32_t peer_port)
{
    VSockUnixConn *c;

    QTAILQ_FOREACH(c, &s->conns, next) {
        if ((c->state == CONN_GUEST_PENDING || c->state == CONN_ESTABLISHED) &&
            c->local_port == local_port && c->peer_port == peer_port) {
            return c;
        }
    }
    return NULL;
}

static uint32_t conn_peer_credit(VSockUnixConn *c)
{
    uint32_t in_flight = c->tx_cnt - c->peer_fwd_cnt;

    return in_flight >= c->peer_buf_alloc ? 0 : c->peer_buf_alloc - in_flight;
}

static uint32_t alloc_host_port(VirtIOVSockUnix *s)
{
    VSockUnixConn *c;
    uint32_t port;
    bool used;

    do {
        port = VSOCK_HOST_PORT_BASE | (s->next_port++ & (VSOCK_HOST_PORT_BASE - 1));
        used = false;
        QTAILQ_FOREACH(c, &s->conns, next) {
            used |= c->state != CONN_HOST_HANDSHAKE && c->local_port == port;
        }
    } while (used);
    return port;
}

/* Returns false if the handshake failed and @c is gone. */
static bool conn_read_handshake(VSockUnixConn *c)
{
    unsigned int port;
    char ch;
    ssize_t n;

    for (;;) {
        n = read(c->fd, &ch, 1);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return true;
        }
        if (n <= 0) {
            conn_free(c);
            return false;
        }
        if (ch == '\n') {
            break;
        }
        if (c->line->len >= VSOCK_LINE_MAX) {
            conn_free(c);
            return false;
        }
        g_string_append_c(c->line, ch);
    }
    if (sscanf(c->line->str, "CONNECT %u", &port) != 1) {
        conn_free(c);
        return false;
    }
    c->local_port = alloc_host_port(c->s);
    c->peer_port = port;
    c->state = CONN_GUEST_PENDING;
    conn_ctrl(c, VIRTIO_VSOCK_OP_REQUEST, 0);
    return true;
}

static void conn_read(void *opaque)
{
    VSockUnixConn *c = opaque;
    VirtIOVSockUnix *s = c->s;
    uint8_t buf[VSOCK_READ_CHUNK];
    uint32_t room;
    ssize_t n;

    if (c->state == CONN_HOST_HANDSHAKE) {
        if (!conn_read_handshake(c)) {
            return;
        }
    } else if (c->state == CONN_ESTABLISHED) {
        room = conn_peer_credit(c);
        room = room > c->to_guest->len ? room - c->to_guest->len : 0;
        n = read(c->fd, buf, MIN(room, sizeof(buf)));
        if (n > 0) {
            g_byte_array_append(c->to_guest, buf, n);
        } else if (n == 0) {
            c->host_eof = true;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            conn_reset(c);
            vsock_rx_flush(s);
            return;
        }
    }
    conn_update_handlers(c);
    vsock_rx_flush(s);
}

static void conn_write(void *opaque)
{
    VSockUnixConn *c = opaque;
    VirtIOVSockUnix *s = c->s;
    ssize_t n;

    n = write(c->fd, c->to_host->data, c->to_host->len);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            conn_reset(c);
            vsock_rx_flush(s);
        }
        return;
    }
    g_byte_array_remove_range(c->to_host, 0, n);
    c->fwd_cnt += n;
    if (c->state == CONN_DRAINING) {
        if (c->to_host->len == 0) {
            conn_free(c);
        }
        return;
    }
    if (c->to_host->len == 0 && c->guest_send_done) {
        shutdown(c->fd, SHUT_WR);
    }
    if (c->fwd_cnt - c->fwd_cnt_sent >= VSOCK_BUF_ALLOC / 4) {
        conn_ctrl(c, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0);
    }
    conn_update_handlers(c);
    vsock_rx_flush(s);
}

static void conn_update_handlers(VSockUnixConn *c)
{
    bool want_read = c->state == CONN_HOST_HANDSHAKE ||
        (c->state == CONN_ESTABLISHED && !c->host_eof &&
         c->to_guest->len < conn_peer_credit(c));
    bool want_write = c->to_host->len > 0;

    qemu_set_fd_handler(c->fd, want_read ? conn_read : NULL,
                        want_write ? conn_write : NULL, c);
}

/* The next connection with payload or an EOF for the guest. */
static VSockUnixConn *conn_next_to_guest(VirtIOVSockUnix *s)
{
    VSockUnixConn *c;

    QTAILQ_FOREACH(c, &s->conns, next) {
        if (c->state != CONN_ESTABLISHED) {
            continue;
        }
        if (c->to_guest->len > 0 && conn_peer_credit(c) > 0) {
            return c;
        }
        if (c->host_eof && !c->eof_sent && c->to_guest->len == 0) {
            return c;
        }
    }
    return NULL;
}

static void vsock_rx_flush(VirtIOVSockUnix *s)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(s);
    bool pushed = false;

    if (!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        return;
    }
    for (;;) {
        VSockUnixPkt *p = QTAILQ_FIRST(&s->ctrl);
        VSockUnixConn *c = p ? NULL : conn_next_to_guest(s);
        VirtQueueElement *elem;
        struct virtio_vsock_hdr h;
        size_t cap, len = 0;

        if (!p && !c) {
            break;
        }
        elem = virtqueue_pop(s->rx_vq, sizeof(VirtQueueElement));
        if (!elem) {
            break;
        }
        cap = iov_size(elem->in_sg, elem->in_num);
        if (cap < VSOCK_HDR_SIZE) {
            virtio_error(vdev, "virtio-vsock-unix: rx buffer of %zu bytes",
                         cap);
            virtqueue_detach_element(s->rx_vq, elem, 0);
            g_free(elem);
            break;
        }
        if (p) {
            h = p->hdr;
            QTAILQ_REMOVE(&s->ctrl, p, next);
            g_free(p);
        } else if (c->to_guest->len > 0) {
            len = MIN(MIN(c->to_guest->len, cap - VSOCK_HDR_SIZE),
                      conn_peer_credit(c));
            hdr_init(&h, s, c->local_port, c->peer_port, VIRTIO_VSOCK_OP_RW,
                     len, 0, c->fwd_cnt);
            c->fwd_cnt_sent = c->fwd_cnt;
        } else {
            hdr_init(&h, s, c->local_port, c->peer_port,
                     VIRTIO_VSOCK_OP_SHUTDOWN, 0, VIRTIO_VSOCK_SHUTDOWN_SEND,
                     c->fwd_cnt);
            c->eof_sent = true;
        }
        trace_pkt("to-guest", &h);
        iov_from_buf(elem->in_sg, elem->in_num, 0, &h, VSOCK_HDR_SIZE);
        if (len) {
            iov_from_buf(elem->in_sg, elem->in_num, VSOCK_HDR_SIZE,
                         c->to_guest->data, len);
            g_byte_array_remove_range(c->to_guest, 0, len);
            c->tx_cnt += len;
            conn_update_handlers(c);
        }
        virtqueue_push(s->rx_vq, elem, VSOCK_HDR_SIZE + len);
        g_free(elem);
        pushed = true;
    }
    if (pushed) {
        virtio_notify(vdev, s->rx_vq);
    }
}

/* The guest connects to host port @port: the device connects to PATH_port. */
static void vsock_guest_connect(VirtIOVSockUnix *s, uint32_t port,
                                uint32_t peer_port,
                                const struct virtio_vsock_hdr *h)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    VSockUnixConn *c;
    int fd;

    if (snprintf(addr.sun_path, sizeof(addr.sun_path), "%s_%u", s->path,
                 port) >= sizeof(addr.sun_path)) {
        queue_ctrl(s, port, peer_port, VIRTIO_VSOCK_OP_RST, 0, 0);
        return;
    }
    fd = qemu_socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        queue_ctrl(s, port, peer_port, VIRTIO_VSOCK_OP_RST, 0, 0);
        return;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        queue_ctrl(s, port, peer_port, VIRTIO_VSOCK_OP_RST, 0, 0);
        return;
    }
    c = conn_new(s, fd, CONN_ESTABLISHED);
    c->local_port = port;
    c->peer_port = peer_port;
    c->peer_buf_alloc = le32_to_cpu(h->buf_alloc);
    c->peer_fwd_cnt = le32_to_cpu(h->fwd_cnt);
    conn_ctrl(c, VIRTIO_VSOCK_OP_RESPONSE, 0);
    conn_update_handlers(c);
}

static void vsock_tx_packet(VirtIOVSockUnix *s, VirtQueueElement *elem,
                            const struct virtio_vsock_hdr *h, size_t payload)
{
    uint16_t op = le16_to_cpu(h->op);
    uint32_t local = le32_to_cpu(h->dst_port);
    uint32_t peer = le32_to_cpu(h->src_port);
    uint32_t flags = le32_to_cpu(h->flags);
    size_t len = MIN(le32_to_cpu(h->len), payload);
    VSockUnixConn *c;
    char line[VSOCK_LINE_MAX];

    if (le64_to_cpu(h->dst_cid) != VSOCK_HOST_CID ||
        le16_to_cpu(h->type) != VIRTIO_VSOCK_TYPE_STREAM) {
        if (op != VIRTIO_VSOCK_OP_RST) {
            queue_ctrl(s, local, peer, VIRTIO_VSOCK_OP_RST, 0, 0);
        }
        return;
    }
    c = conn_find(s, local, peer);
    if (op == VIRTIO_VSOCK_OP_REQUEST) {
        if (c) {
            conn_reset(c);
        }
        vsock_guest_connect(s, local, peer, h);
        return;
    }
    if (!c) {
        if (op != VIRTIO_VSOCK_OP_RST) {
            queue_ctrl(s, local, peer, VIRTIO_VSOCK_OP_RST, 0, 0);
        }
        return;
    }
    c->peer_buf_alloc = le32_to_cpu(h->buf_alloc);
    c->peer_fwd_cnt = le32_to_cpu(h->fwd_cnt);

    switch (op) {
    case VIRTIO_VSOCK_OP_RESPONSE:
        if (c->state != CONN_GUEST_PENDING) {
            conn_reset(c);
            return;
        }
        c->state = CONN_ESTABLISHED;
        snprintf(line, sizeof(line), "OK %u\n", c->local_port);
        /* The reply line is not guest payload: it stays out of fwd_cnt. */
        if (write(c->fd, line, strlen(line)) != strlen(line)) {
            conn_reset(c);
            return;
        }
        break;
    case VIRTIO_VSOCK_OP_RW:
        if (c->state != CONN_ESTABLISHED) {
            conn_reset(c);
            return;
        }
        if (len) {
            size_t old = c->to_host->len;

            g_byte_array_set_size(c->to_host, old + len);
            iov_to_buf(elem->out_sg, elem->out_num, VSOCK_HDR_SIZE,
                       c->to_host->data + old, len);
        }
        break;
    case VIRTIO_VSOCK_OP_CREDIT_REQUEST:
        conn_ctrl(c, VIRTIO_VSOCK_OP_CREDIT_UPDATE, 0);
        break;
    case VIRTIO_VSOCK_OP_SHUTDOWN:
        if (flags & VIRTIO_VSOCK_SHUTDOWN_SEND) {
            c->guest_send_done = true;
            if (c->to_host->len == 0) {
                shutdown(c->fd, SHUT_WR);
            }
        }
        if ((flags & (VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND)) ==
            (VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND)) {
            conn_ctrl(c, VIRTIO_VSOCK_OP_RST, 0);
            conn_close_after_drain(c);
            return;
        }
        break;
    case VIRTIO_VSOCK_OP_RST:
        conn_close_after_drain(c);
        return;
    default:
        break;
    }
    conn_update_handlers(c);
}

static void vsock_handle_tx(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOVSockUnix *s = VIRTIO_VSOCK_UNIX(vdev);
    VirtQueueElement *elem;
    struct virtio_vsock_hdr h;
    size_t total;

    while ((elem = virtqueue_pop(vq, sizeof(VirtQueueElement)))) {
        total = iov_size(elem->out_sg, elem->out_num);
        if (total >= VSOCK_HDR_SIZE) {
            iov_to_buf(elem->out_sg, elem->out_num, 0, &h, VSOCK_HDR_SIZE);
            trace_pkt("from-guest", &h);
            vsock_tx_packet(s, elem, &h, total - VSOCK_HDR_SIZE);
        }
        virtqueue_push(vq, elem, 0);
        g_free(elem);
    }
    virtio_notify(vdev, vq);
    vsock_rx_flush(s);
}

static void vsock_handle_rx(VirtIODevice *vdev, VirtQueue *vq)
{
    vsock_rx_flush(VIRTIO_VSOCK_UNIX(vdev));
}

static void vsock_handle_event(VirtIODevice *vdev, VirtQueue *vq)
{
}

static void vsock_accept(void *opaque)
{
    VirtIOVSockUnix *s = opaque;
    VSockUnixConn *c;
    int fd = qemu_accept(s->listen_fd, NULL, NULL);

    if (fd < 0) {
        return;
    }
    c = conn_new(s, fd, CONN_HOST_HANDSHAKE);
    conn_update_handlers(c);
}

static void vsock_close_all(VirtIOVSockUnix *s)
{
    VSockUnixConn *c, *c_next;
    VSockUnixPkt *p, *p_next;

    QTAILQ_FOREACH_SAFE(c, &s->conns, next, c_next) {
        conn_free(c);
    }
    QTAILQ_FOREACH_SAFE(p, &s->ctrl, next, p_next) {
        QTAILQ_REMOVE(&s->ctrl, p, next);
        g_free(p);
    }
}

static void vsock_get_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtIOVSockUnix *s = VIRTIO_VSOCK_UNIX(vdev);
    struct virtio_vsock_config cfg = {};

    cfg.guest_cid = cpu_to_le64(s->guest_cid);
    memcpy(config, &cfg, sizeof(cfg));
}

static uint64_t vsock_get_features(VirtIODevice *vdev, uint64_t features,
                                   Error **errp)
{
    return features;
}

static int vsock_set_status(VirtIODevice *vdev, uint8_t status)
{
    if (status & VIRTIO_CONFIG_S_DRIVER_OK) {
        vsock_rx_flush(VIRTIO_VSOCK_UNIX(vdev));
    }
    return 0;
}

static void vsock_reset(VirtIODevice *vdev)
{
    vsock_close_all(VIRTIO_VSOCK_UNIX(vdev));
}

static void vsock_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOVSockUnix *s = VIRTIO_VSOCK_UNIX(dev);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };

    if (!s->path) {
        error_setg(errp, "virtio-vsock-unix: 'path' is required");
        return;
    }
    if (s->guest_cid <= VSOCK_HOST_CID || s->guest_cid >= UINT32_MAX) {
        error_setg(errp, "virtio-vsock-unix: guest-cid must be above 2 "
                   "and below 2^32 - 1");
        return;
    }
    /* PATH_<port> must fit too, so leave room for the longest port. */
    if (strlen(s->path) + 12 >= sizeof(addr.sun_path)) {
        error_setg(errp, "virtio-vsock-unix: path '%s' is too long", s->path);
        return;
    }
    pstrcpy(addr.sun_path, sizeof(addr.sun_path), s->path);
    s->listen_fd = qemu_socket(AF_UNIX, SOCK_STREAM, 0);
    if (s->listen_fd < 0) {
        error_setg_errno(errp, errno, "virtio-vsock-unix: socket");
        return;
    }
    unlink(s->path);
    if (bind(s->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(s->listen_fd, 16) < 0) {
        error_setg_errno(errp, errno, "virtio-vsock-unix: listen on '%s'",
                         s->path);
        close(s->listen_fd);
        return;
    }
    qemu_set_blocking(s->listen_fd, false, NULL);
    qemu_set_fd_handler(s->listen_fd, vsock_accept, NULL, s);

    QTAILQ_INIT(&s->conns);
    QTAILQ_INIT(&s->ctrl);
    virtio_init(vdev, VIRTIO_ID_VSOCK, sizeof(struct virtio_vsock_config));
    s->rx_vq = virtio_add_queue(vdev, VSOCK_QUEUE_SIZE, vsock_handle_rx);
    s->tx_vq = virtio_add_queue(vdev, VSOCK_QUEUE_SIZE, vsock_handle_tx);
    s->event_vq = virtio_add_queue(vdev, VSOCK_QUEUE_SIZE, vsock_handle_event);
}

static void vsock_unrealize(DeviceState *dev)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOVSockUnix *s = VIRTIO_VSOCK_UNIX(dev);

    vsock_close_all(s);
    qemu_set_fd_handler(s->listen_fd, NULL, NULL, NULL);
    close(s->listen_fd);
    unlink(s->path);
    virtio_delete_queue(s->rx_vq);
    virtio_delete_queue(s->tx_vq);
    virtio_delete_queue(s->event_vq);
    virtio_cleanup(vdev);
}

static const VMStateDescription vmstate_virtio_vsock_unix = {
    .name = "virtio-vsock-unix",
    .unmigratable = 1,
};

static const Property vsock_properties[] = {
    DEFINE_PROP_STRING("path", VirtIOVSockUnix, path),
    DEFINE_PROP_UINT64("guest-cid", VirtIOVSockUnix, guest_cid, 3),
};

static void vsock_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    device_class_set_props(dc, vsock_properties);
    dc->vmsd = &vmstate_virtio_vsock_unix;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    vdc->realize = vsock_realize;
    vdc->unrealize = vsock_unrealize;
    vdc->get_config = vsock_get_config;
    vdc->get_features = vsock_get_features;
    vdc->set_status = vsock_set_status;
    vdc->reset = vsock_reset;
}

static const TypeInfo vsock_info = {
    .name = TYPE_VIRTIO_VSOCK_UNIX,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOVSockUnix),
    .class_init = vsock_class_init,
};

static void vsock_register_types(void)
{
    type_register_static(&vsock_info);
}

type_init(vsock_register_types)

/*
 * virtio-vsock with its host side in unix sockets
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_VIRTIO_VSOCK_UNIX_H
#define HW_VIRTIO_VSOCK_UNIX_H

#include "hw/virtio/virtio.h"
#include "qemu/queue.h"
#include "qom/object.h"

#define TYPE_VIRTIO_VSOCK_UNIX "virtio-vsock-unix-device"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOVSockUnix, VIRTIO_VSOCK_UNIX)

typedef struct VSockUnixConn VSockUnixConn;
typedef struct VSockUnixPkt VSockUnixPkt;

struct VirtIOVSockUnix {
    VirtIODevice parent_obj;

    VirtQueue *rx_vq;
    VirtQueue *tx_vq;
    VirtQueue *event_vq;

    uint64_t guest_cid;
    char *path;
    int listen_fd;
    uint32_t next_port;

    QTAILQ_HEAD(, VSockUnixConn) conns;
    QTAILQ_HEAD(, VSockUnixPkt) ctrl;
};

#endif

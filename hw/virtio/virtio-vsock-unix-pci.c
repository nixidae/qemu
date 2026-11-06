/*
 * virtio-vsock-unix PCI bindings
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/virtio/virtio-pci.h"
#include "hw/virtio/virtio-vsock-unix.h"
#include "hw/core/qdev-properties.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qom/object.h"

typedef struct VirtIOVSockUnixPCI VirtIOVSockUnixPCI;

#define TYPE_VIRTIO_VSOCK_UNIX_PCI "virtio-vsock-unix-pci-base"
DECLARE_INSTANCE_CHECKER(VirtIOVSockUnixPCI, VIRTIO_VSOCK_UNIX_PCI,
                         TYPE_VIRTIO_VSOCK_UNIX_PCI)

struct VirtIOVSockUnixPCI {
    VirtIOPCIProxy parent_obj;
    VirtIOVSockUnix vdev;
};

static const Property virtio_vsock_unix_pci_properties[] = {
    DEFINE_PROP_UINT32("vectors", VirtIOPCIProxy, nvectors, 3),
};

static void virtio_vsock_unix_pci_realize(VirtIOPCIProxy *vpci_dev,
                                          Error **errp)
{
    VirtIOVSockUnixPCI *dev = VIRTIO_VSOCK_UNIX_PCI(vpci_dev);

    /* virtio-vsock is a virtio 1.0 device only: device id 0x1053. */
    virtio_pci_force_virtio_1(vpci_dev);
    qdev_realize(DEVICE(&dev->vdev), BUS(&vpci_dev->bus), errp);
}

static void virtio_vsock_unix_pci_class_init(ObjectClass *klass,
                                             const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);

    k->realize = virtio_vsock_unix_pci_realize;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    device_class_set_props(dc, virtio_vsock_unix_pci_properties);
    pcidev_k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    pcidev_k->device_id = PCI_DEVICE_ID_VIRTIO_VSOCK;
    pcidev_k->revision = 0x00;
    pcidev_k->class_id = PCI_CLASS_COMMUNICATION_OTHER;
}

static void virtio_vsock_unix_pci_instance_init(Object *obj)
{
    VirtIOVSockUnixPCI *dev = VIRTIO_VSOCK_UNIX_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_VSOCK_UNIX);
}

static const VirtioPCIDeviceTypeInfo virtio_vsock_unix_pci_info = {
    .base_name             = TYPE_VIRTIO_VSOCK_UNIX_PCI,
    .generic_name          = "virtio-vsock-unix-pci",
    .non_transitional_name = "virtio-vsock-unix-pci-non-transitional",
    .instance_size = sizeof(VirtIOVSockUnixPCI),
    .instance_init = virtio_vsock_unix_pci_instance_init,
    .class_init    = virtio_vsock_unix_pci_class_init,
};

static void virtio_vsock_unix_pci_register(void)
{
    virtio_pci_types_register(&virtio_vsock_unix_pci_info);
}

type_init(virtio_vsock_unix_pci_register)

/*
 * vhost-vdpa
 *
 *  Copyright(c) 2017-2018 Intel Corporation. All rights reserved.
 *  Copyright (C) 2020 Red Hat, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include <linux/vhost.h>
#include <linux/vfio.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include "hw/virtio/vhost.h"
#include "hw/virtio/vhost-backend.h"
#include "hw/virtio/virtio-net.h"
#include "hw/virtio/vhost-vdpa.h"
#include "qemu/main-loop.h"
#include <linux/kvm.h>
#include "sysemu/kvm.h"

struct vhost_vdpa {
    VhostVDPA *vdpa;
    MemoryListener listener;
    uint64_t backend_features;
};


static bool vhost_vdpa_listener_skipped_section(MemoryRegionSection *section)
{
    return (!memory_region_is_ram(section->mr) &&
            !memory_region_is_iommu(section->mr)) ||
           /*
            * Sizing an enabled 64-bit BAR can cause spurious mappings to
            * addresses in the upper part of the 64-bit address space.  These
            * are never accessed by the CPU and beyond the address width of
            * some IOMMU hardware.  TODO: VFIO should tell us the IOMMU width.
            */
           section->offset_within_address_space & (1ULL << 63);
}

static int vhost_vdpa_dma_map(struct vhost_vdpa *v, hwaddr iova, hwaddr size,
                              void *vaddr, bool readonly)
{
    VhostVDPA *vdpa = v->vdpa;
    struct vhost_msg_v2 msg;
    int fd = vdpa->device_fd;
    int ret = 0;
    bool v2 = v->backend_features & (1ULL << VHOST_BACKEND_F_IOTLB_MSG_V2);
    if (!v2) {
        error_report("failed msg version write");
        return -1;
    }
    msg.type = VHOST_IOTLB_MSG_V2;
    msg.iotlb.iova = iova;
    msg.iotlb.size = size;
    msg.iotlb.uaddr = (uint64_t)vaddr;
    msg.iotlb.perm = readonly ? VHOST_ACCESS_RO : VHOST_ACCESS_RW;
    msg.iotlb.type = VHOST_IOTLB_UPDATE;

    if (write(fd, &msg, sizeof(msg)) != sizeof(msg)) {
        error_report("failed to write, fd=%d, errno=%d (%s)",
            fd, errno, strerror(errno));
        exit(1);
    }

    return ret;
}

static int vhost_vdpa_dma_unmap(struct vhost_vdpa *v, hwaddr iova,
                                hwaddr size)
{
    VhostVDPA *vdpa = v->vdpa;
    struct vhost_msg_v2 msg;
    int fd = vdpa->device_fd;
    int ret = 0;

    msg.type = VHOST_IOTLB_MSG_V2;
    msg.iotlb.iova = iova;
    msg.iotlb.size = size;
    msg.iotlb.type = VHOST_IOTLB_INVALIDATE;

    if (write(fd, &msg, sizeof(msg)) != sizeof(msg)) {
        error_report("failed to write, fd=%d, errno=%d (%s)",
            fd, errno, strerror(errno));
        exit(1);
    }

    return ret;
}

static void vhost_vdpa_listener_region_add(MemoryListener *listener,
                                           MemoryRegionSection *section)
{
    struct vhost_vdpa *v = container_of(listener, struct vhost_vdpa, listener);
    hwaddr iova;
    Int128 llend, llsize;
    void *vaddr;
    int ret;

    if (vhost_vdpa_listener_skipped_section(section)) {
        return;
    }

    if (unlikely((section->offset_within_address_space & ~TARGET_PAGE_MASK) !=
                 (section->offset_within_region & ~TARGET_PAGE_MASK))) {
        error_report("%s received unaligned region", __func__);
        return;
    }

    iova = TARGET_PAGE_ALIGN(section->offset_within_address_space);
    llend = int128_make64(section->offset_within_address_space);
    llend = int128_add(llend, section->size);
    llend = int128_and(llend, int128_exts64(TARGET_PAGE_MASK));

    if (int128_ge(int128_make64(iova), llend)) {
        return;
    }

    memory_region_ref(section->mr);

    /* Here we assume that memory_region_is_ram(section->mr)==true */

    vaddr = memory_region_get_ram_ptr(section->mr) +
            section->offset_within_region +
            (iova - section->offset_within_address_space);

    llsize = int128_sub(llend, int128_make64(iova));

    ret = vhost_vdpa_dma_map(v, iova, int128_get64(llsize),
                             vaddr, section->readonly);
    if (ret) {
        error_report("vhost vdpa map fail!");
        if (memory_region_is_ram_device(section->mr)) {
            /* Allow unexpected mappings not to be fatal for RAM devices */
            error_report("map ram fail!");
            exit(1);
            return;
        }
        goto fail;
    }

    return;

fail:
    if (memory_region_is_ram_device(section->mr)) {
        error_report("failed to vdpa_dma_map. pci p2p may not work");
        return;

    }
    /*
     * On the initfn path, store the first error in the container so we
     * can gracefully fail.  Runtime, there's not much we can do other
     * than throw a hardware error.
     */
    error_report("vhost-vdpa: DMA mapping failed, unable to continue");
    exit(1);
}

static void vhost_vdpa_listener_region_del(MemoryListener *listener,
                                           MemoryRegionSection *section)
{
    struct vhost_vdpa *v = container_of(listener, struct vhost_vdpa, listener);
    hwaddr iova;
    Int128 llend, llsize;
    int ret;
    bool try_unmap = true;

    if (vhost_vdpa_listener_skipped_section(section)) {
        return;
    }

    if (unlikely((section->offset_within_address_space & ~TARGET_PAGE_MASK) !=
                 (section->offset_within_region & ~TARGET_PAGE_MASK))) {
        error_report("%s received unaligned region", __func__);
        return;
    }

    iova = TARGET_PAGE_ALIGN(section->offset_within_address_space);
    llend = int128_make64(section->offset_within_address_space);
    llend = int128_add(llend, section->size);
    llend = int128_and(llend, int128_exts64(TARGET_PAGE_MASK));

    if (int128_ge(int128_make64(iova), llend)) {
        return;
    }

    llsize = int128_sub(llend, int128_make64(iova));

    if (try_unmap) {
        ret = vhost_vdpa_dma_unmap(v, iova, int128_get64(llsize));
        if (ret) {
            error_report("vhost_vdpa dma unmap error!");
        }
    }

    memory_region_unref(section->mr);
}

static const MemoryListener vhost_vdpa_memory_listener = {
    .region_add = vhost_vdpa_listener_region_add,
    .region_del = vhost_vdpa_listener_region_del,
};

struct notify_arg {
    struct vhost_dev *dev;
    int qid;
};

static int vhost_kernel_call(struct vhost_dev *dev, unsigned long int request,
                             void *arg)
{
    struct vhost_vdpa *v = dev->opaque;
    VhostVDPA *vdpa = v->vdpa;
    int fd = vdpa->device_fd;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_VDPA);

    return ioctl(fd, request, arg);
}



static int vhost_vdpa_init(struct vhost_dev *dev, void *opaque)
{
    struct vhost_vdpa *v;
    uint64_t  features;
    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_VDPA);

    v = g_new0(struct vhost_vdpa, 1);
    v->vdpa = opaque;

    dev->opaque = v;

    v->listener = vhost_vdpa_memory_listener;
    memory_listener_register(&v->listener, &address_space_memory);
    vhost_kernel_call(dev, VHOST_GET_BACKEND_FEATURES, &features);
    v->backend_features = features;
    dev->status = (VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER);
    return 0;
}

static int vhost_vdpa_cleanup(struct vhost_dev *dev)
{
    struct vhost_vdpa *v = dev->opaque;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_VDPA);

    g_free(v);
    dev->opaque = NULL;

    return 0;
}

static int vhost_vdpa_memslots_limit(struct vhost_dev *dev)
{
    int limit = 64;

    return limit;
}

static int vhost_vdpa_set_log_base(struct vhost_dev *dev, uint64_t base,
                                   struct vhost_log *log)
{
    return 0;
}

static int vhost_vdpa_set_mem_table(struct vhost_dev *dev,
                                    struct vhost_memory *mem)
{

    if (mem->padding) {
        return -1;
    }

    return 0;
}

static int vhost_vdpa_set_vring_addr(struct vhost_dev *dev,
                                     struct vhost_vring_addr *addr)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_ADDR, addr);
}

static int vhost_vdpa_set_vring_num(struct vhost_dev *dev,
                                    struct vhost_vring_state *ring)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_NUM, ring);
}

static int vhost_vdpa_set_vring_base(struct vhost_dev *dev,
                                     struct vhost_vring_state *ring)
{
    return vhost_kernel_call(dev, VHOST_GET_VRING_BASE, ring);
}

static int vhost_vdpa_get_vring_base(struct vhost_dev *dev,
                                     struct vhost_vring_state *ring)
{

    return vhost_kernel_call(dev, VHOST_GET_VRING_BASE, ring);
}

static int vhost_vdpa_set_vring_kick(struct vhost_dev *dev,
                                     struct vhost_vring_file *file)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_KICK, file);
}

static int vhost_vdpa_set_vring_call(struct vhost_dev *dev,
                                     struct vhost_vring_file *file)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_CALL, file);
}

static int vhost_vdpa_set_features(struct vhost_dev *dev,
                                   uint64_t features)
{
    int ret;
    uint8_t status;
    uint32_t device_id;
    if (vhost_kernel_call(dev, VHOST_VDPA_GET_DEVICE_ID, &device_id)) {
        error_report("%s get device id failed, errno=%d", __func__, errno);
    }

    status = 0;
    if (vhost_kernel_call(dev, VHOST_VDPA_SET_STATUS, &status)) {
        error_report("%s reset failed, errno=%d", __func__, errno);
    }
    features |= (1ULL << VIRTIO_F_IOMMU_PLATFORM);
    ret = vhost_kernel_call(dev, VHOST_SET_FEATURES, &features);
    if (ret) {
        error_report("%s called, failed, errno=%d", __func__, errno);
        return ret;
    }
    dev->status |= VIRTIO_CONFIG_S_FEATURES_OK;
    return vhost_kernel_call(dev, VHOST_VDPA_SET_STATUS, &dev->status);
}

static int vhost_vdpa_get_features(struct vhost_dev *dev,
                                   uint64_t *features)
{
    return vhost_kernel_call(dev, VHOST_GET_FEATURES, features);
}

static int vhost_vdpa_set_owner(struct vhost_dev *dev)
{
    return vhost_kernel_call(dev, VHOST_SET_OWNER, NULL);
}

static int vhost_vdpa_reset_device(struct vhost_dev *dev)
{
    return vhost_kernel_call(dev, VHOST_RESET_OWNER, NULL);
}

static int vhost_vdpa_get_vq_index(struct vhost_dev *dev, int idx)
{
    assert(idx >= dev->vq_index && idx < dev->vq_index + dev->nvqs);

    return idx - dev->vq_index;
}

static int vhost_vdpa_set_vring_enable(struct vhost_dev *dev, int enable)
{
    int i;

    for (i = 0; i < dev->nvqs; ++i) {
        struct vhost_vring_state state = {
            .index = dev->vq_index + i,
            .num   = enable,
        };

        state.num = 1;

        vhost_kernel_call(dev, VHOST_VDPA_SET_VRING_ENABLE, &state);
    }

    return 0;
}

static int vhost_vdpa_set_state(struct vhost_dev *dev, int state)
{
    int ret;

    if (state == VHOST_DEVICE_S_RUNNING) {
        dev->status |= VIRTIO_CONFIG_S_DRIVER_OK;
    } else if (state == VHOST_DEVICE_S_STOPPED) {
        dev->status = VHOST_DEVICE_S_STOPPED;
    } else {
        dev->status |= state;
    }

    ret = vhost_kernel_call(dev, VHOST_VDPA_SET_STATUS, &dev->status);
    if (ret) {
        perror("SET_STATUS");
    }
    return ret;
}


const VhostOps vdpa_ops = {
        .backend_type = VHOST_BACKEND_TYPE_VDPA,
        .vhost_backend_init = vhost_vdpa_init,
        .vhost_backend_cleanup = vhost_vdpa_cleanup,
        .vhost_backend_memslots_limit = vhost_vdpa_memslots_limit,
        .vhost_set_log_base = vhost_vdpa_set_log_base,
        .vhost_set_mem_table = vhost_vdpa_set_mem_table,
        .vhost_set_vring_addr = vhost_vdpa_set_vring_addr,
        .vhost_set_vring_endian = NULL,
        .vhost_set_vring_num = vhost_vdpa_set_vring_num,
        .vhost_set_vring_base = vhost_vdpa_set_vring_base,
        .vhost_get_vring_base = vhost_vdpa_get_vring_base,
        .vhost_set_vring_kick = vhost_vdpa_set_vring_kick,
        .vhost_set_vring_call = vhost_vdpa_set_vring_call,
        .vhost_set_features = vhost_vdpa_set_features,
        .vhost_get_features = vhost_vdpa_get_features,
        .vhost_set_owner = vhost_vdpa_set_owner,
        .vhost_reset_device = vhost_vdpa_reset_device,
        .vhost_get_vq_index = vhost_vdpa_get_vq_index,
        .vhost_set_vring_enable = vhost_vdpa_set_vring_enable,
        .vhost_requires_shm_log = NULL,
        .vhost_migration_done = NULL,
        .vhost_backend_can_merge = NULL,
        .vhost_net_set_mtu = NULL,
        .vhost_set_iotlb_callback = NULL,
        .vhost_send_device_iotlb_msg = NULL,
        .vhost_set_state = vhost_vdpa_set_state,
};

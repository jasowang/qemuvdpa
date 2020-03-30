/*
 * vhost-vdpa.c
 *
 * Copyright(c) 2017-2018 Intel Corporation. All rights reserved.
 * Copyright (C) 2020 Red Hat, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "clients.h"
#include "net/vhost_net.h"
#include "net/vhost-vdpa.h"
#include "hw/virtio/vhost-vdpa.h"
#include "chardev/char-fe.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qemu/option.h"
#include "qapi/error.h"
#include "trace.h"
#include <linux/vfio.h>
#include <sys/ioctl.h>
#include <err.h>

typedef struct VhostVDPAState {
    NetClientState nc;
    VhostVDPA vhost_vdpa;
    VHostNetState *vhost_net;
    uint64_t acked_features;
    bool started;
} VhostVDPAState;

VHostNetState *vhost_vdpa_get_vhost_net(NetClientState *nc)
{
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);
    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);
    return s->vhost_net;
}

uint64_t vhost_vdpa_get_acked_features(NetClientState *nc)
{
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);
    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);
    return s->acked_features;
}

static void vhost_vdpa_stop(int queues, NetClientState *ncs)
{
    VhostVDPAState *s;

    assert(ncs->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);

    s = DO_UPCAST(VhostVDPAState, nc, ncs);

        if (s->vhost_net) {
            /* save acked features */
            uint64_t features = vhost_net_get_acked_features(s->vhost_net);
            if (features) {
                s->acked_features = features;
            }
            vhost_net_cleanup(s->vhost_net);
    }
}

static int vhost_vdpa_start(NetClientState *ncs, void *be)
{
    VhostNetOptions options;
    struct vhost_net *net = NULL;
    VhostVDPAState *s;
    int i=0;

    options.backend_type = VHOST_BACKEND_TYPE_VDPA;

    assert(ncs->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);

    s = DO_UPCAST(VhostVDPAState, nc, ncs);

    options.net_backend = ncs;
        options.opaque      = be;
        options.busyloop_timeout = 0;
        net = vhost_net_init(&options);
        if (!net) {
            error_report("failed to init vhost_net for queue");
            goto err;
        }


        if (s->vhost_net) {
            vhost_net_cleanup(s->vhost_net);
            g_free(s->vhost_net);
        }
        s->vhost_net = net;

    return 0;

err:
    if (net) {
        vhost_net_cleanup(net);
    }
    vhost_vdpa_stop(i, ncs);
    return -1;
}

    /* In case of RARP (message size is 60) notify backup to send a fake RARP.
       This fake RARP will be sent by backend only for guest
       without GUEST_ANNOUNCE capability.
     */

        /* extract guest mac address from the RARP message */




static void vhost_vdpa_cleanup(NetClientState *nc)
{
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);

    if (s->vhost_net) {
        vhost_net_cleanup(s->vhost_net);
        g_free(s->vhost_net);
        s->vhost_net = NULL;
    }

    qemu_purge_queued_packets(nc);
}

static bool vhost_vdpa_has_vnet_hdr(NetClientState *nc)
{
    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);

    return true;
}

static bool vhost_vdpa_has_ufo(NetClientState *nc)
{
    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);

    return true;
}

static NetClientInfo net_vhost_vdpa_info = {
        .type = NET_CLIENT_DRIVER_VHOST_VDPA,
        .size = sizeof(VhostVDPAState),
        .cleanup = vhost_vdpa_cleanup,
        .has_vnet_hdr = vhost_vdpa_has_vnet_hdr,
        .has_ufo = vhost_vdpa_has_ufo,
};

static int net_vhost_vdpa_init(NetClientState *peer, const char *device,
                               const char *name, const char *vhostdev)
{
    NetClientState *nc, *nc0 = NULL;
    NetClientState *ncs;
    VhostVDPAState *s;
    int vdpa_device_fd;
    
    assert(name);

        nc = qemu_new_net_client(&net_vhost_vdpa_info, peer, device, name);
    snprintf(nc->info_str, sizeof(nc->info_str), "vhost-vdpa");
    nc->queue_index = 0;
        if (!nc0) {
            nc0 = nc;
            s = DO_UPCAST(VhostVDPAState, nc, nc);
        }

    ncs= nc;

    s = DO_UPCAST(VhostVDPAState, nc, nc0);

    vdpa_device_fd = open(vhostdev, O_RDWR);
    if (vdpa_device_fd == -1)
        err(EXIT_FAILURE, "%s (%d)", vhostdev, errno);

    s->vhost_vdpa.device_fd = vdpa_device_fd;
    vhost_vdpa_start(ncs, (void *)&s->vhost_vdpa);

    assert(s->vhost_net);

    return 0;
}

static int net_vhost_check_net(void *opaque, QemuOpts *opts, Error **errp)
{
    const char *name = opaque;
    const char *driver, *netdev;

    driver = qemu_opt_get(opts, "driver");
    netdev = qemu_opt_get(opts, "netdev");

    if (!driver || !netdev) {
        return 0;
    }

    if (strcmp(netdev, name) == 0 &&
        !g_str_has_prefix(driver, "virtio-net-")) {
        error_setg(errp, "vhost-vdpa requires frontend driver virtio-net-*");
        return -1;
    }

    return 0;
}

int net_init_vhost_vdpa(const Netdev *netdev, const char *name,
                        NetClientState *peer, Error **errp)
{
    const NetdevVhostVDPAOptions *vhost_vdpa_opts;

    assert(netdev->type == NET_CLIENT_DRIVER_VHOST_VDPA);
    vhost_vdpa_opts = &netdev->u.vhost_vdpa;

    /* verify net frontend */
    if (qemu_opts_foreach(qemu_find_opts("device"), net_vhost_check_net,
                          (char *)name, errp)) {
        return -1;
    }


    return net_vhost_vdpa_init(peer, "vhost_vdpa", name,
                               vhost_vdpa_opts->vhostdev);

    return 0;
}

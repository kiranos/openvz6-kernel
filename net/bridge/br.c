/*
 *	Generic parts
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/llc.h>
#include <linux/cpt_image.h>
#include <net/llc.h>
#include <net/stp.h>

#include "br_private.h"

int (*br_should_route_hook)(struct sk_buff *skb);

static struct netdev_rst br_netdev_rst = {
	.cpt_object = CPT_OBJ_NET_BR,
	.ndo_rst = br_rst,
};

static const struct stp_proto br_stp_proto = {
	.rcv	= br_stp_rcv,
};

static struct pernet_operations br_net_ops = {
	.exit	= br_net_exit,
};


static struct net_device *__br_get_br_dev_for_port_rcu(struct net_device *port_dev)
{
	struct net_bridge_port *port = rcu_dereference(port_dev->br_port);
	return port ? port->br->dev : NULL;
}

static int __init br_init(void)
{
	int err;

	err = stp_proto_register(&br_stp_proto);
	if (err < 0) {
		printk(KERN_ERR "bridge: can't register sap for STP\n");
		return err;
	}

	err = br_fdb_init();
	if (err)
		goto err_out;

	err = register_pernet_device(&br_net_ops);
	if (err)
		goto err_out1;

	err = br_netfilter_init();
	if (err)
		goto err_out2;

	err = register_netdevice_notifier(&br_device_notifier);
	if (err)
		goto err_out3;

	err = br_netlink_init();
	if (err)
		goto err_out4;

	brioctl_set(br_ioctl_deviceless_stub);
	br_get_br_dev_for_port_hook = __br_get_br_dev_for_port_rcu;

#if defined(CONFIG_ATM_LANE) || defined(CONFIG_ATM_LANE_MODULE)
	br_fdb_test_addr_hook = br_fdb_test_addr;
#endif

	register_netdev_rst(&br_netdev_rst);
	return 0;
err_out4:
	unregister_netdevice_notifier(&br_device_notifier);
err_out3:
	br_netfilter_fini();
err_out2:
	unregister_pernet_device(&br_net_ops);
err_out1:
	br_fdb_fini();
err_out:
	stp_proto_unregister(&br_stp_proto);
	return err;
}

static void __exit br_deinit(void)
{
	unregister_netdev_rst(&br_netdev_rst);
	stp_proto_unregister(&br_stp_proto);

	br_netlink_fini();
	unregister_netdevice_notifier(&br_device_notifier);
	brioctl_set(NULL);

	unregister_pernet_device(&br_net_ops);

	rcu_barrier(); /* Wait for completion of call_rcu()'s */

	br_netfilter_fini();
#if defined(CONFIG_ATM_LANE) || defined(CONFIG_ATM_LANE_MODULE)
	br_fdb_test_addr_hook = NULL;
#endif

	br_get_br_dev_for_port_hook = NULL;
	br_fdb_fini();
}

EXPORT_SYMBOL(br_should_route_hook);

module_init(br_init)
module_exit(br_deinit)
MODULE_LICENSE("GPL");
MODULE_VERSION(BR_VERSION);
MODULE_ALIAS_RTNL_LINK("bridge");

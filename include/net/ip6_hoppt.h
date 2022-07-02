/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Hop-by-Hop Path Tracing implementation
 *
 *  Author:
 *  Andrea Mayer <andrea.mayer@uniroma2.it>
 */

#ifndef _NET_IPV6_HOPPT_H
#define _NET_IPV6_HOPPT_H

#include <linux/ipv6.h>

extern int ipv6_hoppt_init(void);
extern void ipv6_hoppt_exit(void);

extern int ipv6_hoppt_label_lookup_rcu(struct net *net, int ifindex);

#endif /* _NET_IPV6_HOPPT_H */

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
extern int ipv6_hoppt_iifindex(struct net *net, struct sk_buff *skb);
extern int seg6_find_tlv(const struct ipv6_sr_hdr *srh, int type);
extern struct sr6_tlv_ptss *get_srh_tlv_ptss(const struct ipv6_sr_hdr *srh);
extern void ipv6_hoppt_get_timespec64(struct timespec64 *ts);
extern void ipv6_hoppt_tlv_ptss_update(struct sr6_tlv_ptss *tlv, int label,
				       int ifload, struct timespec64 *ts);

#endif /* _NET_IPV6_HOPPT_H */

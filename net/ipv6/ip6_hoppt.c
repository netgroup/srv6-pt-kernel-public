// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Hop-by-Hop Path Tracing implementation
 *
 *  Author:
 *  Andrea Mayer <andrea.mayer@uniroma2.it>
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>

#include <net/seg6.h>

#if defined(CONFIG_NETFILTER)
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#endif

#include <net/genetlink.h>
#include <net/netns/generic.h>

#include <net/ip6_hoppt.h>
#include <linux/ip6_hoppt_genl.h>

#define HT_MAP_BITS			5
#define HASH_INITVAL			((u32)0x0badbabe)

#define IPV6_HOPPT_LABEL_BIT_SIZE	12 /* PT Labels are 12 bits wide */

struct sr6_ptmpt_mcd {
	__be16	rinfo;
	__u8	tts;
} __packed;

#define SRV6_TLV_HOPPT		50
#define SR6_TLV_PTMPT_MCD_MAX	12

/* Hop-by-Hop TLV for Packet Tracing */
struct sr6_tlv_ptmpt {
	struct sr6_tlv tlvhdr;
#define sr6_tlv_ptmpt_type	tlvhdr.type
#define sr6_tlv_ptmpt_len	tlvhdr.len

	__u8 tlv_data[0];	/* tlv len is evaluated starting from here */

	struct sr6_ptmpt_mcd mcds[SR6_TLV_PTMPT_MCD_MAX];
} __packed;

#define SR6_TLV_PTMPT_DATA_SIZE			\
	(sizeof(struct sr6_tlv_ptmpt) -		\
	 offsetof(struct sr6_tlv_ptmpt, tlv_data))

static struct genl_family ipv6_hoppt_genl_family;
static unsigned int ipv6_hoppt_net_id;

/* structure used for binding the ifindex of a device with a given label */
struct ipv6_hoppt_map_elem {
	struct hlist_node hnode;
	struct rcu_head rcu;

	int ifindex;	/* hashtable key */
	int ttstmpl;	/* tts template */
	u32 label;
};

static const int ipv6_hoppt_ttstmpl_shift[IPV6_HOPPT_TTS_TMPL_MAX + 1] = {
	/* a zero-bit shift is considered bogus */
	[IPV6_HOPPT_TTS_TMPL_1] = 18,
	[IPV6_HOPPT_TTS_TMPL_2] = 20,
	[IPV6_HOPPT_TTS_TMPL_3] = 24,
	[IPV6_HOPPT_TTS_TMPL_4] = 25,
};

struct ipv6_hoppt_map {
	/* protected by rtnl lock */
	DECLARE_HASHTABLE(ht, HT_MAP_BITS);

	/* keep track of the number of associations among devs and labels */
	u32 elements;
};

/* contiain the interface used to receive the incoming packet */
struct ipv6_hoppt_tgrcv {
	int ifindex;
};

struct ipv6_hoppt_netns {
	struct ipv6_hoppt_tgrcv tgrcv;
	struct ipv6_hoppt_map hmap;
};

static struct ipv6_hoppt_netns *ipv6_hoppt_pernet(struct net *net)
{
	return net_generic(net, ipv6_hoppt_net_id);
}

static struct ipv6_hoppt_map *ipv6_hoppt_pernet_map(struct net *net)
{
	struct ipv6_hoppt_netns *pt_netns = ipv6_hoppt_pernet(net);

	return &pt_netns->hmap;
}

static struct ipv6_hoppt_tgrcv *ipv6_hoppt_pernet_tgrcv(struct net *net)
{
	struct ipv6_hoppt_netns *pt_netns = ipv6_hoppt_pernet(net);

	return &pt_netns->tgrcv;
}

static void ipv6_hoppt_tgrcv_init(struct ipv6_hoppt_tgrcv *tgrcv)
{
	/* by default we do not have any generator incoming interface */
	tgrcv->ifindex = -1;
}

static void ipv6_hoppt_map_init(struct ipv6_hoppt_map *hmap)
{
	hash_init(hmap->ht);
	hmap->elements = 0;
}

static u32 ipv6_hoppt_map_elem_key(int ifindex)
{
	return jhash_1word((u32)ifindex, HASH_INITVAL);
}

static void ipv6_hoppt_map_add(struct ipv6_hoppt_map *hmap,
			       struct ipv6_hoppt_map_elem *me)
{
	int ifindex = me->ifindex;
	u32 key;

	key = ipv6_hoppt_map_elem_key(ifindex);
	hash_add_rcu(hmap->ht, &me->hnode, key);
}

static void ipv6_hoppt_map_del(struct ipv6_hoppt_map_elem *me)
{
	hash_del_rcu(&me->hnode);
}

static struct
ipv6_hoppt_map_elem *__ipv6_hoppt_map_lookup_check(struct ipv6_hoppt_map *hmap,
						   int ifindex, bool expr)
{
	struct ipv6_hoppt_map_elem *me;
	u32 key;

	key = ipv6_hoppt_map_elem_key(ifindex);
	hash_for_each_possible_rcu(hmap->ht, me, hnode, key, expr) {
		if (me->ifindex == ifindex)
			return me;
	}

	return NULL;
}

/* called with rcu lock held */
static struct
ipv6_hoppt_map_elem *ipv6_hoppt_map_lookup_rcu(struct ipv6_hoppt_map *hmap,
					       int ifindex)
{
	/* note that expr = false permits to evaluate rcu read lock checks */
	return __ipv6_hoppt_map_lookup_check(hmap, ifindex, false);
}

/* called with rtnl lock held */
static struct
ipv6_hoppt_map_elem *ipv6_hoppt_map_lookup_rtnl(struct ipv6_hoppt_map *hmap,
						int ifindex)
{
	return __ipv6_hoppt_map_lookup_check(hmap, ifindex,
					     lockdep_rtnl_is_held());
}

int ipv6_hoppt_label_lookup_rcu(struct net *net, int ifindex)
{
	struct ipv6_hoppt_map *hmap = ipv6_hoppt_pernet_map(net);
	struct ipv6_hoppt_map_elem *me;

	me = ipv6_hoppt_map_lookup_rcu(hmap, ifindex);
	if (!me)
		return -ENODEV;

	return me->label;
}

static struct ipv6_hoppt_map_elem *ipv6_hoppt_map_elem_alloc(gfp_t flags)
{
	struct ipv6_hoppt_map_elem *me;

	me = kzalloc(sizeof(*me), flags);
	if (!me)
		return NULL;

	return me;
}

static void ipv6_hoppt_map_elem_init(struct ipv6_hoppt_map_elem *me,
				     int ifindex, u32 label, int ttstmpl)
{
	me->ttstmpl = ttstmpl;
	me->ifindex = ifindex;
	me->label = label;
}

static void ipv6_hoppt_map_elem_free_rcu(struct ipv6_hoppt_map_elem *me)
{
	kfree_rcu(me, rcu);
}

int ipv6_hoppt_iifindex(struct net *net, struct sk_buff *skb)
{
	bool l3_slave = ipv6_l3mdev_skb(IP6CB(skb)->flags);
	struct net_device *orig_dev;
	int iif;

	/* take care of VRFs */
	iif = l3_slave ? IP6CB(skb)->iif : skb->skb_iif;

	/* check if net device "iif" exists or not */
	orig_dev = dev_get_by_index_rcu(net, iif);
	if (unlikely(!orig_dev))
		return -ENODEV;

	return iif;
}

static int __ipv6_hoppt_tgrcv_get_iface(struct net *net)
{
	struct ipv6_hoppt_tgrcv *tgrcv = ipv6_hoppt_pernet_tgrcv(net);

	return READ_ONCE(tgrcv->ifindex);
}

/* check whether the packet is received on a generator interface or not */
static bool ipv6_hoppt_tgrcv_iface(struct net *net, struct sk_buff *skb)
{
	int tgrcv_iif = __ipv6_hoppt_tgrcv_get_iface(net);
	int iif = ipv6_hoppt_iifindex(net, skb);

	if (tgrcv_iif < 0)
		/* the generator interface is not set */
		return false;

	return iif == tgrcv_iif;
}

int seg6_find_tlv(const struct ipv6_sr_hdr *srh, int type)
{
	int srhlen = ipv6_optlen(srh);
	struct sr6_tlv *tlv;
	int tlv_offset;
	int tlv_type;
	int tlv_len;
	int len;

	tlv_offset = sizeof(*srh) + ((srh->first_segment + 1) << 4);
	len = srhlen - tlv_offset;

	while (len > 0) {
		if (unlikely(len < sizeof(*tlv)))
			goto bad;

		tlv = (struct sr6_tlv *)((unsigned char *)srh + tlv_offset);
		tlv_type = tlv->type;

		if (tlv_type == type)
			return tlv_offset;

		switch (tlv_type) {
		case IPV6_TLV_PAD1:
			tlv_len = 1;
			break;
		default:
			tlv_len = sizeof(*tlv) + tlv->len;
			if (tlv_len > len)
				goto bad;
			break;
		}

		tlv_offset += tlv_len;
		len -= tlv_len;
	}
	/* not_found */
 bad:
	return -1;
}

struct sr6_tlv_ptss *get_srh_tlv_ptss(const struct ipv6_sr_hdr *srh)
{
	struct sr6_tlv_ptss *tlv;
	int tlv_offset;

	tlv_offset = seg6_find_tlv(srh, SR6_TLV_PTSS);
	if (unlikely(tlv_offset < 0))
		return NULL;

	tlv = (struct sr6_tlv_ptss *)((unsigned char *)srh + tlv_offset);
	if (tlv->sr6_tlv_ptss_type != SR6_TLV_PTSS ||
	    tlv->sr6_tlv_ptss_len != (sizeof(*tlv) -
				      offsetof(struct sr6_tlv_ptss, tlv_data)))
		return NULL;

	return tlv;
}

static __be16 ipv6_hoppt_htons_ifinfo(int iflabel, int ifload)
{
	return htons(((iflabel & 0x0fff) << 4) | (0x000f & ifload));
}

static void
ipv6_hoppt_tlv_ptss_store_info(struct sr6_tlv_ptss *tlv, int iflabel,
			       int ifload)
{
	tlv->rinfo = ipv6_hoppt_htons_ifinfo(iflabel, ifload);
}

static void
ipv6_hoppt_tlv_ptss_store_timestamp(struct sr6_tlv_ptss *tlv,
				    struct timespec64 *from)
{
	struct timespec_be32 {
		__be32	tv_sec;
		__be32	tv_nsec;
	} *ts32;

	ts32 = (struct timespec_be32 *)&tlv->timestamp;

	ts32->tv_nsec = cpu_to_be32((__u32)from->tv_nsec);
	ts32->tv_sec = cpu_to_be32((__u32)from->tv_sec);
}

void ipv6_hoppt_get_timespec64(struct timespec64 *ts)
{
	*ts = ktime_to_timespec64(ktime_get_real());
}

void ipv6_hoppt_tlv_ptss_update(struct sr6_tlv_ptss *tlv, int label, int ifload,
				struct timespec64 *ts)
{
	ipv6_hoppt_tlv_ptss_store_info(tlv, label, ifload);
	ipv6_hoppt_tlv_ptss_store_timestamp(tlv, ts);
}

#if defined(CONFIG_NETFILTER)
static u8 ipv6_hoppt_mpt_eval_tts(struct ipv6_hoppt_map_elem *me)
{
	int ttstmpl_shift = ipv6_hoppt_ttstmpl_shift[me->ttstmpl];
	struct timespec64 ts;
	u8 tts;

	ts = ktime_to_timespec64(ktime_get_real());
	tts = (u8)(ts.tv_nsec >> ttstmpl_shift);

	return tts;
}

static void ipv6_hoppt_tlv_ptmpt_record_mcd(struct sr6_ptmpt_mcd *mcd, u8 tts,
					    int iflabel, int ifload)
{
	struct sr6_ptmpt_mcd *top = &mcd[0];

	/* make room at the top of the stack */
	memmove((void *)&mcd[1], (const void *)top,
		sizeof(struct sr6_ptmpt_mcd) * (SR6_TLV_PTMPT_MCD_MAX - 1));

	top->tts = tts;
	top->rinfo = ipv6_hoppt_htons_ifinfo(iflabel, ifload);
}

static struct sr6_ptmpt_mcd *
ipv6_hoppt_tlv_ptmpt_mcds(struct sr6_tlv_ptmpt *tlv)
{
	return &tlv->mcds[0];
}

static bool ipv6_hoppt_mpt(struct net *net, struct sk_buff *skb, int optoff)
{
	unsigned char *nh = skb_network_header(skb);
	struct net_device *odev = skb->dev;
	struct ipv6_hoppt_map_elem *me;
	struct ipv6_hoppt_map *hmap;
	struct sr6_ptmpt_mcd *mcds;
	struct sr6_tlv_ptmpt *tlv;
	int oif = odev->ifindex;
	const int ifload = 0;		/* not implemented yet */
	int label;
	u8 tts;

	tlv = (struct sr6_tlv_ptmpt *)&nh[optoff];
	if (unlikely(tlv->sr6_tlv_ptmpt_len != SR6_TLV_PTMPT_DATA_SIZE))
		goto drop;

	hmap = ipv6_hoppt_pernet_map(net);
	me = ipv6_hoppt_map_lookup_rcu(hmap, oif);
	if (unlikely(!me))
		goto out;

	/* from now on, we can only go to commit */
	label = me->label;
	tts = ipv6_hoppt_mpt_eval_tts(me);
	mcds = ipv6_hoppt_tlv_ptmpt_mcds(tlv);

	ipv6_hoppt_tlv_ptmpt_record_mcd(mcds, tts, label, ifload);

	if (net_ratelimit())
		pr_debug("IPv6 Hop-by-Hop PT: Midpoint trace [oif=%d/ID=%d]\n",
			 oif, label);
out:
	return true;

drop:
	kfree_skb(skb);
	return false;
}

static bool ipv6_hoppt_srcpt(struct net *net, struct sk_buff *skb)
{
	struct net_device *odev = skb->dev;
	struct sr6_tlv_ptss *tlv;
	struct ipv6_sr_hdr *srh;
	int oif = odev->ifindex;
	struct timespec64 ts;
	const int ifload = 0;		/* not implemented yet */
	int iflabel;

	iflabel = ipv6_hoppt_label_lookup_rcu(net, oif);
	if (iflabel < 0)
		/* no Path-Tracing (PT) ID (label) set for the outgoing dev.
		 * We return immediately without any further PT processing.
		 */
		return true;

	srh = seg6_get_srh(skb, 0);
	if (unlikely(!srh))
		goto drop;

	tlv = get_srh_tlv_ptss(srh);
	if (unlikely(!tlv))
		goto drop;

	ipv6_hoppt_get_timespec64(&ts);

	ipv6_hoppt_tlv_ptss_update(tlv, iflabel, ifload, &ts);

	if (net_ratelimit())
		pr_debug("IPv6 Hop-by-Hop PT: Source trace [oif=%d/ID=%d]\n",
			 oif, iflabel);
	return true;

drop:
	kfree_skb(skb);
	return false;
}

static bool ipv6_hoppt_core(struct sk_buff *skb, int optoff)
{
	struct net_device *odev = skb->dev;
	struct net *net = dev_net(odev);
	bool src_node;

	src_node = ipv6_hoppt_tgrcv_iface(net, skb);
	if (src_node)
		return ipv6_hoppt_srcpt(net, skb);

	return ipv6_hoppt_mpt(net, skb, optoff);
}

struct tlvtype_proc {
	int	type;
	bool	(*func)(struct sk_buff *skb, int offset);
};

static const struct tlvtype_proc tlvprochopopt_lst[] = {
	{
		.type	= SRV6_TLV_HOPPT,
		.func	= ipv6_hoppt_core,
	},
	{ -1, NULL },
};

/* based on ip6_parse_tlv() in exthdrs.c
 * by default we skip any TLV which is unknown.
 */
static bool ipv6_hoppt_parse_tlv(const struct tlvtype_proc *procs,
				 struct sk_buff *skb)
{
	int len = (skb_transport_header(skb)[1] + 1) << 3;
	const unsigned char *nh = skb_network_header(skb);
	int off = skb_network_header_len(skb);
	const struct tlvtype_proc *curr;
	int padlen = 0;

	if (skb_transport_offset(skb) + len > skb_headlen(skb))
		goto bad;

	off += 2;
	len -= 2;

	while (len > 0) {
		int optlen = nh[off + 1] + 2;
		int i;

		switch (nh[off]) {
		case IPV6_TLV_PAD1:
			optlen = 1;
			padlen++;
			if (padlen > 7)
				goto bad;
			break;

		case IPV6_TLV_PADN:
			/* RFC 2460 states that the purpose of PadN is
			 * to align the containing header to multiples
			 * of 8. 7 is therefore the highest valid value.
			 * See also RFC 4942, Section 2.1.9.5.
			 */
			padlen += optlen;
			if (padlen > 7)
				goto bad;
			/* RFC 4942 recommends receiving hosts to
			 * actively check PadN payload to contain
			 * only zeroes.
			 */
			for (i = 2; i < optlen; i++) {
				if (nh[off + i] != 0)
					goto bad;
			}
			break;

		default: /* Other TLV code so scan list */
			if (optlen > len)
				goto bad;

			for (curr = procs; curr->type >= 0; curr++) {
				if (curr->type == nh[off]) {
					/* type specific length/alignment
					 * checks will be performed in the
					 * func().
					 */
					if (curr->func(skb, off) == false)
						return false;
					break;
				}
			}

			/* by default, we ignore all TLVs for which we do not
			 * have any explicit handler.
			 */
			padlen = 0;
			break;
		}
		/* A "func" callback can invalidate skb pointers. For this
		 * reason, we have to reload the network header pointer again.
		 */
		nh = skb_network_header(skb);
		off += optlen;
		len -= optlen;
	}

	if (len == 0)
		return true;
bad:
	kfree_skb(skb);
	return false;
}

/* skb data and network header must be aligned.
 * This function does not rely on the transport header pointer which may not be
 * set correctly to the hop-by-hop extension header.
 */
static struct ipv6_opt_hdr *__ipv6_hoppt_opt_hdr(struct sk_buff *skb)
{
	return (struct ipv6_opt_hdr *)skb_transport_header(skb);
}

static int ipv6_hoppt_parse_mpt(struct sk_buff *skb)
{
	struct inet6_skb_parm *opt = IP6CB(skb);
	__u8 nexthdr = ipv6_hdr(skb)->nexthdr;
	struct ipv6_opt_hdr *opt_hdr;
	int extlen;
	u16 thoff;

	if (nexthdr != NEXTHDR_HOP)
		return 0;

	/* skb_network_header(skb) is equal to skb->data, and
	 * skb_network_header_len(skb) MUST always be equal to sizeof(struct
	 * ipv6hdr) by definition of hop-by-hop options. So, we should expect
	 * to have the transport header correctly aligned to the hop-by-hop
	 * extension header.
	 * However, along the processing chain, there may be someone who does
	 * not set the transport header correctly. For this reason, we reset
	 * the transport header after the network header (IPv6).
	 * At the end of hop-by-hop processing, we restore the transport header
	 * to the original value.
	 */

	if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr) + 8)))
		return 0;

	if (unlikely(skb_unclone(skb, GFP_ATOMIC) < 0))
		goto drop;

	thoff = skb->transport_header;

	skb_set_transport_header(skb, sizeof(struct ipv6hdr));
	opt_hdr = __ipv6_hoppt_opt_hdr(skb);

	extlen = ipv6_optlen(opt_hdr);
	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + extlen))
		goto out;

	opt->flags |= IP6SKB_HOPBYHOP;
	if (unlikely(!ipv6_hoppt_parse_tlv(tlvprochopopt_lst, skb)))
		/* ipv6_hoppt_parse_tlv() automatically drops the packet in
		 * case of error; we do no need to free the packet manually.
		 *
		 * NB: we are not interested in update the transport header
		 * offset for the moment.
		 */
		return -EINVAL;
out:
	/* restore the transport header */
	skb_set_transport_header(skb, thoff);
	return 0;

drop:
	kfree_skb(skb);
	return -EINVAL;
}

/* skb data and network header must be aligned */
static unsigned int
ipv6_hoppt_mpt_process(void *priv, struct sk_buff *skb,
		       const struct nf_hook_state *state)
{
	int rc;

	rc = ipv6_hoppt_parse_mpt(skb);
	if (unlikely(rc < 0))
		return NF_STOLEN;

	return NF_ACCEPT;
}
#endif

static const
struct nla_policy ipv6_hoppt_genl_policy[IPV6_HOPPT_ATTR_MAX + 1] = {
	[IPV6_HOPPT_ATTR_ID]		= { .type = NLA_U32, },
	[IPV6_HOPPT_ATTR_IFINDEX]	= { .type = NLA_S32, },
	[IPV6_HOPPT_ATTR_TTSTMPL]	= { .type = NLA_S32, },
};

static int ipv6_hoppt_add_tgrcv_iface(struct net *net, int ifindex)
{
	struct ipv6_hoppt_tgrcv *tgrcv = ipv6_hoppt_pernet_tgrcv(net);
	struct net_device *dev;

	ASSERT_RTNL();

	dev = __dev_get_by_index(net, ifindex);
	if (!dev)
		return -ENODEV;

	if (cmpxchg(&tgrcv->ifindex, -1, ifindex) != -1)
		return -EEXIST;

	pr_debug("IPv6 Hop-by-Hop PT: add TG rcv port ifindex=%d\n",
		 ifindex);

	return 0;
}

static int ipv6_hoppt_del_tgrcv_iface(struct net *net, int ifindex)
{
	struct ipv6_hoppt_tgrcv *tgrcv = ipv6_hoppt_pernet_tgrcv(net);

	ASSERT_RTNL();

	if (cmpxchg(&tgrcv->ifindex, ifindex, -1) != ifindex)
		return -ENOENT;

	pr_debug("IPv6 Hop-by-Hop PT: del TG rcv port ifindex=%d\n",
		 ifindex);

	return 0;
}

static int ipv6_hoppt_genl_add_tgrcv_iface(struct sk_buff *unused,
					   struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct nlattr **attrs;
	int ifindex;
	int rc;

	attrs = info->attrs;
	if (!attrs)
		return -EINVAL;

	if (!attrs[IPV6_HOPPT_ATTR_IFINDEX])
		return -EINVAL;

	ifindex = nla_get_s32(attrs[IPV6_HOPPT_ATTR_IFINDEX]);
	if (ifindex < 0)
		return -EINVAL;

	rtnl_lock();
	rc = ipv6_hoppt_add_tgrcv_iface(net, ifindex);
	rtnl_unlock();

	return rc;
}

static int ipv6_hoppt_genl_del_tgrcv_iface(struct sk_buff *unused,
					   struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct nlattr **attrs;
	int ifindex;
	int rc;

	attrs = info->attrs;
	if (!attrs)
		return -EINVAL;

	if (!attrs[IPV6_HOPPT_ATTR_IFINDEX])
		return -EINVAL;

	ifindex = nla_get_s32(attrs[IPV6_HOPPT_ATTR_IFINDEX]);
	if (ifindex < 0)
		return -EINVAL;

	rtnl_lock();
	rc = ipv6_hoppt_del_tgrcv_iface(net, ifindex);
	rtnl_unlock();

	return rc;
}

static int
__ipv6_hoppt_genl_tgrcv_dump_iface(struct sk_buff *skb, u32 portid, u32 seq,
				   u32 flags, u8 mcd, int ifindex)
{
	void *hdr;

	hdr = genlmsg_put(skb, portid, seq, &ipv6_hoppt_genl_family, flags,
			  mcd);
	if (!hdr)
		return -ENOMEM;

	if (nla_put_s32(skb, IPV6_HOPPT_ATTR_IFINDEX, ifindex))
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int ipv6_hoppt_genl_show_tgrcv_iface(struct sk_buff *unused,
					    struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct sk_buff *msg;
	int ifindex;
	int rc;

	/* we can build the reply message (prealloc sk_buff) */
	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	rtnl_lock();

	ifindex = __ipv6_hoppt_tgrcv_get_iface(net);
	if (ifindex < 0) {
		rc = -ENOENT;
		goto error;
	}

	rc = __ipv6_hoppt_genl_tgrcv_dump_iface(msg, info->snd_portid,
						info->snd_seq, 0,
						IPV6_HOPPT_CMD_TGRCV_DUMP_ID,
						ifindex);
	if (rc)
		goto error;

	pr_debug("IPv6 Hop-by-Hop PT: show TG rcv port ifindex=%d\n", ifindex);

	rtnl_unlock();

	return genlmsg_reply(msg, info);

error:
	rtnl_unlock();

	nlmsg_free(msg);
	return rc;
}

static void __ipv6_hoppt_del_label(struct net *net,
				   struct ipv6_hoppt_map_elem *me)
{
	struct ipv6_hoppt_map *hmap = ipv6_hoppt_pernet_map(net);

	ipv6_hoppt_map_del(me);
	--hmap->elements;

	ipv6_hoppt_map_elem_free_rcu(me);
}

static int
ipv6_hoppt_add_label(struct net *net, int ifindex, u32 label, int ttstmpl)
{
	struct ipv6_hoppt_map *hmap = ipv6_hoppt_pernet_map(net);
	struct ipv6_hoppt_map_elem *me;
	struct net_device *dev;

	ASSERT_RTNL();

	dev = __dev_get_by_index(net, ifindex);
	if (!dev)
		return -ENODEV;

	me = ipv6_hoppt_map_lookup_rtnl(hmap, ifindex);
	if (me)
		return -EEXIST;

	me = ipv6_hoppt_map_elem_alloc(GFP_KERNEL);
	if (!me)
		return -ENOMEM;

	ipv6_hoppt_map_elem_init(me, ifindex, label, ttstmpl);

	ipv6_hoppt_map_add(hmap, me);
	++hmap->elements;

	pr_debug("IPv6 Hop-by-Hop PT: add ID=%u to ifindex=%d, tts tmpl=%d\n",
		 label, ifindex, ttstmpl);

	return 0;
}

#if 0
static int ipv6_hoppt_replace_label(struct net *net, int ifindex, u32 label)
{
	struct ipv6_hoppt_map *hmap = ipv6_hoppt_pernet_map(net);
	struct ipv6_hoppt_map_elem *me;
	struct net_device *dev;

	ASSERT_RTNL();

	dev = __dev_get_by_index(net, ifindex);
	if (!dev)
		return -ENODEV;

	me = ipv6_hoppt_map_lookup_rtnl(hmap, ifindex);
	if (!me)
		goto add_label;

	/* remove the element from the map and schedule the destruction of
	 * the object when no one will refer to the object anymore.
	 */
	__ipv6_hoppt_del_label(net, me);

add_label:
	me = ipv6_hoppt_map_elem_alloc(GFP_KERNEL);
	if (!me)
		return -ENOMEM;

	ipv6_hoppt_map_elem_init(me, ifindex, label);

	ipv6_hoppt_map_add(hmap, me);
	++hmap->elements;

	pr_debug("IPv6 Hop-by-Hop PT: add ID=%u to ifindex=%d\n", label,
		 ifindex);

	return 0;
}
#endif

static int ipv6_hoppt_del_label(struct net *net, int ifindex)
{
	struct ipv6_hoppt_map *hmap = ipv6_hoppt_pernet_map(net);
	struct ipv6_hoppt_map_elem *me;

	ASSERT_RTNL();

	me = ipv6_hoppt_map_lookup_rtnl(hmap, ifindex);
	if (!me)
		return -ENOENT;

	__ipv6_hoppt_del_label(net, me);

	pr_debug("IPv6 Hop-by-Hop PT: del (reset) ID from ifindex=%d\n",
		 ifindex);

	return 0;
}

static int ipv6_hoppt_validate_label(u32 label, struct netlink_ext_ack *extack)
{
	if (label < (1 << IPV6_HOPPT_LABEL_BIT_SIZE))
		return 0;

	if (extack)
		NL_SET_ERR_MSG(extack, "IPv6 Hop-by-Hop PT: invalid ID");

	return -EINVAL;
}

static int ipv6_hoppt_validate_ttstmpl(int ttstmpl,
				       struct netlink_ext_ack *extack)
{
	if (ttstmpl > 0 && ttstmpl <= IPV6_HOPPT_TTS_TMPL_MAX)
		return 0;

	if (extack)
		NL_SET_ERR_MSG(extack,
			       "IPv6 Hop-by-Hop PT: invalid tts template");

	return -EINVAL;
}

static int ipv6_hoppt_genl_add_label(struct sk_buff *unused,
				     struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct nlattr **attrs;
	int ttstmpl;
	int ifindex;
	u32 label;
	int rc;

	attrs = info->attrs;
	if (!attrs)
		return -EINVAL;

	/* mandatory attributes */
	if (!attrs[IPV6_HOPPT_ATTR_ID] || !attrs[IPV6_HOPPT_ATTR_IFINDEX] ||
	    !attrs[IPV6_HOPPT_ATTR_TTSTMPL])
		return -EINVAL;

	label = nla_get_u32(attrs[IPV6_HOPPT_ATTR_ID]);

	rc = ipv6_hoppt_validate_label(label, info->extack);
	if (rc)
		return rc;

	ifindex = nla_get_s32(attrs[IPV6_HOPPT_ATTR_IFINDEX]);
	if (ifindex < 0)
		return -EINVAL;

	ttstmpl = nla_get_s32(attrs[IPV6_HOPPT_ATTR_TTSTMPL]);

	rc = ipv6_hoppt_validate_ttstmpl(ttstmpl, info->extack);
	if (rc)
		return rc;

	rtnl_lock();
	rc = ipv6_hoppt_add_label(net, ifindex, label, ttstmpl);
	rtnl_unlock();

	return rc;
}

static int ipv6_hoppt_genl_del_label(struct sk_buff *unused,
				     struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct nlattr **attrs;
	int ifindex;
	int rc;

	attrs = info->attrs;
	if (!attrs)
		return -EINVAL;

	if (!attrs[IPV6_HOPPT_ATTR_IFINDEX])
		return -EINVAL;

	ifindex = nla_get_s32(attrs[IPV6_HOPPT_ATTR_IFINDEX]);
	if (ifindex < 0)
		return -EINVAL;

	rtnl_lock();
	rc = ipv6_hoppt_del_label(net, ifindex);
	rtnl_unlock();

	return rc;
}

static int
__ipv6_hoppt_gen_dump_label(struct sk_buff *skb, u32 portid, u32 seq, u32 flags,
			    u8 mcd, struct ipv6_hoppt_map_elem *me)
{
	void *hdr;

	hdr = genlmsg_put(skb, portid, seq, &ipv6_hoppt_genl_family, flags,
			  mcd);
	if (!hdr)
		return -ENOMEM;

	if (nla_put_s32(skb, IPV6_HOPPT_ATTR_IFINDEX, me->ifindex) ||
	    nla_put_u32(skb, IPV6_HOPPT_ATTR_ID, me->label) ||
	    nla_put_s32(skb, IPV6_HOPPT_ATTR_TTSTMPL, me->ttstmpl))
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int ipv6_hoppt_genl_show_label(struct sk_buff *skb,
				      struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct ipv6_hoppt_map_elem *me;
	struct ipv6_hoppt_map *hmap;
	struct nlattr **attrs;
	struct sk_buff *msg;
	int ifindex;
	int rc;

	attrs = info->attrs;
	if (!attrs)
		return -EINVAL;

	if (!attrs[IPV6_HOPPT_ATTR_IFINDEX])
		return -EINVAL;

	ifindex = nla_get_s32(attrs[IPV6_HOPPT_ATTR_IFINDEX]);
	if (ifindex < 0)
		return -EINVAL;

	/* we can build the reply message (prealloc sk_buff) */
	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	rtnl_lock();
	rcu_read_lock();

	hmap = ipv6_hoppt_pernet_map(net);

	me = ipv6_hoppt_map_lookup_rtnl(hmap, ifindex);
	if (!me) {
		rc = -ENOENT;
		goto error;
	}

	rc = __ipv6_hoppt_gen_dump_label(msg, info->snd_portid, info->snd_seq,
					 0, IPV6_HOPPT_CMD_SHOW_ID, me);
	if (rc)
		goto error;

	pr_debug("IPv6 Hop-by-Hop PT: show ID=%d from ifindex=%d\n", me->label,
		 ifindex);

	rcu_read_unlock();
	rtnl_unlock();

	return genlmsg_reply(msg, info);

error:
	rcu_read_unlock();
	rtnl_unlock();

	nlmsg_free(msg);
	return rc;
}

static int ipv6_hoppt_genl_dump_labels_start(struct netlink_callback *cb)
{
	struct net *net = sock_net(cb->skb->sk);
	struct ipv6_hoppt_map *hmap;

	hmap = (struct ipv6_hoppt_map *)cb->args[0];
	if (!hmap) {
		cb->args[0] = (long)ipv6_hoppt_pernet_map(net);
		cb->args[1] = 0; /* skip default value is 0 */
	}

	return 0;
}

static int ipv6_hoppt_genl_dump_labels(struct sk_buff *skb,
				       struct netlink_callback *cb)
{
	struct ipv6_hoppt_map *hmap = (struct ipv6_hoppt_map *)cb->args[0];
	struct ipv6_hoppt_map_elem *me;
	long skip = cb->args[1];
	int d = 0, i;
	int rc = 0;

	rtnl_lock();
	rcu_read_lock();

	hash_for_each_rcu(hmap->ht, i, me, hnode) {
		if (d++ < skip)
			continue;

		rc = __ipv6_hoppt_gen_dump_label(skb,
						 NETLINK_CB(cb->skb).portid,
						 cb->nlh->nlmsg_seq,
						 NLM_F_MULTI,
						 IPV6_HOPPT_CMD_DUMP_ID, me);
		if (rc)
			goto done;
	}

	rc = skb->len;

done:
	rcu_read_unlock();
	rtnl_unlock();

	/* update the "skip" value for further calls */
	cb->args[1] = d;

	return rc;
}

static int ipv6_hoppt_genl_dump_labels_done(struct netlink_callback *cb)
{
	/* dump is done */
	return 0;
}

static int ipv6_hoppt_device_event(struct notifier_block *unused,
				   unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct net *net = dev_net(dev);
	int ifindex = dev->ifindex;

	switch (event) {
	case NETDEV_UNREGISTER:
		/* we remove the label associated with the unregistered dev.
		 *
		 * Note that dev->reg is still set to NETREG_RELEASED while
		 * moving the dev from one netns to another. The
		 * ipv6_hoppt_del_label() is designed to be called many
		 * times under the NETDEV_UNREGISTER event. The function
		 * removes the link between the device and the label (if any)
		 * in the map and subsequent calls to the
		 * ipv6_hoppt_del_label() return immediately.
		 */
		ipv6_hoppt_del_label(net, ifindex);

		ipv6_hoppt_del_tgrcv_iface(net, ifindex);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block ipv6_hoppt_dev_notifier_block __read_mostly = {
	.notifier_call = ipv6_hoppt_device_event,
};

static const struct genl_ops ipv6_hoppt_genl_ops[] = {
	{
		.cmd		= IPV6_HOPPT_CMD_ADD_ID,
		.validate	= GENL_DONT_VALIDATE_STRICT |
				  GENL_DONT_VALIDATE_DUMP,
		.doit		= ipv6_hoppt_genl_add_label,
		.flags		= GENL_ADMIN_PERM,
	},
	{
		.cmd		= IPV6_HOPPT_CMD_DEL_ID,
		.validate	= GENL_DONT_VALIDATE_STRICT |
				  GENL_DONT_VALIDATE_DUMP,
		.doit		= ipv6_hoppt_genl_del_label,
		.flags		= GENL_ADMIN_PERM,
	},
	{
		.cmd		= IPV6_HOPPT_CMD_SHOW_ID,
		.validate	= GENL_DONT_VALIDATE_STRICT |
				  GENL_DONT_VALIDATE_DUMP,
		.doit		= ipv6_hoppt_genl_show_label,
		.flags		= GENL_ADMIN_PERM,
	},
	{
		.cmd		= IPV6_HOPPT_CMD_DUMP_ID,
		.validate	= GENL_DONT_VALIDATE_STRICT |
				  GENL_DONT_VALIDATE_DUMP,
		.start		= ipv6_hoppt_genl_dump_labels_start,
		.dumpit		= ipv6_hoppt_genl_dump_labels,
		.done		= ipv6_hoppt_genl_dump_labels_done,
		.flags		= GENL_ADMIN_PERM,
	},
	{
		.cmd		= IPV6_HOPPT_CMD_TGRCV_ADD_ID,
		.validate	= GENL_DONT_VALIDATE_STRICT |
				  GENL_DONT_VALIDATE_DUMP,
		.doit		= ipv6_hoppt_genl_add_tgrcv_iface,
		.flags		= GENL_ADMIN_PERM,
	},
	{
		.cmd		= IPV6_HOPPT_CMD_TGRCV_DEL_ID,
		.validate	= GENL_DONT_VALIDATE_STRICT |
				  GENL_DONT_VALIDATE_DUMP,
		.doit		= ipv6_hoppt_genl_del_tgrcv_iface,
		.flags		= GENL_ADMIN_PERM,
	},
	{
		.cmd		= IPV6_HOPPT_CMD_TGRCV_DUMP_ID,
		.validate	= GENL_DONT_VALIDATE_STRICT |
				  GENL_DONT_VALIDATE_DUMP,
		.doit		= ipv6_hoppt_genl_show_tgrcv_iface,
		.flags		= GENL_ADMIN_PERM,
	},

};

static struct genl_family ipv6_hoppt_genl_family __ro_after_init = {
	.hdrsize	= 0,
	.name		= IPV6_HOPPT_GENL_NAME,
	.version	= IPV6_HOPPT_GENL_VERSION,
	.maxattr	= IPV6_HOPPT_ATTR_MAX,
	.policy		= ipv6_hoppt_genl_policy,
	.netnsok	= true,
	.parallel_ops	= true,
	.ops		= ipv6_hoppt_genl_ops,
	.n_ops		= ARRAY_SIZE(ipv6_hoppt_genl_ops),
	.module		= THIS_MODULE,
};

#if defined(CONFIG_NETFILTER)
static const struct nf_hook_ops ipv6_hoppt_tn_ops = {
	.hook		= ipv6_hoppt_mpt_process,
	.pf		= NFPROTO_IPV6,
	.hooknum	= NF_INET_POST_ROUTING,
	.priority	= NF_IP6_PRI_LAST,
};
#endif

static int __net_init ipv6_hoppt_netns_init(struct net *net)
{
	struct ipv6_hoppt_tgrcv *tgrcv = ipv6_hoppt_pernet_tgrcv(net);
	struct ipv6_hoppt_map *hmap = ipv6_hoppt_pernet_map(net);
#if defined(CONFIG_NETFILTER)
	int rc = nf_register_net_hook(net, &ipv6_hoppt_tn_ops);

	if (rc < 0)
		return rc;
#endif

	ipv6_hoppt_tgrcv_init(tgrcv);
	ipv6_hoppt_map_init(hmap);

	return 0;
}

static void __net_exit ipv6_hoppt_netns_exit(struct net *net)
{
	/* note that on netns destroying, the netdevice notifier will take care
	 * of removing the mapping among devs and labels. For this reason, we
	 * do not need to clean the content of the hmap->ht directly.
	 */
	struct ipv6_hoppt_map *hmap = ipv6_hoppt_pernet_map(net);

	WARN_ON(hmap->elements != 0);

#if defined(CONFIG_NETFILTER)
	nf_unregister_net_hook(net, &ipv6_hoppt_tn_ops);
#endif
}

static struct pernet_operations ipv6_hoppt_netns_ops __net_initdata = {
	.init	= ipv6_hoppt_netns_init,
	.exit	= ipv6_hoppt_netns_exit,
	.id	= &ipv6_hoppt_net_id,
	.size	= sizeof(struct ipv6_hoppt_netns),
};

int __init ipv6_hoppt_init(void)
{
	int err;

	err = register_netdevice_notifier(&ipv6_hoppt_dev_notifier_block);
	if (err)
		goto out;

	err = genl_register_family(&ipv6_hoppt_genl_family);
	if (err)
		goto unreg_nb;

	err = register_pernet_subsys(&ipv6_hoppt_netns_ops);
	if (err)
		goto unreg_genl;

	pr_info("IPv6 Hop-by-Hop Path Tracing (PT)\n");

	return 0;

unreg_genl:
	genl_unregister_family(&ipv6_hoppt_genl_family);
unreg_nb:
	unregister_netdevice_notifier(&ipv6_hoppt_dev_notifier_block);
out:
	return err;
}

void ipv6_hoppt_exit(void)
{
	unregister_pernet_subsys(&ipv6_hoppt_netns_ops);
	genl_unregister_family(&ipv6_hoppt_genl_family);
	unregister_netdevice_notifier(&ipv6_hoppt_dev_notifier_block);
}

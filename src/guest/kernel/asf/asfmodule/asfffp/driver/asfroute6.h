/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfroute6.h
 *
 * Description: Some route/arp helper functions taken from Linux
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/*
 * History
 * 25 Feb 2014 - Subha: Initial Implemenatation: All routines based on Linux
 * routing routines
 *
 */
/******************************************************************************/
#ifndef _ASF_ROUTE6_H
#define _ASF_ROUTE6_H

#include <net/ip6_route.h>
#include <net/ip6_fib.h>

struct _ipv6
{
    struct dst_entry *dst;
    struct neighbour *n;
};



static inline int _asf_route6_resolve(ASFNetDevEntry_t *inputDev, struct _ipv6 *ipv6, ASFBuffer_t *abuf)
{
	struct sk_buff *skb = abuf->nativeBuffer;
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	struct net *net = dev_net(skb->dev);
	int flags = RT6_LOOKUP_F_HAS_SADDR;
	struct flowi6 fl6 = {
		.flowi6_iif = inputDev->ndev->ifindex,
		.daddr = iph->daddr,
		.saddr = iph->saddr,
		.flowlabel = (* (__be32 *) iph) & IPV6_FLOWINFO_MASK,
		.flowi6_mark = skb->mark,
		.flowi6_proto = iph->nexthdr,
	};

	ipv6->dst = ip6_route_lookup(net, &fl6, flags);

	if (ipv6->dst->error != 0)
	{
		asf_debug("ip6_route_lookup returned error %d \n", ipv6->dst->error);
		dst_release(ipv6->dst);
		ipv6->dst = NULL;
		return -1;
	}
	asf_debug("ip6_route_lookup returned error %d\n", ipv6->dst->error);
	return 0;
		
}



static inline int _asf_arp6_resolve(struct _ipv6 *ipv6, ASFBuffer_t *abuf, ASF_IPv6Addr_t *ipv6DestIp)
{
	struct neighbour *neigh;
	int ret;
	
	rcu_read_lock_bh();

	asf_debug("asf_arp6_resolve called\n");
	ipv6->n = ipv6->dst->ops->neigh_lookup(ipv6->dst, abuf->nativeBuffer, ipv6DestIp);
	if (unlikely(!ipv6->n))
	{
		asf_debug("asf_arp6_resolve: failed: neigh_lookup failed\n");
		rcu_read_unlock_bh();
		return -1;
	}
	asf_debug("n state = %d, hh_len = %d\n", ipv6->n->nud_state, ipv6->n->hh.hh_len);
	if (!((ipv6->n->nud_state & NUD_CONNECTED) && ipv6->n->hh.hh_len))
	{
		neigh = ipv6->n;
		// Not sure neigh_release(flow->ipv6.n);
		ipv6->n = NULL;
		dst_hold(ipv6->dst);
		skb_dst_set(abuf->nativeBuffer, ipv6->dst);
		ret = dst_neigh_output(ipv6->dst, neigh, abuf->nativeBuffer);
		if (ret == 0)
		{
			asf_debug("Stack will handle the transmit\n");
			rcu_read_unlock_bh();
			return 2;
		}
		else
		{
			asf_debug("dst_neigh_output returned %d\n", ret);
			rcu_read_unlock_bh();
			return -1;
		}
	}
	asf_debug("__ipv6_neigh_lookup succeeded\n");
	rcu_read_unlock_bh();
	return 0;
}
#endif

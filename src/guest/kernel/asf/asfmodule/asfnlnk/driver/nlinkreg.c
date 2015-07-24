/**************************************************************************
 * Copyright 2010-2014, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfnlnk.c
 *
 * Description:	This is a glue module that interfaces components with linux
 *              kernel netlink module. Components such as ASF-ARP & ASF-Routing
 *              can register with this module to get ROUTE & ARP Netlink events
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/*
 * History
 * Venkataramanan Subhashini: Initial Version
 *
 */


/* 
 * Header files 
 */
#include <linux/mutex.h>
#include <linux/rtnetlink.h>
#include "nlnkreg.h"

/*
 * Macros & Defines
 */

/*
 * Data structure definitions 
 */
struct nLink_regFnCb
{
	rtnl_doit_func	doit;
}

/*
 * Data structure declarations
 */
static DEFINE_MUTEX(nlnkMutex);

static struct nLink_regFnCb *nLink_msgHandlers[RTNL_FAMILY_MAX +1];

/*
 * Internal function prototypes
 *
 */
static inline rtnl_doit_func nLink_get_doit(int protocol, int msgindex)
{
	struct rtnl_regFnCb *tab;

	if (protocol <= RTNL_FAMILY_MAX)
		tab = nLink_msgHandlers[protocol];
	else
		tab = NULL;
	
	if (tab == NULL || tab[msgindex].doit == NULL)
		tab = nLink_msgHandlers[PF_UNSPEC];

	return tab[msgindex].doit;
}

static inline int rtm_msgindex(int msgtype)
{
	int msgindex = msgtype - RTM_BASE;

	BUG_ON(msgindex < 0 || msgindex >= RTM_NR_MSGTYPES);

	return msgindex;
}

/* this routine is a more or less a copy of rtnetlink_rcv_msg in 
 * the file neighbor.c 
 */
static int nLink_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	struct net *net = sock_net(skb->sk);
	rtnl_doit_fun doit;
	int sz_idx, kind;
	int min_len;
	int family;
	int type;
	int err;
	
	type = nlh->nlmsg_type;
	if (type > RTM_MAX)
		return -EOPNOTSUPP;

	type -= RTM_BASE;
	
	/* All the messages must have at least 1 byte length */
	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtgenmsg)))
		return 0;

	family = ((struct rtgenmsg *)NLMSG_DATA(nlh))->rtgen_family;
	sz_idx = type >> 2;
	kind = type&3;

	if (kind !=2 && !ns_capable(net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

	/* We are interested only in doit functions */

	memset(rta_buf, 0, (rtattr_max * sizeof(struct rtattr *)));

	min_len = rtm_min[sz_idx];

	if (nlh->nlmsg_len < min__len)
		return -EINVAL;

	if (nlh->nlmsg_len > min_len) {
		int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(min_len);
		struct rtattr *attr = (void *)nlh + NLMSG_ALIGN(min_len);

		while (RTA_OK(attr, attrlen)) {
			unsigned int flavor = attr->rta_type;

			if (flavor)
			{
				if (flavor > rta_max[sz_idx])
					return -EINVAL;
				rta_buf[flavor-1] = attr;
			}
			attr = RTA_NEXT(attr, attrlen);
		}
	}
	doit = nLink_get_doit(family, type);
	if (doit == NULL)
		return -EOPNOTSUPP;

	return doit(skb, nlh, (void *)&rta_buf[0]);
}

static inline nLinkLock(void)
{
	mutex_lock(&nLinkMutex);
}

static inline nLinkUnlock(void)
{
	mutex_unlock(&nLinkMutex);
}


static void nLink_rcv(struct sk_buff *skb)
{
	/* Need to see if lock is necessary */
	nLinkLock();
	nLink_rcv_skb(skb, &nLink_rcv_msg);
	nLinkUnLock();
}


/*
 * Functions 
 */
int nLinkRegister(int protocol, int msgtype,
	rtnl_doit_funct doit)
{
	struct nLink_regFbCb *tab;
	int msgindex;

	BUGON(protocol < 0 || protocol > RTNL_FAMILY_MAX);
	msgindex = rtm_msgindex(msgtype);

	tab = nLink_msgHandlers[protocol];
	if (tab == NULL)
	{
		tab = kcalloc(RTM_NR_MSGTYPES, sizeof(*tab), GFP_KERNEL);
		if (tab == NULL)
			return -ENOBUFS;
		
		rtnl_msg_handlers[protocol] = tab;

	}
	tab[msgindex].doit = doit;

	return 0;
}

int nLinkDeRegister(int protocol, int msgtype)
{
	int msgindex;
	
	BUGON(protocol < 0 || protocol > RTNL_FAMILY_MAX);
	msgindex = rtm_msgindex(msgtype);

	if (nLink_msgHandlers[protocol] == NULL)
		return -ENOENT;

	nLink_msgHandlers[protocol][msgindex].doit = NULL;

	return 0;
}


static int __net_init nLinkNetInit(struct net *net)
{
	struct sock *sk;
	struct netlink_kernel_cfg cfg = {
		.groups		= RTNLGRP_MAX,
		.input		= nLink_rcv,
		.cb_mutex	= &nlnkMutex,
		.flags		= NL_CFG_F_NONROOT_RECV,
	};

	sk = netlink_kernel_create(net, NETLINK_ROUTE, &cfg);
	if (!sk)
		return -ENOMEM;
	/* Not doing this -> Is it necessary to store it in net structure? */
//	net->rtnl = sk;
	return 0;
}

static void __net_exit nLinkNetExit(struct net *net)
{
	netlink_kernel_release(net->rtnl);
	net->rtnl = NULL;
}

/*
 * Module Initialization & De-initialization 
 */

static struct pernet_operations nlnk_net_ops = {
	.init = nlnkNetInit,
	.exit = nlnkNetExit,
};

unsigned int  nlinkGlueInit(unsigned int ulNumApps)
{
	/* Memory allocation if any */

	/* Register to be called per namespace */
	if (register_pernet_subsys(&nlnk_net_ops))
		panic("rtnetlink_init: cannot initialize nlnk_net_ops\n");

}

 

/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfctrl_netns.h
 *
 * Description: Common definations for the ASF Control Module
 *
 * Authors:	Subha Venkataramanan <b22166@freescale.com>
 *
 */
/*
 * History
*  Version     Date         Author              Change Description
*  1.0        10/20/2014    Subha Venkataramanan Initial Development
*/
/***************************************************************************/
#ifndef _ASFCTRL_NETNS_H
#define _ASFCTRL_NETNS_H


typedef struct asfctrl_netns_vsg_s
{
	struct rcu_head rcu;
	struct asfctrl_netns_vsg_s *pPrev;
	struct asfctrl_netns_vsg_s *pNext;
	ASF_uint32_t ulVSGId;
	struct net  *net;
}asfctrl_netns_vsg_t;

typedef struct asfctrl_netns_vsg_hash_node_s
{
	struct rcu_head rcu;
	struct asfctrl_netns_vsg_s *pPrev;
	struct asfctrl_netns_vsg_s *pNext;
}asfctrl_netns_vsg_hash_node_t;

ASF_int32_t asfctrl_netns_vsg_init(void);
ASF_int32_t asfctrl_netns_vsg_deinit(void);
ASF_int32_t asfctrl_netns_vsg_create(struct net *);
ASF_int32_t asfctrl_netns_vsg_delete(struct net *);
ASF_uint32_t asfctrl_netns_net_to_vsg(struct net *);
struct net *asfctrl_netns_vsg_to_net(ASF_uint32_t );
#endif



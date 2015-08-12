#ifndef _VIRTIO_IPSEC_H
#define _VIRTIO_IPSEC_H


#define VIRTIO_IPSEC_VENDOR_ID 	0x1AF4
#define VIRTIO_IPSEC_DEVICE_ID  0x1054

/* The feature bitmap for virtio net */

/*
The PCI feature bits part of Virtio Standards will be supported. 
VIRTIO_RING_F_INDIRECT_DESC	28	
VIRTIO_RING_F_EVENT_IDX		29	
*/

#define VIRTIO_IPSEC_F_SG_BUFFERS 0
#define VIRTIO_IPSEC_F_AH 	1
#define VIRTIO_IPSEC_F_WESP			(2)	/* Device supports WESP */
#define VIRTIO_IPSEC_F_SA_BUNDLES		(3)	/* Device supports SA bundle */
#define VIRTIO_IPSEC_F_UDP_ENCAPSULATION	(4)	/* UDP Encapsulation for NAT Traversal */
#define VIRTIO_IPSEC_F_TFC			(5)	/* Device supports Traffic Flow Confidentiality */
#define VIRTIO_IPSEC_F_ESN			(6)	/* Device supports Extended Sequence number */
#define VIRTIO_IPSEC_F_ECN			(7)	/* Device supports Explicit Congestion Notification */
#define VIRTIO_IPSEC_F_DF			(8)	/* DF bit support */
#define VIRTIO_IPSEC_F_ANTI_REPLAY_CHECK	(9)	/* Device supports Anti replay check */
#define VIRTIO_IPSEC_IPV6_SUPPORT		(10)	/* Is Support IPv6 */	
#define VIRTIO_IPSEC_F_SOFT_LIFETIME_BYTES_NOTIFY	(11)	/* Device notifies when soft life time is about to expire, so that Guest can initiate new SA negotiation */
#define VIRTIO_IPSEC_F_SEQNUM_OVERFLOW_NOTIFY	12 	/* Device notifies when sequence number is about to overflow, so that Guest can initiate new SA negotiation */
#define VIRTIO_IPSEC_F_SEQNUM_PERIODIC_NOTIFY   13	/* Periodic update of Sequence number from device to guest */

#define SAFE_REF_ARRAY_GET_DATA(table, index) (table->base[index].data)
#define SAFE_REF_ARRAY_GET_MAGIC_NUM(table, index) (table->base[index].magic_num)



struct safe_ref_array_node {
	void data;
	u32 magic_num;
	struct safe_ref_array_node *next;
	struct safe_ref_array_node *prev;
};

struct safe_ref_array {
	safe_ref_array_node *head;
	safe_ref_array_node *base;
	u32 num_entries;
	u32 num_cur_entries;
	u32 magic_num;
	spinlock_t  lock;
	bool b_lock;
};

#define IPSEC_IFNAMESIZ	16	

struct data_q_per_cpu_vars {
		u8 data_q_pair_index_start_decap;
		u8 data_q_pair_index_cur_decap;
		u8 data_q_pair_index_start_encap;
		u8 data_q_pair_index_cur_encap;
};

struct ipsec_queue {
	struct list_head link;	
	/* Virtqueue associated with the encap queue */
	struct virtqueue *vq;

	/* Fragments + linear part + virtio header: Need to Check : AVS */
	struct scatterlist sg[MAX_SKB_FRAGS+2];

	/* Copied from virtio-net: need to check: AVS */
	char name[40];
};



#define VIRTIO_IPSEC_MAX_CB_ARG_SIZE 64
struct virt_ipsec_data_ctx
{
	struct list_head link;
	struct virtio_ipsec_hdr hdr;
	struct g_ipsec_la_resp_cbfn	cb_fn;
	u8 cb_arg[VIRTIO_IPSEC_MAX_CB_ARG_SIZE];
	u32 cb_arg_len;
};
	
struct ipsec_data_q_pair
{
	struct ipsec_queue decap_q;
	struct ipsec_queue encap_q;
	struct virt_ipsec_data_ctx *decap_ctx;
	u32 decap_q_index_max;
	u32 decap_q_index_cur;
	struct virt_ipsec_data_ctx *encap_ctx;
	u32 encap_q_index_max;
	u32 encap_q_index_cur;
};	

/* Virtio Accelerator Block */
struct virt_ipsec_info {
	struct list_head node; /* prev/next entries */
	struct virtio_device *vdev; /* Pointer to virtio device */
	char name[IPSEC_IFNAMESIZ];
	struct list_head apps; /* List of application contexts */
	struct ipsec_queue *cvq; /* Pointer to control virt queue */
	struct ipsec_queue *nvq; /* Pointer to notification virt queue */
	/* Following Out+Inq will be percpu variables */
	struct ipsec_data_q_pair *data_q_pair; /* decap-q, encap-q, decap-hdrs, encap-hdrs */
	struct virtio_ipsec_ctrl_hdr *ctrl_hdr; /* Array of allocated control headers */
	struct data_q_per_cpu_vars *data_q_per_cpu_vars;
	struct work_struct c_work;
	u8 vcpu_scaling; /* Number of queues required to achieve vcpu scaling */
	u8 device_scaling; /* Number of queues required to achieve device scaling */
	u8 num_q_pairs_per_vcpu; /* Number of queues per vcpu */
	u8 num_queues; /* Number of queues (Encap + decap) across vpcus */
	spinlock_t	      lock;
	u32 
	    sg_buffer:1,
	    ah:1,
	    wesp:1,
	    sa_bundles:1,
	    udp_encap:1,
	    tfc:1,
	    esn:1,
	    ecn:1,
            df:1,
            anti_replay:1,
	    v6_support:1,
	    notify_lifetime:1,
	    notify_seqnum_overflow:1,
	    notify_seqnum_periodic:1;
	/* affinity hint */
	bool affinity_hint_set;
};

int32 safe_ref_array_setup(
	safe_ref_array *table,  
	u32 num_entries, bool b_lock)
{
	int ii;
	safe_ref_array_node *node,

	node = kzalloc((sizeof(safe_ref_array_node)*num_entries), GFP_KERNEL);

	if (NULL == node) {
		return -ENOMEM;
	}
	table->head = table->base = node;
	table->num_entries = num_entries;
	table->magic_num= 1;

	/* Set up first node */
	node[0].prev = NULL;
	node[0].next = &(node[1]);
	for (ii = 1; ii < (num_entries-1); ii++) {
		node[ii].next = &(node[ii+1]);
		node[ii+1].prev = &(node[ii]);
	}
	/* Set up Last node */
	node[ii].next = NULL;
	node[ii].prev = &(node[ii-1]);

	if (b_lock)
		spin_lock_init(&table->tblLock);

	table->num_cur_entries = 0;
	table->bLock = b_lock;

	return 0;
}

void safe_ref_array_cleanup(safe_ref_array *table)
{
	if (table->base)
		kfree(table->base);
}

/* ptrArray_add */
static inline unsigned int safe_ref_array_add(
	safe_ref_array *table,  void *data)
{
	unsigned int index;
	safe_ref_array_node *node;

	if (table->b_lock)
		spin_lock_bh(&table->lock);

	if (table->num_cur_entries >= table->num_entries)	{
		spin_unlock_bh(&table->lock);
		index = table->num_entries;
		goto err_max_table;
	}
	
	if (table->head == NULL) {
		node = NULL;
	} else {
		node = table->head;
		table->head = table->head->pNext;
		if (table->head)
			table->head->prev = NULL;

	}
	table->num_cur_entries++;
	if (table->bLock)
		spin_unlock_bh(&table->lock);

	if (node) {
		node->next = NULL;
		node->prev = NULL;
		node->data = data;
		table->ulMagicNum = (table->ulMagicNum + 1) == 0 ? 1 :  table->ulMagicNum+1;
		node->ulMagicNum = table->ulMagicNum;
		index = node - table->pBase;
		smp_wmb();
	} else {
		index= table->num_entries +1;
	}

#ifdef POINTER_ARRAY_DEBUG
	printk("safe_ref_array_add : Index =%d, pNode = 0x%x, pTable->pBase = 0x%x\r\n", ulIndex, pNode, pTable->pBase);
#endif

err_max_table:
	return index;
}



static inline void safe_ref_array_node_delete(
	safe_ref_array *table, 
	u32 index,
	void (*func)(struct rcu_head *rcu))
{
	safe_ref_array_node *node = &(table->base[index]);
	struct rcu_head *data;


	node->magic_num= 0;
	data = node->data;
	node->data = NULL;

	smp_wmb();

	if (table->bLock)
		spin_lock_bh(&table->tblLock);
	if (table->head) {
		node->next = table->head;
		table->head->prev = node;
	}
	table->head = node;
	if (table->b_lock)
		spin_unlock_bh(&table->lock);

	if (func != NULL)
		call_rcu(data,  func);
}






#endif

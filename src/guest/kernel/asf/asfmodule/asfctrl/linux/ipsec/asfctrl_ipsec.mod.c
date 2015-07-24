#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xe425eab3, "module_layout" },
	{ 0x326201e5, "secpath_dup" },
	{ 0x2c4dcf73, "kmalloc_caches" },
	{ 0xd965aa88, "ASFGetCapabilities" },
	{ 0x98dd7053, "__xfrm_policy_lookup" },
	{ 0x4c4fef19, "kernel_stack" },
	{ 0xb43e2628, "asfctrl_vsg_l2blobconfig_id" },
	{ 0xb8a5445b, "asfctrl_dev_get_cii" },
	{ 0x1e6f2b9a, "dst_release" },
	{ 0x1637ff0f, "_raw_spin_lock_bh" },
	{ 0x33cb91b5, "km_state_expired" },
	{ 0x35c66406, "ip6_forward" },
	{ 0x1976aa06, "param_ops_bool" },
	{ 0x54efb5d6, "cpu_number" },
	{ 0x7d11c268, "jiffies" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xda3d5aa2, "ip_forward" },
	{ 0xfb578fc5, "memset" },
	{ 0x4aecad9f, "unregister_ipsec_offload_hook" },
	{ 0x27e1a049, "printk" },
	{ 0xa7ad8481, "asf_ip_send" },
	{ 0x6b748d9d, "netif_receive_skb" },
	{ 0xbb9f9860, "asfctrl_invalidate_sessions" },
	{ 0x11a169f4, "xfrm_register_km" },
	{ 0x1e619a2c, "ip6_route_input" },
	{ 0x3d0c189b, "init_net" },
	{ 0xc0ccc396, "ip6_route_output" },
	{ 0x2438c6b4, "ip_route_input_noref" },
	{ 0x3ff62317, "local_bh_disable" },
	{ 0x41e9fac7, "__secpath_destroy" },
	{ 0xd98644d0, "xfrm_state_policy_mapping" },
	{ 0xdb805047, "__alloc_skb" },
	{ 0xc9d54888, "xfrm_unregister_km" },
	{ 0xba63339c, "_raw_spin_unlock_bh" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xaf804e4d, "kfree_skb" },
	{ 0x29c7b72f, "hrtimer_start" },
	{ 0x799aca4, "local_bh_enable" },
	{ 0x1ca09506, "asfIpv6MakeFragment" },
	{ 0xdb66d29c, "pskb_expand_head" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xd280fff5, "kmem_cache_alloc_trace" },
	{ 0xd52bf1ce, "_raw_spin_lock" },
	{ 0xf853a9b2, "ip_route_output_flow" },
	{ 0x2f9c1d2f, "xfrm_state_lookup" },
	{ 0x37a0cba, "kfree" },
	{ 0x69acdf38, "memcpy" },
	{ 0xb7e36e62, "register_ipsec_offload_hook" },
	{ 0x2121f48e, "skb_put" },
	{ 0x6c8f4630, "asfctrl_register_ipsec_func" },
	{ 0x586da098, "asfctrl_vsg_config_id" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=asf,asfctrl";


MODULE_INFO(srcversion, "3A17B550955D4D1E9E1AC18");

#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <string.h>
#include <net/if_arp.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <libnl3/netlink/attr.h>
#include <libnl3/netlink/msg.h>
#include <libnl3/netlink/netlink.h>
#include <linux/openvswitch.h>

#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
#include <nftables/libnftables.h>
#endif

#ifdef CONFIG_HAS_SELINUX
#include <selinux/selinux.h>
#endif

#include "../soccr/soccr.h"

#include "imgset.h"
#include "namespaces.h"
#include "net.h"
#include "libnetlink.h"
#include "cr_options.h"
#include "sk-inet.h"
#include "tun.h"
#include "util-pie.h"
#include "plugin.h"
#include "action-scripts.h"
#include "sockets.h"
#include "pstree.h"
#include "string.h"
#include "sysctl.h"
#include "kerndat.h"
#include "util.h"
#include "external.h"
#include "fdstore.h"
#include "netfilter.h"
#include "mount.h"
#include "common/list.h"

#include "protobuf.h"
#include "images/netdev.pb-c.h"
#include "images/inventory.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "net: "

#ifndef IFLA_NEW_IFINDEX
#define IFLA_NEW_IFINDEX 49
#endif

#ifndef IFLA_LINK_NETNSID
#define IFLA_LINK_NETNSID 37
#undef IFLA_MAX
#define IFLA_MAX IFLA_LINK_NETNSID
#endif

#ifndef RTM_NEWNSID
#define RTM_NEWNSID 88
#endif

#ifndef IFLA_MACVLAN_FLAGS
#define IFLA_MACVLAN_FLAGS 2
#endif

enum {
	IFLA_IPTUN_UNSPEC,
	IFLA_IPTUN_LINK,
	IFLA_IPTUN_LOCAL,
	IFLA_IPTUN_REMOTE,
	IFLA_IPTUN_TTL,
	IFLA_IPTUN_TOS,
	IFLA_IPTUN_ENCAP_LIMIT,
	IFLA_IPTUN_FLOWINFO,
	IFLA_IPTUN_FLAGS,
	IFLA_IPTUN_PROTO,
	IFLA_IPTUN_PMTUDISC,
	IFLA_IPTUN_6RD_PREFIX,
	IFLA_IPTUN_6RD_RELAY_PREFIX,
	IFLA_IPTUN_6RD_PREFIXLEN,
	IFLA_IPTUN_6RD_RELAY_PREFIXLEN,
	IFLA_IPTUN_ENCAP_TYPE,
	IFLA_IPTUN_ENCAP_FLAGS,
	IFLA_IPTUN_ENCAP_SPORT,
	IFLA_IPTUN_ENCAP_DPORT,
	__IFLA_IPTUN_MAX,
};
#define IFLA_IPTUN_MAX (__IFLA_IPTUN_MAX - 1)

#ifndef IFLA_VXLAN_DF
#define IFLA_VXLAN_DF 29
#undef IFLA_VXLAN_MAX
#define IFLA_VXLAN_MAX IFLA_VXLAN_DF
#endif

static int ns_sysfs_fd = -1;

int read_ns_sys_file(char *path, char *buf, int len)
{
	int fd, rlen;

	BUG_ON(ns_sysfs_fd == -1);

	fd = openat(ns_sysfs_fd, path, O_RDONLY, 0);
	if (fd < 0) {
		pr_perror("Can't open ns' %s", path);
		return -1;
	}

	rlen = read(fd, buf, len);
	close(fd);

	if (rlen == len) {
		pr_err("Too small buffer to read ns sys file %s\n", path);
		return -1;
	}

	if (rlen > 0)
		buf[rlen - 1] = '\0';

	return rlen;
}

static bool sysctl_entries_equal(SysctlEntry *a, SysctlEntry *b)
{
	if (a->type != b->type)
		return false;

	switch (a->type) {
	case SYSCTL_TYPE__CTL_32:
		return a->has_iarg && b->has_iarg && a->iarg == b->iarg;
	case SYSCTL_TYPE__CTL_STR:
		return a->sarg && b->sarg && !strcmp(a->sarg, b->sarg);
	default:;
	}

	return false;
}

static char *devconfs4[] = {
	"accept_local",
	"accept_redirects",
	"accept_source_route",
	"arp_accept",
	"arp_announce",
	"arp_filter",
	"arp_ignore",
	"arp_notify",
	"bootp_relay",
	"disable_policy",
	"disable_xfrm",
	"force_igmp_version",
	"forwarding",
	"igmpv2_unsolicited_report_interval",
	"igmpv3_unsolicited_report_interval",
	"log_martians",
	"medium_id",
	"promote_secondaries",
	"proxy_arp",
	"proxy_arp_pvlan",
	"route_localnet",
	"rp_filter",
	"secure_redirects",
	"send_redirects",
	"shared_media",
	"src_valid_mark",
	"tag",
	"ignore_routes_with_linkdown",
	"drop_gratuitous_arp",
	"drop_unicast_in_l2_multicast",
};

char *devconfs6[] = {
	"accept_dad",
	"accept_ra",
	"accept_ra_defrtr",
	"accept_ra_from_local",
	"accept_ra_min_hop_limit",
	"accept_ra_mtu",
	"accept_ra_pinfo",
	"accept_ra_rt_info_max_plen",
	"accept_ra_rtr_pref",
	"accept_redirects",
	"accept_source_route",
	"autoconf",
	"dad_transmits",
	"disable_ipv6",
	"drop_unicast_in_l2_multicast",
	"drop_unsolicited_na",
	"force_mld_version",
	"force_tllao",
	"forwarding",
	"hop_limit",
	"ignore_routes_with_linkdown",
	"keep_addr_on_down",
	"max_addresses",
	"max_desync_factor",
	"mldv1_unsolicited_report_interval",
	"mldv2_unsolicited_report_interval",
	"mtu",
	"ndisc_notify",
	"optimistic_dad",
	"proxy_ndp",
	"regen_max_retry",
	"router_probe_interval",
	"router_solicitation_delay",
	"router_solicitation_interval",
	"router_solicitations",
	"stable_secret",
	"suppress_frag_ndisc",
	"temp_prefered_lft",
	"temp_valid_lft",
	"use_oif_addrs_only",
	"use_optimistic",
	"use_tempaddr",
};

#define CONF_OPT_PATH	  "net/%s/conf/%s/%s"
#define MAX_CONF_OPT_PATH IFNAMSIZ + 60
#define MAX_STR_CONF_LEN  200

static const char *unix_conf_entries[] = {
	"max_dgram_qlen",
};

/*
 * MAX_CONF_UNIX_PATH = (sizeof(CONF_UNIX_FMT) - strlen("%s"))
 * 					  + MAX_CONF_UNIX_OPT_PATH
 */
#define CONF_UNIX_BASE	       "net/unix"
#define CONF_UNIX_FMT	       CONF_UNIX_BASE "/%s"
#define MAX_CONF_UNIX_OPT_PATH 32
#define MAX_CONF_UNIX_PATH     (sizeof(CONF_UNIX_FMT) + MAX_CONF_UNIX_OPT_PATH - 2)

static int net_conf_op(char *tgt, SysctlEntry **conf, int n, int op, char *proto, struct sysctl_req *req,
		       char (*path)[MAX_CONF_OPT_PATH], int size, char **devconfs, SysctlEntry **def_conf)
{
	int i, ri, ar = -1;
	int ret, flags = op == CTL_READ ? CTL_FLAGS_OPTIONAL : 0;
	SysctlEntry **rconf;

	if (n > size)
		pr_warn("The image contains unknown sysctl-s\n");

	if (opts.weak_sysctls)
		flags = CTL_FLAGS_OPTIONAL;

	rconf = xmalloc(sizeof(SysctlEntry *) * size);
	if (!rconf)
		return -1;

	for (i = 0, ri = 0; i < size; i++) {
		if (i >= n) {
			pr_warn("Skip %s/%s\n", tgt, devconfs[i]);
			continue;
		}
		/*
		 * If dev conf value is the same as default skip restoring it,
		 * mtu may be changed by disable_ipv6 so we can not skip
		 * it's restore
		 */
		if (def_conf && sysctl_entries_equal(conf[i], def_conf[i]) && strcmp(devconfs[i], "mtu")) {
			pr_debug("Skip %s/%s, coincides with default\n", tgt, devconfs[i]);
			continue;
		}

		/*
		 * Make "accept_redirects" go last on write(it should
		 * restore after forwarding to be correct)
		 */
		if (op == CTL_WRITE && !strcmp(devconfs[i], "accept_redirects")) {
			ar = i;
			continue;
		}

		snprintf(path[i], MAX_CONF_OPT_PATH, CONF_OPT_PATH, proto, tgt, devconfs[i]);
		req[ri].name = path[i];
		req[ri].flags = flags;
		switch (conf[i]->type) {
		case SYSCTL_TYPE__CTL_32:
			req[ri].type = CTL_32;

			/* skip non-existing sysctl */
			if (op == CTL_WRITE && !conf[i]->has_iarg)
				continue;

			req[ri].arg = &conf[i]->iarg;
			break;
		case SYSCTL_TYPE__CTL_STR:
			req[ri].type = CTL_STR(MAX_STR_CONF_LEN);
			req[ri].flags |=
				op == CTL_READ && !strcmp(devconfs[i], "stable_secret") ? CTL_FLAGS_READ_EIO_SKIP : 0;

			/* skip non-existing sysctl */
			if (op == CTL_WRITE && !conf[i]->sarg)
				continue;

			req[ri].arg = conf[i]->sarg;
			break;
		default:
			continue;
		}
		rconf[ri] = conf[i];
		ri++;
	}

	if (ar != -1 && conf[ar]->type == SYSCTL_TYPE__CTL_32 && conf[ar]->has_iarg) {
		snprintf(path[ar], MAX_CONF_OPT_PATH, CONF_OPT_PATH, proto, tgt, devconfs[ar]);
		req[ri].name = path[ar];
		req[ri].type = CTL_32;
		req[ri].arg = &conf[ar]->iarg;
		req[ri].flags = flags;
		rconf[ri] = conf[ar];
		ri++;
	}

	ret = sysctl_op(req, ri, op, CLONE_NEWNET);
	if (ret < 0) {
		pr_err("Failed to %s %s/<confs>\n", (op == CTL_READ) ? "read" : "write", tgt);
		goto err_free;
	}

	if (op == CTL_READ) {
		/* (un)mark (non-)existing sysctls in image */
		for (i = 0; i < ri; i++)
			if (req[i].flags & CTL_FLAGS_HAS) {
				if (rconf[i]->type == SYSCTL_TYPE__CTL_32)
					rconf[i]->has_iarg = true;
			} else {
				if (rconf[i]->type == SYSCTL_TYPE__CTL_STR)
					rconf[i]->sarg = NULL;
			}
	}

err_free:
	xfree(rconf);
	return ret;
}

static int ipv4_conf_op(char *tgt, SysctlEntry **conf, int n, int op, SysctlEntry **def_conf)
{
	struct sysctl_req req[ARRAY_SIZE(devconfs4)];
	char path[ARRAY_SIZE(devconfs4)][MAX_CONF_OPT_PATH];

	return net_conf_op(tgt, conf, n, op, "ipv4", req, path, ARRAY_SIZE(devconfs4), devconfs4, def_conf);
}

static int ipv6_conf_op(char *tgt, SysctlEntry **conf, int n, int op, SysctlEntry **def_conf)
{
	struct sysctl_req req[ARRAY_SIZE(devconfs6)];
	char path[ARRAY_SIZE(devconfs6)][MAX_CONF_OPT_PATH];

	return net_conf_op(tgt, conf, n, op, "ipv6", req, path, ARRAY_SIZE(devconfs6), devconfs6, def_conf);
}

static int unix_conf_op(SysctlEntry ***rconf, size_t *n, int op)
{
	int i, ret = -1, flags = 0;
	char path[ARRAY_SIZE(unix_conf_entries)][MAX_CONF_UNIX_PATH] = {};
	struct sysctl_req req[ARRAY_SIZE(unix_conf_entries)] = {};
	SysctlEntry **conf = *rconf;

	if (*n != ARRAY_SIZE(unix_conf_entries)) {
		pr_err("unix: Unexpected entries in config (%zu %zu)\n", *n, ARRAY_SIZE(unix_conf_entries));
		return -EINVAL;
	}

	if (opts.weak_sysctls || op == CTL_READ)
		flags = CTL_FLAGS_OPTIONAL;

	for (i = 0; i < *n; i++) {
		snprintf(path[i], MAX_CONF_UNIX_PATH, CONF_UNIX_FMT, unix_conf_entries[i]);
		req[i].name = path[i];
		req[i].flags = flags;

		switch (conf[i]->type) {
		case SYSCTL_TYPE__CTL_32:
			req[i].type = CTL_32;
			req[i].arg = &conf[i]->iarg;
			break;
		default:
			pr_err("unix: Unknown config type %d\n", conf[i]->type);
			return -1;
		}
	}

	ret = sysctl_op(req, *n, op, CLONE_NEWNET);
	if (ret < 0) {
		pr_err("unix: Failed to %s %s/<confs>\n", (op == CTL_READ) ? "read" : "write", CONF_UNIX_BASE);
		return -1;
	}

	if (op == CTL_READ) {
		bool has_entries = false;

		for (i = 0; i < *n; i++) {
			if (req[i].flags & CTL_FLAGS_HAS) {
				conf[i]->has_iarg = true;
				if (!has_entries)
					has_entries = true;
			}
		}

		/*
		 * Zap the whole section of data.
		 * Unix conf is optional.
		 */
		if (!has_entries) {
			*n = 0;
			*rconf = NULL;
		}
	}

	return 0;
}

static char *coreconfs[] = {
	"somaxconn",
};

static int core_conf_op(SysctlEntry **conf, int n, int op)
{
	struct sysctl_req req[ARRAY_SIZE(coreconfs)];
	char path[ARRAY_SIZE(coreconfs)][256];
	SysctlEntry *rconf[ARRAY_SIZE(coreconfs)] = {};
	int ret = 0;
	int i, ri;

	if (n > ARRAY_SIZE(coreconfs))
		pr_warn("The image contains unknown sysctl-s\n");

	for (i = 0, ri = 0; i < ARRAY_SIZE(coreconfs); i++) {
		if (i >= n) {
			pr_warn("Skip %s\n", coreconfs[i]);
			continue;
		}

		if (conf[i]->type != SYSCTL_TYPE__CTL_32)
			continue;
		if (op == CTL_WRITE && !conf[i]->has_iarg)
			continue;

		snprintf(path[i], sizeof(path[i]), "net/core/%s", coreconfs[i]);
		req[ri].name = path[i];
		req[ri].type = CTL_32;
		req[ri].arg = &conf[i]->iarg;
		if (op == CTL_READ || opts.weak_sysctls)
			req[ri].flags = CTL_FLAGS_OPTIONAL;
		else
			req[ri].flags = 0;

		rconf[ri] = conf[i];
		ri++;
	}

	ret = sysctl_op(req, ri, op, CLONE_NEWNET);
	if (ret < 0) {
		pr_err("Failed to %s\n", (op == CTL_READ ? "read" : "write"));
		return ret;
	}

	if (op == CTL_READ) {
		for (i = 0; i < ri; i++) {
			if (req[i].flags & CTL_FLAGS_HAS)
				rconf[i]->has_iarg = true;
		}
	}

	return ret;
}

/*
 * I case if some entry is missing in
 * the kernel, simply write DEVCONFS_UNUSED
 * into the image so we would skip it.
 */
#define DEVCONFS_UNUSED (-1u)

static int ipv4_conf_op_old(char *tgt, int *conf, int n, int op, int *def_conf)
{
	int i, ri;
	int ret, flags = op == CTL_READ ? CTL_FLAGS_OPTIONAL : 0;
	struct sysctl_req req[ARRAY_SIZE(devconfs4)];
	char path[ARRAY_SIZE(devconfs4)][MAX_CONF_OPT_PATH];

	if (n > ARRAY_SIZE(devconfs4))
		pr_warn("The image contains unknown sysctl-s\n");

	for (i = 0, ri = 0; i < ARRAY_SIZE(devconfs4); i++) {
		if (i >= n) {
			pr_warn("Skip %s/%s\n", tgt, devconfs4[i]);
			continue;
		}
		/*
		 * If dev conf value is the same as default skip restoring it
		 */
		if (def_conf && conf[i] == def_conf[i]) {
			pr_debug("DEBUG Skip %s/%s, val =%d\n", tgt, devconfs4[i], conf[i]);
			continue;
		}

		if (op == CTL_WRITE && conf[i] == DEVCONFS_UNUSED)
			continue;
		else if (op == CTL_READ)
			conf[i] = DEVCONFS_UNUSED;

		snprintf(path[i], MAX_CONF_OPT_PATH, CONF_OPT_PATH, "ipv4", tgt, devconfs4[i]);
		req[ri].name = path[i];
		req[ri].arg = &conf[i];
		req[ri].type = CTL_32;
		req[ri].flags = flags;
		ri++;
	}

	ret = sysctl_op(req, ri, op, CLONE_NEWNET);
	if (ret < 0) {
		pr_err("Failed to %s %s/<confs>\n", (op == CTL_READ) ? "read" : "write", tgt);
		return -1;
	}
	return 0;
}

struct netlink_genl_family {
	char *name;
	int16_t id;
};

static struct netlink_genl_family nl_genl_list[] = {
	{.name = OVS_DATAPATH_FAMILY, .id = 0},
	{.name = OVS_VPORT_FAMILY, .id = 0}
};

static void fill_genl_families(void)
{
	int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(nl_genl_list); i++) {
		if (nl_genl_list[i].id)
			continue;

		ret = get_genl_family_id(&(nl_genl_list[i].id), nl_genl_list[i].name, strlen(nl_genl_list[i].name) + 1);
		if (ret)
			pr_warn("Unable to find genlik id for %s\n", nl_genl_list[i].name);

		pr_debug("Found genl id %d for %s\n", nl_genl_list[i].id, nl_genl_list[i].name);
	}
}

static int16_t get_cached_genl_family_id(char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(nl_genl_list); i++) {
		if (!strcmp(nl_genl_list[i].name, name) && nl_genl_list[i].id)
			return nl_genl_list[i].id;
	}

	return -1;
}

struct ovs_vport {
	OvsVportEntry vport_entry;
	int ifindex;
	char name[IFNAMSIZ];
	OvsVportTunnelOptions to;
	struct list_head list;
};

struct ovs_datapath {
	OvsDatapathLinkEntry dp_entry;
	int ifindex;
	char name[IFNAMSIZ];
	struct list_head vports_head;
	struct list_head list;
};

static LIST_HEAD(ovs_dp_head);

/*
 * 128 bytes should be sufficient for most OVS requests connected to datapaths\vports,
 * because there are like 5-6 int values and one string 16< bytes long
 */

struct ovs_request {
	struct nlmsghdr h;
	struct genlmsghdr gh;
	struct ovs_header ovsh;
	char buf[128];
};

static int rc_dump_one_vport(struct nlmsghdr *h, struct ns_id *ns, void *arg)
{
	struct nlattr *tb[OVS_VPORT_ATTR_MAX + 1];
	struct list_head *vport_head = arg;
	struct ovs_vport *item = NULL;

	item = xzalloc(sizeof(struct ovs_vport));
	if (!item)
		return -ENOMEM;

	ovs_vport_entry__init(&item->vport_entry);
	ovs_vport_tunnel_options__init(&item->to);
	list_add(&item->list, vport_head);

	nlmsg_parse(h, sizeof(struct genlmsghdr) + sizeof(struct ovs_header), tb, OVS_VPORT_ATTR_MAX, NULL);

	BUG_ON(!tb[OVS_VPORT_ATTR_NAME]);
	strncpy(item->name, nla_data(tb[OVS_VPORT_ATTR_NAME]), IFNAMSIZ - 1);
	item->vport_entry.name = (void *)item->name;

	BUG_ON(!tb[OVS_VPORT_ATTR_TYPE]);
	item->vport_entry.type = nla_get_s32(tb[OVS_VPORT_ATTR_TYPE]);

	BUG_ON(!tb[OVS_VPORT_ATTR_PORT_NO]);
	item->vport_entry.port_no = nla_get_u32(tb[OVS_VPORT_ATTR_PORT_NO]);

	item->vport_entry.datapath_ifindex = ((struct ovs_request *)h)->ovsh.dp_ifindex;

	if (tb[OVS_VPORT_ATTR_UPCALL_PID])
		item->vport_entry.upcall_pid = nla_get_u32(tb[OVS_VPORT_ATTR_UPCALL_PID]);
	else
		item->vport_entry.upcall_pid = 0;

	if (tb[OVS_VPORT_ATTR_IFINDEX])
		item->ifindex = nla_get_s32(tb[OVS_VPORT_ATTR_IFINDEX]);

	if (tb[OVS_VPORT_ATTR_OPTIONS]) {
		struct nlattr *vp_attr[OVS_TUNNEL_ATTR_MAX + 1];

		nla_parse_nested(vp_attr, OVS_TUNNEL_ATTR_MAX, tb[OVS_VPORT_ATTR_OPTIONS], NULL);

		if (vp_attr[OVS_TUNNEL_ATTR_DST_PORT]) {
			item->to.port = *(uint16_t *)nla_data(vp_attr[OVS_TUNNEL_ATTR_DST_PORT]);
			item->vport_entry.opt = &item->to;
		}

		if (vp_attr[OVS_TUNNEL_ATTR_EXTENSION]) {
			pr_err("Unsupported value OVS_TUNNEL_ATTR_EXTENSION at port %s\n", item->name);
			return -ENOTSUP;
		}
	}

	if (item->vport_entry.type > OVS_VPORT_TYPE_INTERNAL && item->vport_entry.type != OVS_VPORT_TYPE_VXLAN) {
		pr_err("Unsupported openvswitch port type %d (%s)\n", item->vport_entry.type, item->name);
		return -ENOTSUP;
	}

	/* Currently we create vxlan through rtnetlink and just plug it as netdev rather than ovs */
	if (item->vport_entry.type == OVS_VPORT_TYPE_VXLAN)
		item->vport_entry.type = OVS_VPORT_TYPE_NETDEV;

	if (tb[OVS_VPORT_ATTR_NETNSID]) {
		pr_err("Unsupported openvswitch configuration: can't dump vports that are moved to another netns (%s)\n",
		       item->name);
		return -ENOTSUP;
	}

	return 0;
}

static int dump_ovs_vports(int master_ifindex, struct list_head *head, int sk)
{
	int16_t ovs_vport_genl_id;
	int ret;
	struct ovs_request rq;

	ovs_vport_genl_id = get_cached_genl_family_id(OVS_VPORT_FAMILY);
	if (ovs_vport_genl_id < 0) {
		pr_err("Unable to get %s genl_family id\n", OVS_VPORT_FAMILY);
		return -1;
	}

	memset(&rq, 0, sizeof(rq));
	rq.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr) + sizeof(struct ovs_header));
	rq.h.nlmsg_type = ovs_vport_genl_id;
	rq.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
	rq.h.nlmsg_pid = 0;
	rq.h.nlmsg_seq = CR_NLMSG_SEQ;

	rq.gh.cmd = OVS_VPORT_CMD_GET;
	rq.gh.version = OVS_VPORT_VERSION;

	rq.ovsh.dp_ifindex = master_ifindex;

	ret = do_rtnl_req(sk, &rq, rq.h.nlmsg_len, rc_dump_one_vport, NULL, NULL, head);
	if (ret < 0)
		pr_err("Error %d %s while dumping vport on datapath %d\n", ret, strerror(ret), master_ifindex);

	return 0;
}

static int rc_dump_one_dp(struct nlmsghdr *h, struct ns_id *ns, void *arg)
{
	struct nlattr *tb[OVS_DP_ATTR_MAX + 1];
	struct list_head *dp_head = arg;
	struct ovs_datapath *item = NULL;

	item = xzalloc(sizeof(struct ovs_datapath));
	if (!item)
		return -ENOMEM;

	ovs_datapath_link_entry__init(&item->dp_entry);
	list_add(&item->list, dp_head);
	INIT_LIST_HEAD(&item->vports_head);

	nlmsg_parse(h, sizeof(struct genlmsghdr) + sizeof(struct ovs_header), tb, OVS_DP_ATTR_MAX, NULL);

	BUG_ON(!tb[OVS_DP_ATTR_USER_FEATURES]);
	item->dp_entry.features = nla_get_u32(tb[OVS_DP_ATTR_USER_FEATURES]);

	BUG_ON(!tb[OVS_DP_ATTR_NAME]);
	strncpy(item->name, nla_data(tb[OVS_DP_ATTR_NAME]), IFNAMSIZ - 1);
	item->dp_entry.name = (void *)item->name;

	if (tb[OVS_DP_ATTR_UPCALL_PID])
		item->dp_entry.upcall_pid = nla_get_u32(tb[OVS_DP_ATTR_UPCALL_PID]);
	else
		item->dp_entry.upcall_pid = 0;

	item->ifindex = ((struct ovs_request *)h)->ovsh.dp_ifindex;

	return 0;
}

static int dump_all_dp(void)
{
	int16_t ovs_dp_genl_id;
	int ret, sk;
	struct ovs_request rq;
	struct ovs_datapath *dp;

	ovs_dp_genl_id = get_cached_genl_family_id(OVS_DATAPATH_FAMILY);
	if (ovs_dp_genl_id < 0) {
		pr_err("Unable to get %s genl_family id\n", OVS_DATAPATH_FAMILY);
		return -1;
	}

	sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sk < 0) {
		pr_perror("Can't open netlink socket for dump");
		return -1;
	}

	memset(&rq, 0, sizeof(rq));
	rq.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr) + sizeof(struct ovs_header));
	rq.h.nlmsg_type = ovs_dp_genl_id;
	rq.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
	rq.h.nlmsg_pid = 0;
	rq.h.nlmsg_seq = CR_NLMSG_SEQ;

	rq.gh.cmd = OVS_DP_CMD_GET;
	rq.gh.version = OVS_DATAPATH_VERSION;

	ret = do_rtnl_req(sk, &rq, rq.h.nlmsg_len, rc_dump_one_dp, NULL, NULL, &ovs_dp_head);
	if (ret < 0) {
		pr_err("Error while dumping datapaths %d %s\n", ret, strerror(ret));
		goto out;
	}

	list_for_each_entry(dp, &ovs_dp_head, list) {
		ret = dump_ovs_vports(dp->ifindex, &dp->vports_head, sk);
		if (ret)
			goto out;
	}

out:
	close(sk);
	return ret;
}

static int fill_ovs_layout(void)
{
	if (!list_empty(&ovs_dp_head)) {
		pr_err("Openvswitch layout map already exists!\n");
		return -1;
	}

	return dump_all_dp();
}

static void free_ovs_layout(void)
{
	struct ovs_datapath *dp, *dp_next;
	struct ovs_vport *vp, *vp_next;

	list_for_each_entry_safe(dp, dp_next, &ovs_dp_head, list) {
		list_for_each_entry_safe(vp, vp_next, &dp->vports_head, list) {
			list_del(&vp->list);
			free(vp);
		}

		list_del(&dp->list);
		free(dp);
	}
}

static struct ovs_datapath *find_ovs_datapath(int ifindex)
{
	struct ovs_datapath *dp;

	list_for_each_entry(dp, &ovs_dp_head, list)
		if (dp->ifindex == ifindex)
			return dp;

	return NULL;
}

static struct ovs_vport *find_ovs_vport(int ifindex)
{
	struct ovs_datapath *dp;
	struct ovs_vport *vp;

	list_for_each_entry(dp, &ovs_dp_head, list)
		list_for_each_entry(vp, &dp->vports_head, list)
			if (vp->ifindex == ifindex)
				return vp;

	return NULL;
}

int write_netdev_img(NetDeviceEntry *nde, struct cr_imgset *fds, struct nlattr **info)
{
	return pb_write_one(img_from_set(fds, CR_FD_NETDEV), nde, PB_NETDEV);
}

static int lookup_net_by_netid(struct ns_id *ns, int net_id)
{
	struct netns_id *p;

	list_for_each_entry(p, &ns->net.ids, node)
		if (p->netnsid_value == net_id)
			return p->target_ns_id;

	return -1;
}

static int dump_one_netdev(int type, struct ifinfomsg *ifi, struct nlattr **tb, struct ns_id *ns, struct cr_imgset *fds,
			   int (*dump)(NetDeviceEntry *, struct cr_imgset *, struct nlattr **info))
{
	int ret = -1, i, peer_ifindex;
	NetDeviceEntry netdev = NET_DEVICE_ENTRY__INIT;
	SysctlEntry *confs4 = NULL;
	int size4 = ARRAY_SIZE(devconfs4);
	SysctlEntry *confs6 = NULL;
	int size6 = ARRAY_SIZE(devconfs6);
	char stable_secret[MAX_STR_CONF_LEN + 1] = {};
	struct nlattr *info[IFLA_INFO_MAX + 1], **arg = NULL;

	if (!tb[IFLA_IFNAME]) {
		pr_err("No name for link %d\n", ifi->ifi_index);
		return -1;
	}

	netdev.type = type;
	netdev.ifindex = ifi->ifi_index;
	netdev.mtu = *(int *)RTA_DATA(tb[IFLA_MTU]);
	netdev.flags = ifi->ifi_flags;
	netdev.name = RTA_DATA(tb[IFLA_IFNAME]);

	if (kdat.has_nsid) {
		s32 nsid = -1;

		peer_ifindex = ifi->ifi_index;
		if (tb[IFLA_LINK])
			peer_ifindex = nla_get_u32(tb[IFLA_LINK]);

		netdev.has_peer_ifindex = true;
		netdev.peer_ifindex = peer_ifindex;

		if (tb[IFLA_LINK_NETNSID])
			nsid = nla_get_s32(tb[IFLA_LINK_NETNSID]);

		pr_debug("The peer link is in the %d netns with the %u index\n", nsid, netdev.peer_ifindex);

		if (nsid == -1)
			nsid = ns->id;
		else
			nsid = lookup_net_by_netid(ns, nsid);
		if (nsid < 0) {
			pr_warn("The %s veth is in an external netns\n", netdev.name);
		} else {
			netdev.has_peer_nsid = true;
			netdev.peer_nsid = nsid;
		}
	}
	/*
	 * If kdat.has_nsid is false, a multiple network namespaces are not dumped,
	 * so if we are here, this means only one netns is dumped.
	 */

	if (tb[IFLA_ADDRESS] && (type != ND_TYPE__LOOPBACK)) {
		netdev.has_address = true;
		netdev.address.data = nla_data(tb[IFLA_ADDRESS]);
		netdev.address.len = nla_len(tb[IFLA_ADDRESS]);
		pr_info("Found ll addr (%02x:../%d) for %s\n", (int)netdev.address.data[0], (int)netdev.address.len,
			netdev.name);
	}

	if (tb[IFLA_MASTER]) {
		struct ovs_vport *vp;

		netdev.has_master = true;
		netdev.master = nla_get_u32(tb[IFLA_MASTER]);

		if (find_ovs_datapath(netdev.master)) {
			vp = find_ovs_vport(netdev.ifindex);
			if (!vp) {
				pr_err("Master link is ovs datapath, but no vport exists for given ifindex\n");
				return -ENOENT;
			}

			netdev.vz_ovs_vport = &vp->vport_entry;
		}
	}

	netdev.n_conf4 = size4;
	netdev.conf4 = xmalloc(sizeof(SysctlEntry *) * size4);
	if (!netdev.conf4)
		goto err_free;

	confs4 = xmalloc(sizeof(SysctlEntry) * size4);
	if (!confs4)
		goto err_free;

	for (i = 0; i < size4; i++) {
		sysctl_entry__init(&confs4[i]);
		netdev.conf4[i] = &confs4[i];
		netdev.conf4[i]->type = CTL_32;
	}

	netdev.n_conf6 = size6;
	netdev.conf6 = xmalloc(sizeof(SysctlEntry *) * size6);
	if (!netdev.conf6)
		goto err_free;

	confs6 = xmalloc(sizeof(SysctlEntry) * size6);
	if (!confs6)
		goto err_free;

	for (i = 0; i < size6; i++) {
		sysctl_entry__init(&confs6[i]);
		netdev.conf6[i] = &confs6[i];
		if (strcmp(devconfs6[i], "stable_secret")) {
			netdev.conf6[i]->type = SYSCTL_TYPE__CTL_32;
		} else {
			netdev.conf6[i]->type = SYSCTL_TYPE__CTL_STR;
			netdev.conf6[i]->sarg = stable_secret;
		}
	}

	ret = ipv4_conf_op(netdev.name, netdev.conf4, size4, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;

	ret = ipv6_conf_op(netdev.name, netdev.conf6, size6, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;

	if (!dump)
		dump = write_netdev_img;

	if (tb[IFLA_LINKINFO]) {
		ret = nla_parse_nested(info, IFLA_INFO_MAX, tb[IFLA_LINKINFO], NULL);
		if (ret < 0) {
			pr_err("failed to parse nested linkinfo\n");
			return -1;
		}
		arg = info;
	}

	ret = dump(&netdev, fds, arg);
err_free:
	xfree(netdev.conf4);
	xfree(confs4);
	xfree(netdev.conf6);
	xfree(confs6);
	return ret;
}

static char *link_kind(struct ifinfomsg *ifi, struct nlattr **tb)
{
	struct nlattr *linkinfo[IFLA_INFO_MAX + 1];

	if (!tb[IFLA_LINKINFO]) {
		pr_err("No linkinfo for eth link %d\n", ifi->ifi_index);
		return NULL;
	}

	nla_parse_nested(linkinfo, IFLA_INFO_MAX, tb[IFLA_LINKINFO], NULL);
	if (!linkinfo[IFLA_INFO_KIND]) {
		pr_err("No kind for eth link %d\n", ifi->ifi_index);
		return NULL;
	}

	return nla_data(linkinfo[IFLA_INFO_KIND]);
}

static int dump_unknown_device(struct ifinfomsg *ifi, char *kind, struct nlattr **tb, struct ns_id *ns,
			       struct cr_imgset *fds)
{
	int ret;

	ret = run_plugins(DUMP_EXT_LINK, ifi->ifi_index, ifi->ifi_type, kind);
	if (ret == 0)
		return dump_one_netdev(ND_TYPE__EXTLINK, ifi, tb, ns, fds, NULL);

	if (ret == -ENOTSUP)
		pr_err("Unsupported link %d (type %d kind %s)\n", ifi->ifi_index, ifi->ifi_type, kind);
	return -1;
}

static int dump_bridge(NetDeviceEntry *nde, struct cr_imgset *imgset, struct nlattr **info)
{
	return write_netdev_img(nde, imgset, info);
}

static int dump_macvlan(NetDeviceEntry *nde, struct cr_imgset *imgset, struct nlattr **info)
{
	MacvlanLinkEntry macvlan = MACVLAN_LINK_ENTRY__INIT;
	int ret;
	struct nlattr *data[IFLA_MACVLAN_FLAGS + 1];

	if (!info || !info[IFLA_INFO_DATA]) {
		pr_err("no data for macvlan\n");
		return -1;
	}

	ret = nla_parse_nested(data, IFLA_MACVLAN_FLAGS, info[IFLA_INFO_DATA], NULL);
	if (ret < 0) {
		pr_err("failed to parse macvlan data\n");
		return -1;
	}

	if (!data[IFLA_MACVLAN_MODE]) {
		pr_err("macvlan mode required for %s\n", nde->name);
		return -1;
	}

	macvlan.mode = *((u32 *)RTA_DATA(data[IFLA_MACVLAN_MODE]));

	if (data[IFLA_MACVLAN_FLAGS])
		macvlan.flags = *((u16 *)RTA_DATA(data[IFLA_MACVLAN_FLAGS]));

	nde->macvlan = &macvlan;
	return write_netdev_img(nde, imgset, info);
}

static int dump_vxlan(NetDeviceEntry *nde, struct cr_imgset *imgset, struct nlattr **info)
{
	VxlanLinkEntry vxlan = VXLAN_LINK_ENTRY__INIT;
	int ret;
	struct nlattr *data[IFLA_VXLAN_MAX + 1];

	if (!info || !info[IFLA_INFO_DATA]) {
		pr_err("no data for vxlan\n");
		return -1;
	}

	ret = nla_parse_nested(data, IFLA_VXLAN_MAX, info[IFLA_INFO_DATA], NULL);
	if (ret < 0) {
		pr_err("failed to parse vxlan data\n");
		return -1;
	}

#define ENCODE_ENTRY(__type, __ifla, __proto)                              \
	do {                                                               \
		if (data[__ifla]) {                                        \
			vxlan.__proto = *(__type *)nla_data(data[__ifla]); \
			vxlan.has_##__proto = true;                        \
		}                                                          \
	} while (0)

	BUG_ON(!data[IFLA_VXLAN_ID]);
	vxlan.id = *((u32 *)RTA_DATA(data[IFLA_VXLAN_ID]));

	if (data[IFLA_VXLAN_GROUP]) {
		BUG_ON(nla_len(data[IFLA_VXLAN_GROUP]) != 4);
		vxlan.n_group = 1;
		vxlan.group = nla_data(data[IFLA_VXLAN_GROUP]);
	}

	if (data[IFLA_VXLAN_GROUP6]) {
		BUG_ON(nla_len(data[IFLA_VXLAN_GROUP6]) != 16);
		vxlan.n_group6 = 4;
		vxlan.group6 = nla_data(data[IFLA_VXLAN_GROUP6]);
	}

	ENCODE_ENTRY(u32, IFLA_VXLAN_LINK, link);

	if (data[IFLA_VXLAN_LOCAL]) {
		BUG_ON(nla_len(data[IFLA_VXLAN_LOCAL]) != 4);
		vxlan.n_local = 1;
		vxlan.local = nla_data(data[IFLA_VXLAN_LOCAL]);
	}

	if (data[IFLA_VXLAN_LOCAL6]) {
		BUG_ON(nla_len(data[IFLA_VXLAN_LOCAL6]) != 16);
		vxlan.n_local6 = 4;
		vxlan.local6 = nla_data(data[IFLA_VXLAN_LOCAL6]);
	}

	ENCODE_ENTRY(u8, IFLA_VXLAN_TOS, tos);
	ENCODE_ENTRY(u8, IFLA_VXLAN_TTL, ttl);
	ENCODE_ENTRY(u32, IFLA_VXLAN_LABEL, label);
	ENCODE_ENTRY(u8, IFLA_VXLAN_LEARNING, learning);
	ENCODE_ENTRY(u32, IFLA_VXLAN_AGEING, ageing);
	ENCODE_ENTRY(u32, IFLA_VXLAN_LIMIT, limit);

	if (data[IFLA_VXLAN_PORT_RANGE]) {
		vxlan.port_range.data = nla_data(data[IFLA_VXLAN_PORT_RANGE]);
		vxlan.port_range.len = nla_len(data[IFLA_VXLAN_PORT_RANGE]);
	}

	ENCODE_ENTRY(u8, IFLA_VXLAN_PROXY, proxy);
	ENCODE_ENTRY(u8, IFLA_VXLAN_RSC, rsc);
	ENCODE_ENTRY(u8, IFLA_VXLAN_L2MISS, l2miss);
	ENCODE_ENTRY(u8, IFLA_VXLAN_L3MISS, l3miss);
	ENCODE_ENTRY(u8, IFLA_VXLAN_COLLECT_METADATA, collect_metadata);
	ENCODE_ENTRY(u16, IFLA_VXLAN_PORT, port);
	ENCODE_ENTRY(u8, IFLA_VXLAN_UDP_CSUM, udp_csum);
	ENCODE_ENTRY(u8, IFLA_VXLAN_UDP_ZERO_CSUM6_TX, udp_zero_csum6_tx);
	ENCODE_ENTRY(u8, IFLA_VXLAN_UDP_ZERO_CSUM6_RX, udp_zero_csum6_rx);
	ENCODE_ENTRY(u8, IFLA_VXLAN_REMCSUM_TX, remcsum_tx);
	ENCODE_ENTRY(u8, IFLA_VXLAN_REMCSUM_RX, remcsum_rx);

	ENCODE_ENTRY(u8, IFLA_VXLAN_DF, df);

#undef ENCODE_ENTRY

#define ENCODE_ENTRY_FLAG(__ifla, __proto)          \
	do {                                        \
		if (data[__ifla]) {                 \
			vxlan.__proto = true;       \
			vxlan.has_##__proto = true; \
		}                                   \
	} while (0)

	ENCODE_ENTRY_FLAG(IFLA_VXLAN_GBP, gbp);
	ENCODE_ENTRY_FLAG(IFLA_VXLAN_GPE, gpe);
	ENCODE_ENTRY_FLAG(IFLA_VXLAN_REMCSUM_NOPARTIAL, remcsum_nopartial);
	ENCODE_ENTRY_FLAG(IFLA_VXLAN_TTL_INHERIT, ttl_inherit);
#undef ENCODE_ENTRY_FLAG

	nde->vz_vxlan = &vxlan;
	return write_netdev_img(nde, imgset, info);
}

static int dump_one_ovs(NetDeviceEntry *nde, struct cr_imgset *imgset, struct nlattr **info)
{
	struct ovs_datapath *dp;
	struct ovs_vport *vp;
	int ifindex = nde->ifindex;

	/*
	 * Netdev can be either datapath or internal vport
	 */

	dp = find_ovs_datapath(ifindex);
	vp = find_ovs_vport(ifindex);

	if (dp) {
		nde->type = ND_TYPE__VZ_OVS_DATAPATH;
		nde->vz_ovs_dp = &dp->dp_entry;

		/* datapath upcall pid exposed via its vport */
		if (!vp) {
			pr_err("No vport for datapath %s\n", dp->name);
			goto err;
		}

		dp->dp_entry.upcall_pid = vp->vport_entry.upcall_pid;

		goto success;
	}

	if (vp) {
		nde->type = ND_TYPE__VZ_OVS_INTERNAL_VPORT;
		nde->vz_ovs_vport = &vp->vport_entry;
		goto success;
	}

err:
	pr_err("Openvswitch link %d cannot be dumped\n", ifindex);
	return -ENOENT;

success:
	return write_netdev_img(nde, imgset, NULL);
}

static int dump_one_ethernet(struct ifinfomsg *ifi, char *kind, struct nlattr **tb, struct ns_id *ns,
			     struct cr_imgset *fds)
{
	if (!strcmp(kind, "veth"))
		/*
		 * This is not correct. The peer of the veth device may
		 * be either outside or inside the netns we're working
		 * on, but there's currently no way of finding this out.
		 *
		 * Sigh... we have to assume, that the veth device is a
		 * connection to the outer world and just dump this end :(
		 */
		return dump_one_netdev(ND_TYPE__VETH, ifi, tb, ns, fds, NULL);
	if (!strcmp(kind, "tun"))
		return dump_one_netdev(ND_TYPE__TUN, ifi, tb, ns, fds, dump_tun_link);
	if (!strcmp(kind, "bridge"))
		return dump_one_netdev(ND_TYPE__BRIDGE, ifi, tb, ns, fds, dump_bridge);
	if (!strcmp(kind, "gretap")) {
		char *name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

		if (!name) {
			pr_err("gretap %d has no name\n", ifi->ifi_index);
			return -1;
		}

		if (!strcmp(name, "gretap0")) {
			pr_info("found %s, ignoring\n", name);
			return 0;
		}

		pr_warn("GRE tap device %s not supported natively\n", name);
	}
	if (!strcmp(kind, "macvlan"))
		return dump_one_netdev(ND_TYPE__MACVLAN, ifi, tb, ns, fds, dump_macvlan);
	if (!strcmp(kind, "vxlan"))
		return dump_one_netdev(ND_TYPE__VZ_VXLAN, ifi, tb, ns, fds, dump_vxlan);
	if (!strcmp(kind, "openvswitch"))
		return dump_one_netdev(ND_TYPE__VZ_OVS_DATAPATH, ifi, tb, ns, fds, dump_one_ovs);

	return dump_unknown_device(ifi, kind, tb, ns, fds);
}

static int dump_one_gendev(struct ifinfomsg *ifi, char *kind, struct nlattr **tb, struct ns_id *ns,
			   struct cr_imgset *fds)
{
	if (!strcmp(kind, "tun"))
		return dump_one_netdev(ND_TYPE__TUN, ifi, tb, ns, fds, dump_tun_link);

	return dump_unknown_device(ifi, kind, tb, ns, fds);
}

static int dump_one_voiddev(struct ifinfomsg *ifi, char *kind, struct nlattr **tb, struct ns_id *ns,
			    struct cr_imgset *fds)
{
	if (!strcmp(kind, "venet"))
		return dump_one_netdev(ND_TYPE__VENET, ifi, tb, ns, fds, NULL);

	return dump_unknown_device(ifi, kind, tb, ns, fds);
}

static int dump_one_gre(struct ifinfomsg *ifi, char *kind, struct nlattr **tb, struct ns_id *ns, struct cr_imgset *fds)
{
	if (!strcmp(kind, "gre")) {
		char *name = (char *)RTA_DATA(tb[IFLA_IFNAME]);
		if (!name) {
			pr_err("gre device %d has no name\n", ifi->ifi_index);
			return -1;
		}

		if (!strcmp(name, "gre0")) {
			pr_info("found %s, ignoring\n", name);
			return 0;
		}

		pr_warn("GRE tunnel device %s not supported natively\n", name);
	}

	return dump_unknown_device(ifi, kind, tb, ns, fds);
}

static int dump_sit(NetDeviceEntry *nde, struct cr_imgset *imgset, struct nlattr **info)
{
	int ret;
	struct nlattr *data[__IFLA_IPTUN_MAX];
	SitEntry se = SIT_ENTRY__INIT;
	/* There are for IP(v6) addresses kernel feeds to us */
	uint32_t a_local, a_remote, rd_prefix[4], rl_prefix;

	if (!info || !info[IFLA_INFO_DATA]) {
		pr_err("no data for sit\n");
		return -1;
	}

	pr_info("Some data for SIT provided\n");
	ret = nla_parse_nested(data, IFLA_IPTUN_MAX, info[IFLA_INFO_DATA], NULL);
	if (ret < 0) {
		pr_err("failed to parse sit data\n");
		return -1;
	}

#define ENCODE_ENTRY(__type, __ifla, __proto)                           \
	do {                                                            \
		if (data[__ifla]) {                                     \
			se.__proto = *(__type *)nla_data(data[__ifla]); \
			se.has_##__proto = true;                        \
		}                                                       \
	} while (0)

	if (data[IFLA_IPTUN_LOCAL]) {
		a_local = *(u32 *)nla_data(data[IFLA_IPTUN_LOCAL]);
		if (a_local != 0) {
			se.n_local = 1;
			se.local = &a_local;
		}
	}

	if (data[IFLA_IPTUN_REMOTE]) {
		a_remote = *(u32 *)nla_data(data[IFLA_IPTUN_REMOTE]);
		if (a_remote != 0) {
			se.n_remote = 1;
			se.remote = &a_remote;
		}
	}

	ENCODE_ENTRY(u32, IFLA_IPTUN_LINK, link);
	ENCODE_ENTRY(u8, IFLA_IPTUN_TTL, ttl);
	ENCODE_ENTRY(u8, IFLA_IPTUN_TOS, tos);
	ENCODE_ENTRY(u16, IFLA_IPTUN_FLAGS, flags);
	ENCODE_ENTRY(u8, IFLA_IPTUN_PROTO, proto);

	if (data[IFLA_IPTUN_PMTUDISC]) {
		u8 v;

		v = *(u8 *)nla_data(data[IFLA_IPTUN_PMTUDISC]);
		if (v)
			se.pmtudisc = se.has_pmtudisc = true;
	}

	ENCODE_ENTRY(u16, IFLA_IPTUN_ENCAP_TYPE, encap_type);
	ENCODE_ENTRY(u16, IFLA_IPTUN_ENCAP_FLAGS, encap_flags);
	ENCODE_ENTRY(u16, IFLA_IPTUN_ENCAP_SPORT, encap_sport);
	ENCODE_ENTRY(u16, IFLA_IPTUN_ENCAP_DPORT, encap_dport);

	if (data[IFLA_IPTUN_6RD_PREFIXLEN]) {
		se.rd_prefixlen = *(u16 *)nla_data(data[IFLA_IPTUN_6RD_PREFIXLEN]);
		if (!se.rd_prefixlen)
			goto skip;

		if (!data[IFLA_IPTUN_6RD_PREFIX]) {
			pr_err("No 6rd prefix for sit device\n");
			return -1;
		}

		se.has_rd_prefixlen = true;
		memcpy(&rd_prefix, nla_data(data[IFLA_IPTUN_6RD_PREFIX]), sizeof(rd_prefix));
		se.n_rd_prefix = 4;
		se.rd_prefix = rd_prefix;

		se.relay_prefixlen = *(u16 *)nla_data(data[IFLA_IPTUN_6RD_RELAY_PREFIXLEN]);
		if (!se.relay_prefixlen)
			goto skip;

		if (!data[IFLA_IPTUN_6RD_RELAY_PREFIX]) {
			pr_err("No 6rd relay prefix for sit device\n");
			return -1;
		}

		se.has_relay_prefixlen = true;
		memcpy(&rl_prefix, nla_data(data[IFLA_IPTUN_6RD_RELAY_PREFIX]), sizeof(rl_prefix));
		se.n_relay_prefix = 1;
		se.relay_prefix = &rl_prefix;
	skip:;
	}

#undef ENCODE_ENTRY

	nde->sit = &se;
	return write_netdev_img(nde, imgset, info);
}

static int dump_one_sit(struct ifinfomsg *ifi, char *kind, struct nlattr **tb, struct ns_id *ns, struct cr_imgset *fds)
{
	char *name;

	if (strcmp(kind, "sit")) {
		pr_err("SIT device with %s kind\n", kind);
		return -1;
	}

	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);
	if (!name) {
		pr_err("sit device %d has no name\n", ifi->ifi_index);
		return -1;
	}

	if (!strcmp(name, "sit0")) {
		pr_info("found %s, ignoring\n", name);
		return 0;
	}

	return dump_one_netdev(ND_TYPE__SIT, ifi, tb, ns, fds, dump_sit);
}

static int list_one_link(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	return 0;
}

static int dump_one_link(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	struct cr_imgset *fds = arg;
	struct ifinfomsg *ifi;
	int ret = 0, len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	struct nlattr *tb[IFLA_MAX + 1];
	char *kind;

	ifi = NLMSG_DATA(hdr);

	if (len < 0) {
		pr_err("No iflas for link %d\n", ifi->ifi_index);
		return -1;
	}

	nlmsg_parse(hdr, sizeof(struct ifinfomsg), tb, IFLA_MAX, NULL);
	pr_info("\tLD: Got link %d, type %d\n", ifi->ifi_index, ifi->ifi_type);

	if (ifi->ifi_type == ARPHRD_LOOPBACK)
		return dump_one_netdev(ND_TYPE__LOOPBACK, ifi, tb, ns, fds, NULL);

	kind = link_kind(ifi, tb);
	if (!kind)
		goto unk;

	switch (ifi->ifi_type) {
	case ARPHRD_ETHER:
		ret = dump_one_ethernet(ifi, kind, tb, ns, fds);
		break;
	case ARPHRD_NONE:
		ret = dump_one_gendev(ifi, kind, tb, ns, fds);
		break;
	case ARPHRD_VOID:
		ret = dump_one_voiddev(ifi, kind, tb, ns, fds);
		break;
	case ARPHRD_IPGRE:
		ret = dump_one_gre(ifi, kind, tb, ns, fds);
		break;
	case ARPHRD_SIT:
		ret = dump_one_sit(ifi, kind, tb, ns, fds);
		break;
	default:
	unk:
		ret = dump_unknown_device(ifi, kind, tb, ns, fds);
		break;
	}

	return ret;
}

static int dump_one_nf(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	struct cr_img *img = arg;

	if (lazy_image(img) && open_image_lazy(img))
		return -1;

	if (write_img_buf(img, hdr, hdr->nlmsg_len))
		return -1;

	return 0;
}

static int ct_restore_callback(struct nlmsghdr *nlh)
{
	struct nfgenmsg *msg;
	struct nlattr *tb[CTA_MAX + 1], *tbp[CTA_PROTOINFO_MAX + 1], *tb_tcp[CTA_PROTOINFO_TCP_MAX + 1];
	int err;

	msg = NLMSG_DATA(nlh);

	if (msg->nfgen_family != AF_INET && msg->nfgen_family != AF_INET6)
		return 0;

	err = nlmsg_parse(nlh, sizeof(struct nfgenmsg), tb, CTA_MAX, NULL);
	if (err < 0)
		return -1;

	if (!tb[CTA_PROTOINFO])
		return 0;

	err = nla_parse_nested(tbp, CTA_PROTOINFO_MAX, tb[CTA_PROTOINFO], NULL);
	if (err < 0)
		return -1;

	if (!tbp[CTA_PROTOINFO_TCP])
		return 0;

	err = nla_parse_nested(tb_tcp, CTA_PROTOINFO_TCP_MAX, tbp[CTA_PROTOINFO_TCP], NULL);
	if (err < 0)
		return -1;

	if (tb_tcp[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL]) {
		struct nf_ct_tcp_flags *flags;

		flags = nla_data(tb_tcp[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL]);
		flags->flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
		flags->mask |= IP_CT_TCP_FLAG_BE_LIBERAL;
	}

	if (tb_tcp[CTA_PROTOINFO_TCP_FLAGS_REPLY]) {
		struct nf_ct_tcp_flags *flags;

		flags = nla_data(tb_tcp[CTA_PROTOINFO_TCP_FLAGS_REPLY]);
		flags->flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
		flags->mask |= IP_CT_TCP_FLAG_BE_LIBERAL;
	}

	return 0;
}

static int restore_nf_ct(int pid, int type)
{
	struct nlmsghdr *nlh = NULL;
	int exit_code = -1, sk;
	struct cr_img *img;

	img = open_image(type, O_RSTR, pid);
	if (img == NULL)
		return -1;
	if (empty_image(img)) {
		close_image(img);
		return 0;
	}

	sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (sk < 0) {
		pr_perror("Can't open rtnl sock for net dump");
		goto out_img;
	}

	nlh = xmalloc(sizeof(struct nlmsghdr));
	if (nlh == NULL)
		goto out;

	while (1) {
		struct nlmsghdr *p;
		int ret;

		ret = read_img_buf_eof(img, nlh, sizeof(struct nlmsghdr));
		if (ret < 0)
			goto out;
		if (ret == 0)
			break;

		p = xrealloc(nlh, nlh->nlmsg_len);
		if (p == NULL)
			goto out;
		nlh = p;

		ret = read_img_buf_eof(img, nlh + 1, nlh->nlmsg_len - sizeof(struct nlmsghdr));
		if (ret < 0)
			goto out;
		if (ret == 0) {
			pr_err("The image file was truncated\n");
			goto out;
		}

		if (type == CR_FD_NETNF_CT)
			if (ct_restore_callback(nlh))
				goto out;

		nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
		ret = do_rtnl_req(sk, nlh, nlh->nlmsg_len, NULL, NULL, NULL, NULL);
		if (ret)
			goto out;
	}

	exit_code = 0;
out:
	xfree(nlh);
	close(sk);
out_img:
	close_image(img);
	return exit_code;
}

static int dump_nf_ct(struct cr_imgset *fds, int type)
{
	struct cr_img *img;
	struct {
		struct nlmsghdr nlh;
		struct nfgenmsg g;
	} req;
	int sk, ret;

	pr_info("Dumping netns links\n");

	ret = sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (sk < 0) {
		pr_perror("Can't open rtnl sock for net dump");
		goto out;
	}

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8);

	if (type == CR_FD_NETNF_CT)
		req.nlh.nlmsg_type |= IPCTNL_MSG_CT_GET;
	else if (type == CR_FD_NETNF_EXP)
		req.nlh.nlmsg_type |= IPCTNL_MSG_EXP_GET;
	else
		BUG();

	req.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	req.g.nfgen_family = AF_UNSPEC;

	img = img_from_set(fds, type);

	ret = do_rtnl_req(sk, &req, sizeof(req), dump_one_nf, NULL, NULL, img);
	close(sk);
out:
	return ret;
}

/*
 * When we request information about a link, the kernel shows
 * information about the pair device (netns id and idx).
 * If a pair device lives in another namespace and this namespace
 * doesn't have a netns ID in the current namespace, the kernel
 * will generate it. So we need to list all links, before dumping
 * netns indexes.
 */
static int list_links(int rtsk, void *args)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	pr_info("Dumping netns links\n");

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	req.g.rtgen_family = AF_PACKET;

	return do_rtnl_req(rtsk, &req, sizeof(req), list_one_link, NULL, NULL, args);
}

static int dump_links(int rtsk, struct ns_id *ns, struct cr_imgset *fds)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	pr_info("Dumping netns links\n");

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	req.g.rtgen_family = AF_PACKET;

	return do_rtnl_req(rtsk, &req, sizeof(req), dump_one_link, NULL, ns, fds);
}

static int restore_link_cb(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	pr_info("Got response on SETLINK.\n");
	return 0;
}

static int restore_newlink_cb(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	pr_info("Got response on RTM_NEWLINK.\n");
	return 0;
}

struct newlink_req {
	struct nlmsghdr h;
	struct ifinfomsg i;
	char buf[1024];
};

/* Optional extra things to be provided at the top level of the NEWLINK
 * request.
 */
struct newlink_extras {
	int link;	  /* IFLA_LINK */
	int target_netns; /* IFLA_NET_NS_FD */
};

typedef int (*link_info_t)(struct ns_id *ns, struct net_link *, struct newlink_req *);

static int populate_newlink_req(struct ns_id *ns, struct newlink_req *req, int msg_type, struct net_link *link,
				link_info_t link_info, struct newlink_extras *extras)
{
	NetDeviceEntry *nde = link->nde;

	memset(req, 0, sizeof(*req));

	req->h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req->h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
	req->h.nlmsg_type = msg_type;
	req->h.nlmsg_seq = CR_NLMSG_SEQ;
	req->i.ifi_family = AF_PACKET;
	/*
	 * SETLINK is called for external devices which may
	 * have ifindex changed. Thus configure them by their
	 * name only.
	 */
	if (msg_type == RTM_NEWLINK)
		req->i.ifi_index = nde->ifindex;
	req->i.ifi_flags = nde->flags;

	if (extras) {
		if (extras->link >= 0)
			addattr_l(&req->h, sizeof(*req), IFLA_LINK, &extras->link, sizeof(extras->link));

		if (extras->target_netns >= 0)
			addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &extras->target_netns,
				  sizeof(extras->target_netns));
	}

	addattr_l(&req->h, sizeof(*req), IFLA_IFNAME, nde->name, strlen(nde->name));
	addattr_l(&req->h, sizeof(*req), IFLA_MTU, &nde->mtu, sizeof(nde->mtu));

	if (nde->has_address) {
		pr_debug("Restore ll addr (%02x:../%d) for device\n", (int)nde->address.data[0], (int)nde->address.len);
		addattr_l(&req->h, sizeof(*req), IFLA_ADDRESS, nde->address.data, nde->address.len);
	}

	if (link_info) {
		struct rtattr *linkinfo;
		int ret;

		linkinfo = NLMSG_TAIL(&req->h);
		addattr_l(&req->h, sizeof(*req), IFLA_LINKINFO, NULL, 0);

		ret = link_info(ns, link, req);
		if (ret < 0)
			return ret;

		linkinfo->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)linkinfo;
	}

	return 0;
}

static int kerndat_newifindex_err_cb(int err, struct ns_id *ns, void *arg)
{
	switch (err) {
	case -ENODEV:
		kdat.has_newifindex = false;
		break;
	case -ERANGE:
		kdat.has_newifindex = true;
		break;
	default:
		pr_err("Unexpected error: %d(%s)\n", err, strerror(-err));
		break;
	}
	return 0;
}

int kerndat_has_newifindex(void)
{
	struct newlink_req req = {};
	int ifindex = -1;
	int sk, ret;

	kdat.has_newifindex = false;
	sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sk < 0) {
		pr_perror("Unable to create a netlink socket");
		return -1;
	}
	memset(&req, 0, sizeof(req));

	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
	req.h.nlmsg_type = RTM_SETLINK;
	req.h.nlmsg_seq = CR_NLMSG_SEQ;
	req.i.ifi_family = AF_UNSPEC;

	/*
	 * ifindex is negative, so the kernel will return ERANGE if
	 * IFLA_NEW_IFINDEX is supported.
	 */
	addattr_l(&req.h, sizeof(req), IFLA_NEW_IFINDEX, &ifindex, sizeof(ifindex));
	/* criu-kdat doesn't exist, so the kernel will return ENODEV. */
	addattr_l(&req.h, sizeof(req), IFLA_IFNAME, "criu-kdat", 9);

	ret = do_rtnl_req(sk, &req, sizeof(req), restore_link_cb, kerndat_newifindex_err_cb, NULL, NULL);
	close(sk);
	return ret;
}

static int do_rtm_link_req(int msg_type, struct net_link *link, int nlsk, struct ns_id *ns, link_info_t link_info,
			   struct newlink_extras *extras)
{
	struct newlink_req req;

	if (populate_newlink_req(ns, &req, msg_type, link, link_info, extras) < 0)
		return -1;

	return do_rtnl_req(nlsk, &req, req.h.nlmsg_len, restore_link_cb, NULL, NULL, NULL);
}

int restore_link_parms(struct net_link *link, int nlsk)
{
	return do_rtm_link_req(RTM_SETLINK, link, nlsk, NULL, NULL, NULL);
}

static int restore_one_link(struct ns_id *ns, struct net_link *link, int nlsk, link_info_t link_info,
			    struct newlink_extras *extras)
{
	pr_info("Restoring netdev %s idx %d\n", link->nde->name, link->nde->ifindex);
	return do_rtm_link_req(RTM_NEWLINK, link, nlsk, ns, link_info, extras);
}

struct move_req {
	struct newlink_req req;
	char ifnam[IFNAMSIZ];
};

static int move_veth_cb(void *arg, int fd, pid_t pid)
{
	int fd_ns_old = -1, ret = -1;
	struct move_req *mvreq = arg;
	struct newlink_req *req = &mvreq->req;
	int ifindex, nlsk;
	int ns_fd;

	/*
	 * Note: NS_FD_OFF is set in netns_keep_nsfd to remember 'host' netns,
	 * and it happens after start_usernsd, so the sfd remains unset in
	 * scope of usernsd, but usernsd has 'host' netns anyway so we should
	 * not have a need to switch to it.
	 */
	ns_fd = get_service_fd(NS_FD_OFF);
	if (ns_fd >= 0) {
		if (switch_ns_by_fd(ns_fd, &net_ns_desc, &fd_ns_old))
			return -1;
	}

	/* Retrieve ifindex of precreated veth device in source netns. */
	ifindex = if_nametoindex(mvreq->ifnam);
	if (!ifindex)
		goto out;
	req->i.ifi_index = ifindex;

	/* Tell netlink what netns we want to move that veth device into. */
	addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &fd, sizeof(fd));

	nlsk = socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (nlsk < 0)
		goto out;

	ret = do_rtnl_req(nlsk, req, req->h.nlmsg_len, restore_newlink_cb, NULL, NULL, NULL);
	close(nlsk);

out:
	if (fd_ns_old >= 0)
		ret = restore_ns(fd_ns_old, &net_ns_desc);

	return ret;
}

static int move_veth(const char *netdev, struct ns_id *ns, struct net_link *link, int nlsk)
{
	NetDeviceEntry *nde = link->nde;
	struct newlink_req *req;
	struct move_req mvreq;
	size_t len_val;
	int ret;

	if (!kdat.has_newifindex) {
		pr_err("Unable to specify ifindex in the target namespace.\n");
		return -1;
	}

	/*
	 * We require a target ifindex otherwise we can't restore addresses
	 * later on as ip stores ifindex in its address dump for network
	 * devices.
	 */
	if (!nde->ifindex)
		return -1;

	memset(&mvreq.req, 0, sizeof(mvreq.req));
	req = &mvreq.req;

	req->h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req->h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req->h.nlmsg_type = RTM_NEWLINK;
	req->h.nlmsg_seq = CR_NLMSG_SEQ;

	req->i.ifi_family = AF_UNSPEC;
	req->i.ifi_flags = nde->flags;

	/* Tell netlink what name we want in the target netns. */
	addattr_l(&req->h, sizeof(*req), IFLA_IFNAME, nde->name, strlen(nde->name));

	/* Tell netlink what mtu we want in the target netns. */
	addattr_l(&req->h, sizeof(*req), IFLA_MTU, &nde->mtu, sizeof(nde->mtu));

	/* Tell netlink what ifindex we want in the target netns. */
	addattr_l(&req->h, sizeof(*req), IFLA_NEW_IFINDEX, &nde->ifindex, sizeof(nde->ifindex));

	if (nde->has_address) {
		pr_debug("Restore ll addr (%02x:../%d) for device with target ifindex %d\n", (int)nde->address.data[0],
			 (int)nde->address.len, nde->ifindex);
		addattr_l(&req->h, sizeof(*req), IFLA_ADDRESS, nde->address.data, nde->address.len);
	}

	len_val = strlen(netdev);
	if (len_val >= IFNAMSIZ)
		return -1;
	__strlcpy(mvreq.ifnam, netdev, IFNAMSIZ);

	ret = userns_call(move_veth_cb, 0, &mvreq, sizeof(mvreq), ns->ns_fd);
	if (ret < 0)
		return -1;

	link->created = true;
	return 0;
}

#ifndef VETH_INFO_MAX
enum {
	VETH_INFO_UNSPEC,
	VETH_INFO_PEER,

	__VETH_INFO_MAX
#define VETH_INFO_MAX (__VETH_INFO_MAX - 1)
};
#endif

#if IFLA_MAX <= 28
#define IFLA_NET_NS_FD 28
#endif

static int veth_peer_info(struct net_link *link, struct newlink_req *req, struct ns_id *ns, int ns_fd)
{
	NetDeviceEntry *nde = link->nde;
	char key[100], *val;
	struct ns_id *peer_ns = NULL;

	snprintf(key, sizeof(key), "veth[%s]", nde->name);
	val = external_lookup_by_key(key);
	if (!IS_ERR_OR_NULL(val) && ns->id == root_item->ids->net_ns_id) {
		char *aux;

		aux = strchrnul(val, '@');
		addattr_l(&req->h, sizeof(*req), IFLA_IFNAME, val, aux - val);
		addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &ns_fd, sizeof(ns_fd));
		return 0;
	}

	if (nde->has_peer_nsid) {
		struct net_link *plink;

		peer_ns = lookup_ns_by_id(nde->peer_nsid, &net_ns_desc);
		if (!peer_ns)
			goto out;
		list_for_each_entry(plink, &peer_ns->net.links, node) {
			if (plink->nde->ifindex == nde->peer_ifindex && plink->created) {
				req->h.nlmsg_type = RTM_SETLINK;
				return 0;
			}
		}
	}

	link->created = true;
	if (peer_ns) {
		addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &peer_ns->ns_fd, sizeof(int));
		return 0;
	}
out:
	pr_err("Unknown peer net namespace\n");
	return -1;
}

static int veth_link_info(struct ns_id *ns, struct net_link *link, struct newlink_req *req)
{
	int ns_fd = get_service_fd(NS_FD_OFF);
	NetDeviceEntry *nde = link->nde;
	struct rtattr *veth_data, *peer_data;
	struct ifinfomsg ifm;

	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "veth", 4);

	veth_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_DATA, NULL, 0);
	peer_data = NLMSG_TAIL(&req->h);
	memset(&ifm, 0, sizeof(ifm));

	/*
	 * Peer index might lay on the node root net namespace,
	 * where the device index may be already borrowed by
	 * some other device, so we should ignore it.
	 *
	 * Still if peer is laying in some other net-namespace,
	 * we should recreate the device index as well as the
	 * as we do for the master peer end.
	 */
	if (nde->has_peer_nsid)
		ifm.ifi_index = nde->peer_ifindex;
	addattr_l(&req->h, sizeof(*req), VETH_INFO_PEER, &ifm, sizeof(ifm));

	veth_peer_info(link, req, ns, ns_fd);
	peer_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)peer_data;
	veth_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)veth_data;

	return 0;
}

static int venet_link_info(struct ns_id *ns, struct net_link *link, struct newlink_req *req)
{
	int ns_fd = get_service_fd(NS_FD_OFF);
	struct rtattr *venet_data;

	BUG_ON(ns_fd < 0);

	venet_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "venet", 5);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_DATA, NULL, 0);
	addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &ns_fd, sizeof(ns_fd));
	venet_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)venet_data;

	return 0;
}

static int vxlan_link_info(struct ns_id *ns, struct net_link *link, struct newlink_req *req)
{
	struct rtattr *vxlan_data;
	NetDeviceEntry *nde = link->nde;
	VxlanLinkEntry *vxlan = nde->vz_vxlan;

	if (!vxlan) {
		pr_err("Missing vxlan link entry %d\n", nde->ifindex);
		return -1;
	}

	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "vxlan", 5);

	vxlan_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_DATA, NULL, 0);

#define DECODE_ENTRY(__type, __ifla, __proto)                                           \
	do {                                                                            \
		__type aux;                                                             \
		if (vxlan->has_##__proto) {                                             \
			aux = vxlan->__proto;                                           \
			addattr_l(&req->h, sizeof(*req), __ifla, &aux, sizeof(__type)); \
		}                                                                       \
	} while (0)

	addattr_l(&req->h, sizeof(*req), IFLA_VXLAN_ID, &vxlan->id, sizeof(uint32_t));

	if (vxlan->n_group)
		addattr_l(&req->h, sizeof(*req), IFLA_VXLAN_GROUP, vxlan->group, sizeof(uint32_t) * vxlan->n_group);

	if (vxlan->n_group6)
		addattr_l(&req->h, sizeof(*req), IFLA_VXLAN_GROUP6, vxlan->group6, sizeof(uint32_t) * vxlan->n_group6);

	DECODE_ENTRY(u32, IFLA_VXLAN_LINK, link);

	if (vxlan->n_local)
		addattr_l(&req->h, sizeof(*req), IFLA_VXLAN_LOCAL, vxlan->local, sizeof(uint32_t) * vxlan->n_local);

	if (vxlan->n_local6)
		addattr_l(&req->h, sizeof(*req), IFLA_VXLAN_LOCAL6, vxlan->local6, sizeof(uint32_t) * vxlan->n_local6);

	DECODE_ENTRY(u8, IFLA_VXLAN_TOS, tos);
	DECODE_ENTRY(u8, IFLA_VXLAN_TTL, ttl);
	DECODE_ENTRY(u32, IFLA_VXLAN_LABEL, label);
	DECODE_ENTRY(u8, IFLA_VXLAN_LEARNING, learning);
	DECODE_ENTRY(u32, IFLA_VXLAN_AGEING, ageing);
	DECODE_ENTRY(u32, IFLA_VXLAN_LIMIT, limit);

	if (vxlan->has_port_range)
		addattr_l(&req->h, sizeof(*req), IFLA_VXLAN_PORT_RANGE, vxlan->port_range.data, vxlan->port_range.len);

	DECODE_ENTRY(u8, IFLA_VXLAN_PROXY, proxy);
	DECODE_ENTRY(u8, IFLA_VXLAN_RSC, rsc);
	DECODE_ENTRY(u8, IFLA_VXLAN_L2MISS, l2miss);
	DECODE_ENTRY(u8, IFLA_VXLAN_L3MISS, l3miss);
	DECODE_ENTRY(u8, IFLA_VXLAN_COLLECT_METADATA, collect_metadata);
	DECODE_ENTRY(u16, IFLA_VXLAN_PORT, port);
	DECODE_ENTRY(u8, IFLA_VXLAN_UDP_CSUM, udp_csum);
	DECODE_ENTRY(u8, IFLA_VXLAN_UDP_ZERO_CSUM6_TX, udp_zero_csum6_tx);
	DECODE_ENTRY(u8, IFLA_VXLAN_UDP_ZERO_CSUM6_RX, udp_zero_csum6_rx);
	DECODE_ENTRY(u8, IFLA_VXLAN_REMCSUM_TX, remcsum_tx);
	DECODE_ENTRY(u8, IFLA_VXLAN_REMCSUM_RX, remcsum_rx);

	DECODE_ENTRY(u8, IFLA_VXLAN_DF, df);

#undef DECODE_ENTRY

#define DECODE_ENTRY_FLAG(__ifla, __proto)                      \
	do {                                                    \
		if (vxlan->has_##__proto)                       \
			addattr(&req->h, sizeof(*req), __ifla); \
	} while (0)

	DECODE_ENTRY_FLAG(IFLA_VXLAN_GBP, gbp);
	DECODE_ENTRY_FLAG(IFLA_VXLAN_GPE, gpe);
	DECODE_ENTRY_FLAG(IFLA_VXLAN_REMCSUM_NOPARTIAL, remcsum_nopartial);
	DECODE_ENTRY_FLAG(IFLA_VXLAN_TTL_INHERIT, ttl_inherit);
#undef DECODE_ENTRY_FLAG

	vxlan_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)vxlan_data;

	return 0;
}

static int bridge_link_info(struct ns_id *ns, struct net_link *link, struct newlink_req *req)
{
	struct rtattr *bridge_data;

	bridge_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "bridge", sizeof("bridge"));
	bridge_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)bridge_data;

	return 0;
}

static int changeflags(int s, char *name, short flags)
{
	struct ifreq ifr;

	__strlcpy(ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_flags = flags;

	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		pr_perror("couldn't set flags on %s", name);
		return -1;
	}

	return 0;
}

static int macvlan_link_info(struct ns_id *ns, struct net_link *link, struct newlink_req *req)
{
	struct rtattr *macvlan_data;
	NetDeviceEntry *nde = link->nde;
	MacvlanLinkEntry *macvlan = nde->macvlan;

	if (!macvlan) {
		pr_err("Missing macvlan link entry %d\n", nde->ifindex);
		return -1;
	}

	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "macvlan", 7);

	macvlan_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_DATA, NULL, 0);

	addattr_l(&req->h, sizeof(*req), IFLA_MACVLAN_MODE, &macvlan->mode, sizeof(macvlan->mode));

	if (macvlan->has_flags)
		addattr_l(&req->h, sizeof(*req), IFLA_MACVLAN_FLAGS, &macvlan->flags, sizeof(macvlan->flags));

	macvlan_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)macvlan_data;

	return 0;
}

static int userns_restore_one_link(void *arg, int fd, pid_t pid)
{
	int nlsk, ret;
	struct newlink_req *req = arg;
	int ns_fd, rst = -1;

	ns_fd = get_service_fd(NS_FD_OFF);
	if (ns_fd >= 0) {
		if (switch_ns_by_fd(ns_fd, &net_ns_desc, &rst))
			return -1;
	}

	nlsk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nlsk < 0) {
		pr_perror("Can't create nlk socket");
		ret = -1;
		goto out;
	}

	addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &fd, sizeof(fd));

	ret = do_rtnl_req(nlsk, req, req->h.nlmsg_len, restore_link_cb, NULL, NULL, NULL);
	close(nlsk);

out:
	if (rst >= 0 && restore_ns(rst, &net_ns_desc) < 0)
		ret = -1;
	return ret;
}

static int restore_one_macvlan(struct ns_id *ns, struct net_link *link, int nlsk)
{
	struct newlink_extras extras = {
		.link = -1,
		.target_netns = -1,
	};
	char key[100], *val;
	int my_netns = -1, ret = -1;
	NetDeviceEntry *nde = link->nde;

	snprintf(key, sizeof(key), "macvlan[%s]", nde->name);
	val = external_lookup_data(key);
	if (IS_ERR_OR_NULL(val)) {
		pr_err("a macvlan parent for %s is required\n", nde->name);
		return -1;
	}

	/* link and netns_id are used to identify the master device to plug our
	 * macvlan slave into. We identify the destination via setting
	 * IFLA_NET_NS_FD to my_netns, but we have to do that in two different
	 * ways: in the userns case, we send the fd across to usernsd and set
	 * it there, whereas in the non-userns case we can just set it here,
	 * since we can just use a socket from criu's net ns given to us by
	 * restore_links(). We need to do this two different ways because
	 * CAP_NET_ADMIN is required in both namespaces, which we don't have in
	 * the userns case, and usernsd doesn't exist in the non-userns case.
	 */
	extras.link = (int)(unsigned long)val;

	my_netns = open_proc(PROC_SELF, "ns/net");
	if (my_netns < 0)
		return -1;

	{
		struct newlink_req req;

		if (populate_newlink_req(ns, &req, RTM_NEWLINK, link, macvlan_link_info, &extras) < 0)
			goto out;

		if (userns_call(userns_restore_one_link, 0, &req, sizeof(req), my_netns) < 0) {
			pr_err("couldn't restore macvlan interface %s via usernsd\n", nde->name);
			goto out;
		}
	}

	ret = 0;
out:
	if (my_netns >= 0)
		close(my_netns);
	return ret;
}

static int create_one_dp(OvsDatapathLinkEntry *dp_entry, int ifindex, int genlsk)
{
	int16_t ovs_dp_genl_id;
	int ret;
	struct ovs_request rq;

	ovs_dp_genl_id = get_cached_genl_family_id(OVS_DATAPATH_FAMILY);
	if (ovs_dp_genl_id < 0) {
		pr_err("Unable to get %s genl_family id\n", OVS_DATAPATH_FAMILY);
		return -1;
	}

	memset(&rq, 0, sizeof(rq));
	rq.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr) + sizeof(struct ovs_header));
	rq.h.nlmsg_type = ovs_dp_genl_id;
	rq.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
	rq.h.nlmsg_pid = 0;
	rq.h.nlmsg_seq = CR_NLMSG_SEQ;

	rq.gh.cmd = OVS_DP_CMD_NEW;
	rq.gh.version = OVS_DATAPATH_VERSION;

	/* vzkernel feature, see https://lists.openvz.org/pipermail/devel/2020-August/075509.html */
	rq.ovsh.dp_ifindex = ifindex;

	addattr_l(&rq.h, sizeof(rq), OVS_DP_ATTR_NAME, dp_entry->name, strlen(dp_entry->name) + 1);
	addattr_l(&rq.h, sizeof(rq), OVS_DP_ATTR_USER_FEATURES, &dp_entry->features, sizeof(dp_entry->features));
	addattr_l(&rq.h, sizeof(rq), OVS_DP_ATTR_UPCALL_PID, &dp_entry->upcall_pid, sizeof(dp_entry->upcall_pid));

	ret = do_rtnl_req(genlsk, &rq, rq.h.nlmsg_len, NULL, NULL, NULL, NULL);

	return ret;
}

static int create_one_vport(OvsVportEntry *entry, int ifindex, int genlsk)
{
	int16_t ovs_vport_genl_id;
	int ret;
	struct ovs_request rq;

	ovs_vport_genl_id = get_cached_genl_family_id(OVS_VPORT_FAMILY);
	if (ovs_vport_genl_id < 0) {
		pr_err("Unable to get %s genl_family id\n", OVS_VPORT_FAMILY);
		return -1;
	}

	memset(&rq, 0, sizeof(rq));
	rq.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr) + sizeof(struct ovs_header));
	rq.h.nlmsg_type = ovs_vport_genl_id;
	rq.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	rq.h.nlmsg_pid = 0;
	rq.h.nlmsg_seq = CR_NLMSG_SEQ;

	rq.gh.cmd = OVS_VPORT_CMD_NEW;
	rq.gh.version = OVS_VPORT_VERSION;

	rq.ovsh.dp_ifindex = entry->datapath_ifindex;

	addattr_l(&rq.h, sizeof(rq), OVS_VPORT_ATTR_NAME, entry->name, strlen(entry->name) + 1);
	addattr_l(&rq.h, sizeof(rq), OVS_VPORT_ATTR_UPCALL_PID, &entry->upcall_pid, sizeof(entry->upcall_pid));
	addattr_l(&rq.h, sizeof(rq), OVS_VPORT_ATTR_TYPE, &entry->type, sizeof(entry->type));
	addattr_l(&rq.h, sizeof(rq), OVS_VPORT_ATTR_PORT_NO, &entry->port_no, sizeof(entry->port_no));

	/* vzkernel feature, see https://lists.openvz.org/pipermail/devel/2020-August/075509.html */
	if (entry->type == OVS_VPORT_TYPE_INTERNAL)
		addattr_l(&rq.h, sizeof(rq), OVS_VPORT_ATTR_IFINDEX, &ifindex, sizeof(ifindex));

	/*
	 * This code is unused for now since we make all vxlan vports into netdev vports because
	 * there are no API to specify ifindex of vxlan netdev created through ovs.
	 * Following code will come in handy later!
	 */
	if (entry->type == OVS_VPORT_TYPE_VXLAN && entry->opt) {
		struct rtattr *opt;
		int16_t port = entry->opt->port;

		opt = NLMSG_TAIL(&rq.h);
		addattr_l(&rq.h, sizeof(rq), OVS_VPORT_ATTR_OPTIONS, NULL, 0);
		addattr_l(&rq.h, sizeof(rq), OVS_TUNNEL_ATTR_DST_PORT, &port, sizeof(port));

		opt->rta_len = (void *)NLMSG_TAIL(&rq.h) - (void *)opt;
	}

	ret = do_rtnl_req(genlsk, &rq, rq.h.nlmsg_len, NULL, NULL, NULL, NULL);

	return ret;
}

static int restore_ovs_dp(struct ns_id *ns, struct net_link *link, int genlsk)
{
	BUG_ON(!link->nde->vz_ovs_dp);
	if (create_one_dp(link->nde->vz_ovs_dp, link->nde->ifindex, genlsk)) {
		pr_perror("Unable to restore datapath %s", link->nde->vz_ovs_dp->name);
		return -1;
	}

	return restore_link_parms(link, ns->net.nlsk);
}

static int restore_ovs_internal_port(struct ns_id *ns, struct net_link *link, int genlsk)
{
	BUG_ON(!link->nde->vz_ovs_vport);
	if (create_one_vport(link->nde->vz_ovs_vport, link->nde->ifindex, genlsk)) {
		pr_perror("Unable to restore vport %s", link->nde->vz_ovs_vport->name);
		return -1;
	}

	return restore_link_parms(link, ns->net.nlsk);
}

static int sit_link_info(struct ns_id *ns, struct net_link *link, struct newlink_req *req)
{
	NetDeviceEntry *nde = link->nde;
	struct rtattr *sit_data;
	SitEntry *se = nde->sit;

	if (!se) {
		pr_err("Missing sit entry %d\n", nde->ifindex);
		return -1;
	}

	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "sit", 3);
	sit_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_DATA, NULL, 0);

#define DECODE_ENTRY(__type, __ifla, __proto)                                           \
	do {                                                                            \
		__type aux;                                                             \
		if (se->has_##__proto) {                                                \
			aux = se->__proto;                                              \
			addattr_l(&req->h, sizeof(*req), __ifla, &aux, sizeof(__type)); \
		}                                                                       \
	} while (0)

	if (se->n_local) {
		if (se->n_local != 1) {
			pr_err("Too long local addr for sit\n");
			return -1;
		}
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_LOCAL, se->local, sizeof(u32));
	}

	if (se->n_remote) {
		if (se->n_remote != 1) {
			pr_err("Too long remote addr for sit\n");
			return -1;
		}
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_REMOTE, se->remote, sizeof(u32));
	}

	DECODE_ENTRY(u32, IFLA_IPTUN_LINK, link);
	DECODE_ENTRY(u8, IFLA_IPTUN_TTL, ttl);
	DECODE_ENTRY(u8, IFLA_IPTUN_TOS, tos);
	DECODE_ENTRY(u16, IFLA_IPTUN_FLAGS, flags);
	DECODE_ENTRY(u8, IFLA_IPTUN_PROTO, proto);

	if (se->has_pmtudisc && se->pmtudisc) {
		u8 aux = 1;
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_PMTUDISC, &aux, sizeof(u8));
	}

	DECODE_ENTRY(u16, IFLA_IPTUN_ENCAP_TYPE, encap_type);
	DECODE_ENTRY(u16, IFLA_IPTUN_ENCAP_FLAGS, encap_flags);
	DECODE_ENTRY(u16, IFLA_IPTUN_ENCAP_SPORT, encap_sport);
	DECODE_ENTRY(u16, IFLA_IPTUN_ENCAP_DPORT, encap_dport);

	if (se->has_rd_prefixlen) {
		u16 aux;

		if (se->n_rd_prefix != 4) {
			pr_err("Bad 6rd prefixlen for sit\n");
			return -1;
		}

		aux = se->rd_prefixlen;
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_6RD_PREFIXLEN, &aux, sizeof(u16));
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_6RD_PREFIX, se->rd_prefix, 4 * sizeof(u32));

		if (!se->has_relay_prefixlen)
			goto skip;

		if (se->n_relay_prefix != 1) {
			pr_err("Bad 6rd relay prefixlen for sit\n");
			return -1;
		}

		aux = se->relay_prefixlen;
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_6RD_RELAY_PREFIXLEN, &aux, sizeof(u16));
		addattr_l(&req->h, sizeof(*req), IFLA_IPTUN_6RD_RELAY_PREFIX, se->relay_prefix, sizeof(u32));
	skip:;
	}

#undef DECODE_ENTRY

	sit_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)sit_data;

	return 0;
}

static int __restore_link(struct ns_id *ns, struct net_link *link, int nlsk)
{
	NetDeviceEntry *nde = link->nde;
	char key[100], *val;

	pr_info("Restoring link %s type %d\n", nde->name, nde->type);

	switch (nde->type) {
	case ND_TYPE__LOOPBACK: /* fallthrough */
	case ND_TYPE__EXTLINK:	/* see comment in images/netdev.proto */
		return restore_link_parms(link, nlsk);
	case ND_TYPE__VENET:
		return restore_one_link(ns, link, nlsk, venet_link_info, NULL);
	case ND_TYPE__VETH:
		/* Handle pre-created veth devices we just need to move over. */
		snprintf(key, sizeof(key), "netdev[%s]", nde->name);
		val = external_lookup_by_key(key);
		if (!IS_ERR_OR_NULL(val))
			return move_veth(val, ns, link, nlsk);

		return restore_one_link(ns, link, nlsk, veth_link_info, NULL);
	case ND_TYPE__TUN:
		return restore_one_tun(ns, link, nlsk);
	case ND_TYPE__BRIDGE:
		return restore_one_link(ns, link, nlsk, bridge_link_info, NULL);
	case ND_TYPE__MACVLAN:
		return restore_one_macvlan(ns, link, nlsk);
	case ND_TYPE__VZ_VXLAN:
		return restore_one_link(ns, link, nlsk, vxlan_link_info, NULL);
	case ND_TYPE__SIT:
		return restore_one_link(ns, link, nlsk, sit_link_info, NULL);
	case ND_TYPE__VZ_OVS_DATAPATH:
		return restore_ovs_dp(ns, link, ns->net.genlsk);
	case ND_TYPE__VZ_OVS_INTERNAL_VPORT:
		return restore_ovs_internal_port(ns, link, ns->net.genlsk);
	default:
		pr_err("Unsupported link type %d\n", link->nde->type);
		break;
	}

	return -1;
}

static int read_links(struct ns_id *ns)
{
	int ret = -1, id = ns->id;
	struct cr_img *img;
	NetDeviceEntry *nde;

	img = open_image(CR_FD_NETDEV, O_RSTR, id);
	if (!img)
		return -1;

	while (1) {
		struct net_link *link;

		ret = pb_read_one_eof(img, &nde, PB_NETDEV);
		if (ret <= 0)
			break;

		link = xmalloc(sizeof(*link));
		if (link == NULL) {
			ret = -1;
			net_device_entry__free_unpacked(nde, NULL);
			break;
		}

		link->nde = nde;
		link->created = 0;
		list_add(&link->node, &ns->net.links);
	}
	close_image(img);

	return ret;
}

static int restore_link(int nlsk, struct ns_id *ns, struct net_link *link)
{
	NetDeviceEntry *nde = link->nde;
	NetnsEntry **def_netns = &ns->net.netns;
	int ret;

	ret = __restore_link(ns, link, nlsk);
	if (ret) {
		pr_err("Can't restore link: %d\n", ret);
		goto exit;
	}

	/*
	 * optimize restore of devices configuration except lo
	 * lo is created with namespace and before default is set
	 * so we can't optimize its restore
	 */
	if (nde->type == ND_TYPE__LOOPBACK)
		def_netns = NULL;

	if (nde->conf4)
		ret = ipv4_conf_op(nde->name, nde->conf4, nde->n_conf4, CTL_WRITE,
				   def_netns ? (*def_netns)->def_conf4 : NULL);
	else if (nde->conf)
		ret = ipv4_conf_op_old(nde->name, nde->conf, nde->n_conf, CTL_WRITE,
				       def_netns ? (*def_netns)->def_conf : NULL);
	if (ret)
		goto exit;

	if (nde->conf6)
		ret = ipv6_conf_op(nde->name, nde->conf6, nde->n_conf6, CTL_WRITE,
				   def_netns ? (*def_netns)->def_conf6 : NULL);
exit:
	return ret;
}

static int restore_ovs_master(struct net_link *link, int genlsk)
{
	BUG_ON(!link->nde->vz_ovs_vport);
	return create_one_vport(link->nde->vz_ovs_vport, 0, genlsk);
}

static int restore_ifla_master(int nlsk, struct ns_id *ns, struct net_link *link)
{
	struct newlink_req req;

	memset(&req, 0, sizeof(req));

	req.h.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
	req.h.nlmsg_type = RTM_SETLINK;
	req.h.nlmsg_seq = CR_NLMSG_SEQ;
	req.i.ifi_family = AF_PACKET;
	req.i.ifi_index = link->nde->ifindex;
	req.i.ifi_flags = link->nde->flags;

	addattr_l(&req.h, sizeof(req), IFLA_MASTER, &link->nde->master, sizeof(link->nde->master));

	return do_rtnl_req(nlsk, &req, req.h.nlmsg_len, restore_link_cb, NULL, NULL, NULL);
}

struct net_link *lookup_net_link(struct ns_id *ns, uint32_t ifindex)
{
	struct net_link *link;

	list_for_each_entry(link, &ns->net.links, node)
		if (link->nde->ifindex == ifindex)
			return link;

	return NULL;
}

static int restore_master_link(int nlsk, struct ns_id *ns, struct net_link *link)
{
	struct net_link *mlink = NULL;
	mlink = lookup_net_link(ns, link->nde->master);

	if (mlink && mlink->nde->type == ND_TYPE__VZ_OVS_DATAPATH)
		return restore_ovs_master(link, ns->net.genlsk);
	else
		return restore_ifla_master(nlsk, ns, link);
}

static int __restore_links(struct ns_id *nsid, int *nrlinks, int *nrcreated)
{
	struct net_link *link, *t;
	int ret;

	list_for_each_entry_safe(link, t, &nsid->net.links, node) {
		struct net_link *mlink = NULL;

		if (link->created)
			continue;

		(*nrlinks)++;

		pr_debug("Try to restore a link %d:%d:%s\n", nsid->id, link->nde->ifindex, link->nde->name);
		if (link->nde->has_master) {
			mlink = lookup_net_link(nsid, link->nde->master);
			if (mlink == NULL) {
				pr_err("Unable to find the %d master\n", link->nde->master);
				return -1;
			}

			if (!mlink->created) {
				pr_debug("The master %d:%d:%s isn't created yet", nsid->id, mlink->nde->ifindex,
					 mlink->nde->name);
				continue;
			}
		}

		/*
		 * vxlan link may have IFLA_VXLAN_LINK set. In that field stored
		 * ifindex of the interface which will be used for transmitting
		 * vxlan UDP traffic. We should restore this interface at first.
		 */
		if (link->nde->type == ND_TYPE__VZ_VXLAN && link->nde->vz_vxlan->has_link) {
			uint32_t idx = link->nde->vz_vxlan->link;
			struct net_link *tlink;

			tlink = lookup_net_link(nsid, idx);
			if (tlink == NULL) {
				pr_err("Unable to find the interface with ifindex %d\n", idx);
				return -1;
			}

			if (!tlink->created) {
				pr_debug("The iface %d:%d:%s isn't created yet for vxlan %d:%d:%s",
					 nsid->id, tlink->nde->ifindex, tlink->nde->name,
					 nsid->id, link->nde->ifindex, link->nde->name);
				continue;
			}
		}

		if (link->nde->type == ND_TYPE__VZ_OVS_INTERNAL_VPORT) {
			struct net_link *dplink;

			BUG_ON(!link->nde->vz_ovs_vport);
			dplink = lookup_net_link(nsid, link->nde->vz_ovs_vport->datapath_ifindex);

			if (dplink == NULL) {
				pr_err("Unable to find the %d datapath\n", link->nde->vz_ovs_vport->datapath_ifindex);
				return -1;
			}

			if (!dplink->created) {
				pr_debug("The datapath %d:%d:%s isn't created yet, can't restore vport",
					 nsid->id, dplink->nde->ifindex, dplink->nde->name);
				continue;
			}
		}

		ret = restore_link(nsid->net.nlsk, nsid, link);
		if (ret < 0)
			return -1;

		if (ret == 0) {
			(*nrcreated)++;
			link->created = true;

			if (mlink && restore_master_link(nsid->net.nlsk, nsid, link))
				return -1;
		}
	}

	return 0;
}

static int restore_links(void)
{
	int nrcreated, nrlinks;
	struct ns_id *nsid;

	fill_genl_families();

	while (true) {
		nrcreated = 0;
		nrlinks = 0;
		for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
			if (nsid->nd != &net_ns_desc)
				continue;

			if (switch_ns_by_fd(nsid->ns_fd, &net_ns_desc, NULL))
				return -1;

			if (__restore_links(nsid, &nrlinks, &nrcreated))
				return -1;
		}

		if (nrcreated == nrlinks)
			break;
		if (nrcreated == 0) {
			pr_err("Unable to restore network links\n");
			return -1;
		}
	}

	return 0;
}

static int run_ipset_tool(char *sub_cmd, int fdin, int fdout)
{
	char *cmd;
	int ret;

	cmd = getenv("CR_IPSET_TOOL");
	if (!cmd)
		cmd = "ipset";

	ret = cr_system(fdin, fdout, -1, cmd, (char *[]){ cmd, sub_cmd, NULL }, 0);
	if (ret) {
		pr_err("ipset tool failed on %s\n", sub_cmd);
		return -1;
	}

	return 0;
}

static int run_ip_tool(char *arg1, char *arg2, char *arg3, char *arg4, int fdin, int fdout, unsigned flags)
{
	char *ip_tool_cmd;
	int ret;

	pr_debug("\tRunning ip %s %s %s %s\n", arg1, arg2, arg3 ?: "", arg4 ?: "");

	ip_tool_cmd = getenv("CR_IP_TOOL");
	if (!ip_tool_cmd)
		ip_tool_cmd = "ip";

	ret = cr_system(fdin, fdout, -1, ip_tool_cmd, (char *[]){ "ip", arg1, arg2, arg3, arg4, NULL }, flags);
	if (ret) {
		if (!(flags & CRS_CAN_FAIL))
			pr_err("IP tool failed on %s %s %s %s\n", arg1, arg2, arg3 ?: "", arg4 ?: "");
		return -1;
	}

	return 0;
}

static int run_iptables_tool(char *def_cmd, int fdin, int fdout)
{
	int ret;
	char *cmd;

	cmd = getenv("CR_IPTABLES");
	if (!cmd)
		cmd = def_cmd;
	pr_debug("\tRunning %s for %s\n", cmd, def_cmd);
	ret = cr_system(fdin, fdout, -1, "sh", (char *[]){ "sh", "-c", cmd, NULL }, 0);
	if (ret)
		pr_err("%s failed\n", def_cmd);

	return ret;
}

static inline int dump_ifaddr(struct cr_imgset *fds)
{
	struct cr_img *img = img_from_set(fds, CR_FD_IFADDR);
	return run_ip_tool("addr", "save", NULL, NULL, -1, img_raw_fd(img), 0);
}

static inline int dump_route(struct cr_imgset *fds)
{
	struct cr_img *img;

	img = img_from_set(fds, CR_FD_ROUTE);
	if (run_ip_tool("route", "save", NULL, NULL, -1, img_raw_fd(img), 0))
		return -1;

	/* If ipv6 is disabled, "ip -6 route dump" dumps all routes */
	if (!kdat.ipv6)
		return 0;

	img = img_from_set(fds, CR_FD_ROUTE6);
	if (run_ip_tool("-6", "route", "save", NULL, -1, img_raw_fd(img), 0))
		return -1;

	return 0;
}

static inline int dump_rule(struct cr_imgset *fds)
{
	struct cr_img *img;
	char *path;

	img = img_from_set(fds, CR_FD_RULE);
	path = xstrdup(img->path);

	if (!path)
		return -1;

	if (run_ip_tool("rule", "save", NULL, NULL, -1, img_raw_fd(img), CRS_CAN_FAIL)) {
		pr_warn("Check if \"ip rule save\" is supported!\n");
		unlinkat(get_service_fd(IMG_FD_OFF), path, 0);
	}

	free(path);

	return 0;
}

static inline int dump_ipset(struct cr_imgset *fds)
{
	int ret;
	struct cr_img *img;
	img = img_from_set(fds, CR_FD_IPSET);
	ret = run_ipset_tool("save", -1, img_raw_fd(img));
	return ret;
}

static inline int dump_iptables(struct cr_imgset *fds)
{
	struct cr_img *img;
	char *iptables_cmd = "iptables-save";
	char *ip6tables_cmd = "ip6tables-save";

	/*
	 * Let's skip iptables dump if we have nftables support compiled in,
	 * and iptables backend is nft to prevent duplicate dumps.
	 */
#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
	iptables_cmd = get_legacy_iptables_bin(false, false);

	if (kdat.ipv6)
		ip6tables_cmd = get_legacy_iptables_bin(true, false);
#endif

	if (!iptables_cmd) {
		pr_info("skipping iptables dump - no legacy version present\n");
	} else {
		img = img_from_set(fds, CR_FD_IPTABLES);
		if (run_iptables_tool(iptables_cmd, -1, img_raw_fd(img)))
			return -1;
	}

	if (!kdat.ipv6)
		return 0;

	if (!ip6tables_cmd) {
		pr_info("skipping ip6tables dump - no legacy version present\n");
	} else {
		img = img_from_set(fds, CR_FD_IP6TABLES);
		if (run_iptables_tool(ip6tables_cmd, -1, img_raw_fd(img)))
			return -1;
	}

	return 0;
}

#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
static inline int dump_nftables(struct cr_imgset *fds)
{
	int ret = -1;
	struct cr_img *img;
	int img_fd;
	FILE *fp;
	struct nft_ctx *nft;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return -1;

	img = img_from_set(fds, CR_FD_NFTABLES);
	img_fd = img_raw_fd(img);
	if (img_fd < 0) {
		pr_err("Getting raw FD failed\n");
		goto nft_ctx_free_out;
	}
	img_fd = dup(img_fd);
	if (img_fd < 0) {
		pr_perror("dup() failed");
		goto nft_ctx_free_out;
	}

	fp = fdopen(img_fd, "w");
	if (!fp) {
		pr_perror("fdopen() failed");
		close(img_fd);
		goto nft_ctx_free_out;
	}

	nft_ctx_set_output(nft, fp);
#define DUMP_NFTABLES_CMD "list ruleset"
#if defined(CONFIG_HAS_NFTABLES_LIB_API_0)
	if (nft_run_cmd_from_buffer(nft, DUMP_NFTABLES_CMD, strlen(DUMP_NFTABLES_CMD)))
#elif defined(CONFIG_HAS_NFTABLES_LIB_API_1)
	if (nft_run_cmd_from_buffer(nft, DUMP_NFTABLES_CMD))
#else
	BUILD_BUG_ON(1);
#endif
		goto fp_close_out;

	ret = 0;

fp_close_out:
	fclose(fp);
nft_ctx_free_out:
	nft_ctx_free(nft);

	return ret;
}
#endif

static int dump_netns_conf(struct ns_id *ns, struct cr_imgset *fds)
{
	void *buf, *o_buf;
	int ret = -1;
	int i;
	NetnsEntry netns = NETNS_ENTRY__INIT;
	SysctlEntry *unix_confs = NULL;
	size_t sizex = ARRAY_SIZE(unix_conf_entries);
	SysctlEntry *def_confs4 = NULL, *all_confs4 = NULL;
	int size4 = ARRAY_SIZE(devconfs4);
	SysctlEntry *def_confs6 = NULL, *all_confs6 = NULL;
	int size6 = ARRAY_SIZE(devconfs6);
	char def_stable_secret[MAX_STR_CONF_LEN + 1] = {};
	char all_stable_secret[MAX_STR_CONF_LEN + 1] = {};
	NetnsId *ids;
	struct netns_id *p;
	int core_size = ARRAY_SIZE(coreconfs);
	SysctlEntry *core_confs = NULL;

	i = 0;
	list_for_each_entry(p, &ns->net.ids, node)
		i++;

	o_buf = buf = xmalloc(i * (sizeof(NetnsId *) + sizeof(NetnsId)) +
			      size4 * (sizeof(SysctlEntry *) + sizeof(SysctlEntry)) * 2 +
			      size6 * (sizeof(SysctlEntry *) + sizeof(SysctlEntry)) * 2 +
			      sizex * (sizeof(SysctlEntry *) + sizeof(SysctlEntry)) +
			      core_size * (sizeof(SysctlEntry *) + sizeof(SysctlEntry)));
	if (!buf)
		goto out;

	netns.nsids = xptr_pull_s(&buf, i * sizeof(NetnsId *));
	ids = xptr_pull_s(&buf, i * sizeof(NetnsId));
	i = 0;
	list_for_each_entry(p, &ns->net.ids, node) {
		netns_id__init(&ids[i]);
		ids[i].target_ns_id = p->target_ns_id;
		ids[i].netnsid_value = p->netnsid_value;
		netns.nsids[i] = ids + i;
		i++;
	}
	netns.n_nsids = i;

	netns.n_def_conf4 = size4;
	netns.n_all_conf4 = size4;
	netns.def_conf4 = xptr_pull_s(&buf, size4 * sizeof(SysctlEntry *));
	netns.all_conf4 = xptr_pull_s(&buf, size4 * sizeof(SysctlEntry *));
	def_confs4 = xptr_pull_s(&buf, size4 * sizeof(SysctlEntry));
	all_confs4 = xptr_pull_s(&buf, size4 * sizeof(SysctlEntry));

	for (i = 0; i < size4; i++) {
		sysctl_entry__init(&def_confs4[i]);
		sysctl_entry__init(&all_confs4[i]);
		netns.def_conf4[i] = &def_confs4[i];
		netns.all_conf4[i] = &all_confs4[i];
		netns.def_conf4[i]->type = CTL_32;
		netns.all_conf4[i]->type = CTL_32;
	}

	netns.n_def_conf6 = size6;
	netns.n_all_conf6 = size6;
	netns.def_conf6 = xptr_pull_s(&buf, size6 * sizeof(SysctlEntry *));
	netns.all_conf6 = xptr_pull_s(&buf, size6 * sizeof(SysctlEntry *));
	def_confs6 = xptr_pull_s(&buf, size6 * sizeof(SysctlEntry));
	all_confs6 = xptr_pull_s(&buf, size6 * sizeof(SysctlEntry));

	for (i = 0; i < size6; i++) {
		sysctl_entry__init(&def_confs6[i]);
		sysctl_entry__init(&all_confs6[i]);
		netns.def_conf6[i] = &def_confs6[i];
		netns.all_conf6[i] = &all_confs6[i];
		if (strcmp(devconfs6[i], "stable_secret")) {
			netns.def_conf6[i]->type = SYSCTL_TYPE__CTL_32;
			netns.all_conf6[i]->type = SYSCTL_TYPE__CTL_32;
		} else {
			netns.def_conf6[i]->type = SYSCTL_TYPE__CTL_STR;
			netns.all_conf6[i]->type = SYSCTL_TYPE__CTL_STR;
			netns.def_conf6[i]->sarg = def_stable_secret;
			netns.all_conf6[i]->sarg = all_stable_secret;
		}
	}

	netns.n_unix_conf = sizex;
	netns.unix_conf = xptr_pull_s(&buf, sizex * sizeof(SysctlEntry *));
	unix_confs = xptr_pull_s(&buf, sizex * sizeof(SysctlEntry));

	for (i = 0; i < sizex; i++) {
		sysctl_entry__init(&unix_confs[i]);
		netns.unix_conf[i] = &unix_confs[i];
		netns.unix_conf[i]->type = SYSCTL_TYPE__CTL_32;
	}

	netns.n_vz_core_conf = core_size;
	netns.vz_core_conf = xptr_pull_s(&buf, core_size * sizeof(SysctlEntry *));
	core_confs = xptr_pull_s(&buf, core_size * sizeof(SysctlEntry));

	for (i = 0; i < core_size; i++) {
		sysctl_entry__init(&core_confs[i]);
		netns.vz_core_conf[i] = &core_confs[i];
		netns.vz_core_conf[i]->type = SYSCTL_TYPE__CTL_32;
	}

	ret = ipv4_conf_op("default", netns.def_conf4, size4, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;
	ret = ipv4_conf_op("all", netns.all_conf4, size4, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;

	ret = ipv6_conf_op("default", netns.def_conf6, size6, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;
	ret = ipv6_conf_op("all", netns.all_conf6, size6, CTL_READ, NULL);
	if (ret < 0)
		goto err_free;

	ret = unix_conf_op(&netns.unix_conf, &netns.n_unix_conf, CTL_READ);
	if (ret < 0)
		goto err_free;

	ret = core_conf_op(netns.vz_core_conf, core_size, CTL_READ);
	if (ret < 0)
		goto err_free;

	ret = pb_write_one(img_from_set(fds, CR_FD_NETNS), &netns, PB_NETNS);
err_free:
	xfree(o_buf);
out:
	return ret;
}

static int restore_ip_dump(int type, int pid, char *cmd)
{
	int ret = -1, sockfd, n, written;
	FILE *tmp_file;
	struct cr_img *img;
	char buf[1024];

	img = open_image(type, O_RSTR, pid);
	if (empty_image(img)) {
		close_image(img);
		return 0;
	}
	sockfd = img_raw_fd(img);
	if (sockfd < 0) {
		pr_err("Getting raw FD failed\n");
		goto out_image;
	}
	tmp_file = tmpfile();
	if (!tmp_file) {
		pr_perror("Failed to open tmpfile");
		goto out_image;
	}

	while ((n = read(sockfd, buf, 1024)) > 0) {
		written = fwrite(buf, sizeof(char), n, tmp_file);
		if (written < n) {
			pr_perror("Failed to write to tmpfile "
				  "[written: %d; total: %d]",
				  written, n);
			goto out_tmp_file;
		}
	}

	if (fseek(tmp_file, 0, SEEK_SET)) {
		pr_perror("Failed to set file position to beginning of tmpfile");
		goto out_tmp_file;
	}

	if (type == CR_FD_RULE) {
		/*
		 * Delete 3 default rules to prevent duplicates. See kernel's
		 * function fib_default_rules_init() for the details.
		 */
		run_ip_tool("rule", "flush", NULL, NULL, -1, -1, 0);
		run_ip_tool("rule", "delete", "table", "local", -1, -1, 0);
	}

	ret = run_ip_tool(cmd, "restore", NULL, NULL, fileno(tmp_file), -1, 0);

out_tmp_file:
	if (fclose(tmp_file)) {
		pr_perror("Failed to close tmpfile");
	}

out_image:
	close_image(img);

	return ret;
}

static inline int restore_ifaddr(int pid)
{
	return restore_ip_dump(CR_FD_IFADDR, pid, "addr");
}

static inline int restore_route(int pid)
{
	if (restore_ip_dump(CR_FD_ROUTE, pid, "route"))
		return -1;

	if (restore_ip_dump(CR_FD_ROUTE6, pid, "route"))
		return -1;

	return 0;
}

static inline int restore_rule(int pid)
{
	return restore_ip_dump(CR_FD_RULE, pid, "rule");
}

static int __prepare_xtable_lock(void)
{
	/*
	 * __prepare_net_namespaces is executed in a separate process,
	 * so a mount namespace can be changed.
	 */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("Unable to create a mount namespace");
		return -1;
	}

	if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL)) {
		pr_perror("Unable to convert mounts to slave mounts");
		return -1;
	}
	/*
	 * /run/xtables.lock may not exist, so we can't just bind-mount a file
	 * over it.
	 * A new mount will not be propagated to the host mount namespace,
	 * because we are in another userns.
	 */

	if (mount("criu-xtable-lock", "/run", "tmpfs", 0, NULL)) {
		pr_perror("Unable to mount tmpfs into /run");
		return -1;
	}

	return 0;
}

/*
 * iptables-restore is executed from a target userns and it may have not enough
 * rights to open /run/xtables.lock. Here we try to workaround this problem.
 */
static int prepare_xtable_lock(void)
{
	int fd;

	fd = open("/run/xtables.lock", O_RDONLY);
	if (fd >= 0) {
		close(fd);
		return 0;
	}

	return __prepare_xtable_lock();
}

static inline int restore_ipset(int pid)
{
	int ret;
	struct cr_img *img;
	img = open_image(CR_FD_IPSET, O_RSTR, pid);
	if (img == NULL)
		return -1;
	if (empty_image(img)) {
		ret = 0;
		goto out;
	}
	ret = run_ipset_tool("restore", img_raw_fd(img), -1);
out:
	close_image(img);
	return ret;
}

static inline int restore_iptables(int pid)
{
	char *iptables_cmd = "iptables-restore";
	char *ip6tables_cmd = "ip6tables-restore";
	char comm[32];
	int ret = -1;
	struct cr_img *img;

#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
	iptables_cmd = get_legacy_iptables_bin(false, true);

	if (kdat.ipv6)
		ip6tables_cmd = get_legacy_iptables_bin(true, true);
#endif

	img = open_image(CR_FD_IPTABLES, O_RSTR, pid);
	if (img == NULL)
		return -1;
	if (empty_image(img)) {
		ret = 0;
		close_image(img);
		goto ipt6;
	}

	if (!iptables_cmd) {
		pr_err("Can't restore iptables dump - no legacy version present\n");
		close_image(img);
		return -1;
	}

	if (snprintf(comm, sizeof(comm), "%s -w", iptables_cmd) >= sizeof(comm)) {
		pr_err("Can't fit '%s -w' to buffer\n", iptables_cmd);
		close_image(img);
		return -1;
	}

	ret = run_iptables_tool(comm, img_raw_fd(img), -1);
	close_image(img);
	if (ret)
		return ret;
ipt6:
	img = open_image(CR_FD_IP6TABLES, O_RSTR, pid);
	if (img == NULL)
		return -1;
	if (empty_image(img))
		goto out;

	if (!ip6tables_cmd) {
		pr_err("Can't restore ip6tables dump - no legacy version present\n");
		close_image(img);
		return -1;
	}

	if (snprintf(comm, sizeof(comm), "%s -w", ip6tables_cmd) >= sizeof(comm)) {
		pr_err("Can't fit '%s -w' to buffer\n", ip6tables_cmd);
		close_image(img);
		return -1;
	}

	ret = run_iptables_tool(comm, img_raw_fd(img), -1);
out:
	close_image(img);

	return ret;
}

#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
static inline int do_restore_nftables(struct cr_img *img)
{
	int exit_code = -1;
	struct nft_ctx *nft;
	off_t img_data_size;
	char *buf;

	if ((img_data_size = img_raw_size(img)) < 0)
		goto out;

	if (read_img_str(img, &buf, img_data_size) < 0)
		goto out;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		goto buf_free_out;

	if (nft_ctx_buffer_output(nft) || nft_ctx_buffer_error(nft) ||
#if defined(CONFIG_HAS_NFTABLES_LIB_API_0)
	    nft_run_cmd_from_buffer(nft, buf, strlen(buf)))
#elif defined(CONFIG_HAS_NFTABLES_LIB_API_1)
	    nft_run_cmd_from_buffer(nft, buf))
#else
	{
		BUILD_BUG_ON(1);
	}
#endif
		goto nft_ctx_free_out;

	exit_code = 0;

nft_ctx_free_out:
	nft_ctx_free(nft);
buf_free_out:
	xfree(buf);
out:
	return exit_code;
}
#endif

static inline int restore_nftables(int pid)
{
	int exit_code = -1;
	struct cr_img *img;

	img = open_image(CR_FD_NFTABLES, O_RSTR, pid);
	if (img == NULL)
		return -1;
	if (empty_image(img)) {
		/* Backward compatibility */
		pr_info("Skipping nft restore, no image\n");
		exit_code = 0;
		goto image_close_out;
	}

#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
	if (!do_restore_nftables(img))
		exit_code = 0;
#else
	pr_err("Unable to restore nftables. CRIU was built without libnftables support\n");
#endif

image_close_out:
	close_image(img);

	return exit_code;
}

static int __run_nftables_tool(char *def_cmd, int fdin, int fdout)
{
	int ret;
	char *cmd;

	cmd = getenv("CR_NFTABLES");
	if (!cmd)
		cmd = def_cmd;
	pr_debug("\tRunning %s for %s\n", cmd, def_cmd);
	ret = cr_system(fdin, fdout, -1, "sh", (char *[]){ "sh", "-c", cmd, NULL }, 0);
	if (ret)
		pr_err("%s failed\n", def_cmd);

	return ret;
}

struct nftables_arg {
	char *def_cmd;
	int fdin;
	int fdout;
};

#define NFT_CHROOT_PATH "/vz/pkgenv/rpm414x64"

static int ns_run_nftables_tool(void *args)
{
	struct nftables_arg *nfta = (struct nftables_arg *)args;

	pr_info("Using newer nft from chroot %s\n", NFT_CHROOT_PATH);

	if (unshare(CLONE_NEWNS)) {
		pr_perror("Unable to create a new mntns");
		return -1;
	}

	if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)) {
		pr_perror("Can't remount \"/\" with MS_PRIVATE");
		return -1;
	}

	if (mount(NFT_CHROOT_PATH, NFT_CHROOT_PATH, NULL, MS_BIND, NULL)) {
		pr_perror("Unable to self bindmount %s", NFT_CHROOT_PATH);
		return -1;
	}

	if (mkdir(NFT_CHROOT_PATH "/proc", 0600) && (errno != EEXIST)) {
		pr_perror("Failed to create %s/proc", NFT_CHROOT_PATH);
		return -1;
	}

	if (mount("/proc", NFT_CHROOT_PATH "/proc", NULL, MS_BIND | MS_REC, NULL)) {
		pr_perror("Unable to bindmount proc to %s/proc", NFT_CHROOT_PATH);
		return -1;
	}

	if (cr_pivot_root(NFT_CHROOT_PATH)) {
		pr_err("Failed to pivot_root to %s\n", NFT_CHROOT_PATH);
		return -1;
	}

	return __run_nftables_tool(nfta->def_cmd, nfta->fdin, nfta->fdout);
}

static int run_nftables_tool(char *def_cmd, int fdin, int fdout)
{
	struct nftables_arg nfta = {
		.def_cmd = def_cmd,
		.fdin = fdin,
		.fdout = fdout,
	};

	return call_in_child_process(ns_run_nftables_tool, (void *)&nfta);
}

static inline int dump_nftables_vz(struct cr_imgset *fds)
{
	struct cr_img *img;

	img = img_from_set(fds, CR_FD_IPTABLES_NFT);
	if (run_nftables_tool("xtables-nft-multi iptables-save", -1, img_raw_fd(img)))
		return -1;

	if (kdat.ipv6) {
		img = img_from_set(fds, CR_FD_IP6TABLES_NFT);
		if (run_nftables_tool("xtables-nft-multi ip6tables-save", -1, img_raw_fd(img)))
			return -1;
	}

	img = img_from_set(fds, CR_FD_NFTABLES);
	if (run_nftables_tool("nft list ruleset", -1, img_raw_fd(img)))
		return -1;

	return 0;
}

/*
 * NFTABLES_MODE_NFT - try to restore nftables with nft tool only, if no image
 * just silently skip in case we restore from really old criu dump.
 * NFTABLES_MODE_IPT - try to restore nftables with iptables-nft tool only,
 * fail if no image.
 * NFTABLES_MODE_ALL - try to restore nftables with both nft and iptables-nft,
 * if one or both succeed we are good.
 */
static inline int restore_nftables_vz(int pid)
{
	int ret, exit_code = -1;
	struct cr_img *img;

	if (opts.nftables_mode == NFTABLES_MODE_IPT)
		goto ipt;

	img = open_image(CR_FD_NFTABLES, O_RSTR, pid);
	if (img == NULL)
		return -1;
	if (empty_image(img)) {
		/* Backward compatibility */
		pr_info("Skipping nft restore, no image\n");
		close_image(img);
		return 0;
	}

	ret = run_nftables_tool("nft -f /proc/self/fd/0", img_raw_fd(img), -1);
	close_image(img);
	if (!ret)
		exit_code = 0;

	if (opts.nftables_mode == NFTABLES_MODE_NFT)
		goto out;
ipt:
	img = open_image(CR_FD_IPTABLES_NFT, O_RSTR, pid);
	if (img == NULL)
		return -1;
	if (empty_image(img)) {
		if (opts.nftables_mode == NFTABLES_MODE_IPT) {
			pr_err("Missing ipt-nft image. Maybe you should not use --nftables-mode=ipt.\n");
			return -1;
		}
		/* Backward compatibility */
		pr_info("Skipping ipt-nft restore, no image\n");
		close_image(img);
		goto out;
	}

	ret = run_nftables_tool("xtables-nft-multi iptables-restore -w", img_raw_fd(img), -1);
	close_image(img);
	if (ret)
		goto out;

	img = open_image(CR_FD_IP6TABLES_NFT, O_RSTR, pid);
	if (img == NULL)
		return -1;
	if (empty_image(img)) {
		pr_err("Missing ip6t-nft image. Try using --nftables-mode=nft.\n");
		return -1;
	}

	ret = run_nftables_tool("xtables-nft-multi ip6tables-restore -w", img_raw_fd(img), -1);
	close_image(img);
	if (!ret)
		exit_code = 0;
out:
	return exit_code;
}

int read_net_ns_img(void)
{
	struct ns_id *ns;

	if (!(root_ns_mask & CLONE_NEWNET))
		return 0;

	for (ns = ns_ids; ns != NULL; ns = ns->next) {
		struct cr_img *img;
		int ret;

		if (ns->nd != &net_ns_desc)
			continue;

		img = open_image(CR_FD_NETNS, O_RSTR, ns->id);
		if (!img)
			return -1;

		if (empty_image(img)) {
			/* Backward compatibility */
			close_image(img);
			continue;
		}

		ret = pb_read_one(img, &ns->net.netns, PB_NETNS);
		close_image(img);
		if (ret < 0) {
			pr_err("Can not read netns object\n");
			return -1;
		}

		if (ns->net.netns->unix_conf && !ns->net.netns->vz_core_conf) {
			/*
			 * Backward compatibility. In vz7-u16 we've rebased
			 * from criu v3.12 to v3.15. So core_confs id in
			 * netns_entry is now used by unix_conf and
			 * vz_core_conf now has new 1000+x id.
			 */
			ns->net.netns->vz_core_conf = ns->net.netns->unix_conf;
			ns->net.netns->n_vz_core_conf = ns->net.netns->n_unix_conf;
			ns->net.netns->unix_conf = NULL;
			ns->net.netns->n_unix_conf = 0;
		}

		ns->ext_key = ns->net.netns->ext_key;
	}

	return 0;
}

static int restore_netns_conf(struct ns_id *ns)
{
	NetnsEntry *netns = ns->net.netns;
	int ret = 0;

	if (ns->net.netns == NULL)
		/* Backward compatibility */
		goto out;

	if ((netns)->def_conf4) {
		ret = ipv4_conf_op("all", (netns)->all_conf4, (netns)->n_all_conf4, CTL_WRITE, NULL);
		if (ret)
			goto out;
		ret = ipv4_conf_op("default", (netns)->def_conf4, (netns)->n_def_conf4, CTL_WRITE, NULL);
		if (ret)
			goto out;
	} else if ((netns)->def_conf) {
		/* Backward compatibility */
		ret = ipv4_conf_op_old("all", (netns)->all_conf, (netns)->n_all_conf, CTL_WRITE, NULL);
		if (ret)
			goto out;
		ret = ipv4_conf_op_old("default", (netns)->def_conf, (netns)->n_def_conf, CTL_WRITE, NULL);
		if (ret)
			goto out;
	}

	if ((netns)->def_conf6) {
		ret = ipv6_conf_op("all", (netns)->all_conf6, (netns)->n_all_conf6, CTL_WRITE, NULL);
		if (ret)
			goto out;
		ret = ipv6_conf_op("default", (netns)->def_conf6, (netns)->n_def_conf6, CTL_WRITE, NULL);
	}

	if ((netns)->unix_conf) {
		ret = unix_conf_op(&(netns)->unix_conf, &(netns)->n_unix_conf, CTL_WRITE);
		if (ret)
			goto out;
	}

	if ((netns)->vz_core_conf) {
		ret = core_conf_op((netns)->vz_core_conf, (netns)->n_vz_core_conf, CTL_WRITE);
		if (ret)
			goto out;
	}

	ns->net.netns = netns;
out:
	return ret;
}

static int mount_ns_sysfs(void)
{
	char sys_mount[] = "crtools-sys.XXXXXX";

	BUG_ON(ns_sysfs_fd != -1);

	if (kdat.has_fsopen) {
		ns_sysfs_fd = mount_detached_fs("sysfs");
		return ns_sysfs_fd >= 0 ? 0 : -1;
	}

	/*
	 * A new mntns is required to avoid the race between
	 * open_detach_mount and creating mntns.
	 */
	if (unshare(CLONE_NEWNS)) {
		pr_perror("Can't create new mount namespace");
		return -1;
	}

	if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL)) {
		pr_perror("Can't mark the root mount as private");
		return -1;
	}

	if (mkdtemp(sys_mount) == NULL) {
		pr_perror("mkdtemp failed %s", sys_mount);
		return -1;
	}

	/*
	 * The setns() is called, so we're in proper context,
	 * no need in pulling the mountpoint from parasite.
	 */
	pr_info("Mount ns' sysfs in %s\n", sys_mount);
	if (mount("sysfs", sys_mount, "sysfs", MS_MGC_VAL, NULL)) {
		pr_perror("mount failed");
		rmdir(sys_mount);
		return -1;
	}

	ns_sysfs_fd = open_detach_mount(sys_mount);
	return ns_sysfs_fd >= 0 ? 0 : -1;
}

struct net_id_arg {
	struct ns_id *ns;
	int sk;
};

static int __net_get_nsid(int rtsk, int pid, int fd, int *nsid);

static int collect_netns_id(struct ns_id *ns, void *oarg)
{
	struct net_id_arg *arg = oarg;
	struct netns_id *netns_id;
	int nsid = -1;

	if (ns->ns_fd == -1) {
		if (net_get_nsid(arg->sk, ns->ns_pid, &nsid))
			return -1;
	} else {
		if (__net_get_nsid(arg->sk, 0, ns->ns_fd, &nsid))
			return -1;
	}

	if (nsid == -1)
		return 0;

	netns_id = xmalloc(sizeof(*netns_id));
	if (!netns_id)
		return -1;

	pr_debug("Found the %d id for %d in %d\n", nsid, ns->id, arg->ns->id);
	netns_id->target_ns_id = ns->id;
	netns_id->netnsid_value = nsid;

	list_add(&netns_id->node, &arg->ns->net.ids);

	return 0;
}

static int dump_netns_ids(int rtsk, struct ns_id *ns)
{
	struct net_id_arg arg = {
		.ns = ns,
		.sk = rtsk,
	};
	return walk_namespaces(&net_ns_desc, collect_netns_id, (void *)&arg);
}

int net_set_ext(struct ns_id *ns)
{
	int fd, ret;

	fd = inherit_fd_lookup_id(ns->ext_key);
	if (fd < 0) {
		pr_err("Unable to find an external netns: %s\n", ns->ext_key);
		return -1;
	}

	ret = switch_ns_by_fd(fd, &net_ns_desc, NULL);
	close(fd);

	return ret;
}

int dump_net_ns(struct ns_id *ns)
{
	struct cr_imgset *fds;
	int ret = -1;

	if (fill_ovs_layout())
		return -1;

	if (fini_dump_sockets(ns))
		goto out_ovs;

	fds = cr_imgset_open(ns->id, NETNS, O_DUMP);
	if (fds == NULL)
		goto out_ovs;

	ret = mount_ns_sysfs();
	if (ns->ext_key) {
		NetnsEntry netns = NETNS_ENTRY__INIT;

		netns.ext_key = ns->ext_key;
		ret = pb_write_one(img_from_set(fds, CR_FD_NETNS), &netns, PB_NETNS);
		if (ret)
			goto out;
	} else if (!(opts.empty_ns & CLONE_NEWNET)) {
		int sk;

		sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
		if (sk < 0) {
			pr_perror("Can't open rtnl sock for net dump");
			ret = -1;
		}

		/*
		 * If a device has a pair in another netns, the kernel generates
		 * a netns ID for this netns when we request information about
		 * the link.
		 * So we need to get information about all links to be sure that
		 * all related net namespaces have got netns id-s in this netns.
		 */
		if (!ret)
			ret = list_links(sk, NULL);
		if (!ret)
			ret = dump_netns_ids(sk, ns);
		if (!ret)
			ret = dump_links(sk, ns, fds);

		close_safe(&sk);

		if (!ret)
			ret = dump_ifaddr(fds);
		if (!ret)
			ret = dump_route(fds);
		if (!ret)
			ret = dump_rule(fds);
		if (!ret)
			ret = dump_ipset(fds);
		if (!ret)
			ret = dump_iptables(fds);
		if (!opts.ve) {
#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
			if (!ret)
				ret = dump_nftables(fds);
#endif
		} else {
			if (!ret)
				ret = dump_nftables_vz(fds);
		}
		if (!ret)
			ret = dump_netns_conf(ns, fds);
	} else if (ns->type != NS_ROOT) {
		pr_err("Unable to dump more than one netns if the --emptyns is set\n");
		ret = -1;
	}
	if (!ret)
		ret = dump_nf_ct(fds, CR_FD_NETNF_CT);
	if (!ret)
		ret = dump_nf_ct(fds, CR_FD_NETNF_EXP);

out:
	close(ns_sysfs_fd);
	ns_sysfs_fd = -1;

	close_cr_imgset(&fds);

out_ovs:
	free_ovs_layout();

	return ret;
}

static int net_set_nsid(int rtsk, int fd, int nsid);
static int restore_netns_ids(struct ns_id *ns)
{
	int i, sk, exit_code = -1;

	if (!ns->net.netns)
		return 0;

	sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sk < 0) {
		pr_perror("Can't open rtnl sock for net dump");
		return -1;
	}

	for (i = 0; i < ns->net.netns->n_nsids; i++) {
		struct ns_id *tg_ns;
		struct netns_id *id;

		id = xmalloc(sizeof(*id));
		if (!id)
			goto out;
		id->target_ns_id = ns->net.netns->nsids[i]->target_ns_id;
		id->netnsid_value = ns->net.netns->nsids[i]->netnsid_value;
		list_add(&id->node, &ns->net.ids);

		tg_ns = lookup_ns_by_id(id->target_ns_id, &net_ns_desc);
		if (tg_ns == NULL) {
			pr_err("Unknown namespace: %d\n", id->target_ns_id);
			goto out;
		}

		if (net_set_nsid(sk, tg_ns->ns_fd, id->netnsid_value))
			goto out;
	}

	exit_code = 0;
out:
	close(sk);

	return exit_code;
}

static int prepare_net_ns_first_stage(struct ns_id *ns)
{
	int ret = 0;

	if (ns->ext_key || (opts.empty_ns & CLONE_NEWNET))
		return 0;

	ret = restore_netns_conf(ns);
	if (!ret)
		ret = restore_netns_ids(ns);
	if (!ret)
		ret = read_links(ns);

	return ret;
}

static int prepare_net_ns_second_stage(struct ns_id *ns)
{
	int ret = 0, nsid = ns->id;

	if (!(opts.empty_ns & CLONE_NEWNET) && !ns->ext_key) {
		if (ns->net.netns)
			netns_entry__free_unpacked(ns->net.netns, NULL);

		if (!ret)
			ret = restore_ifaddr(nsid);
		if (!ret)
			ret = restore_route(nsid);
		if (!ret)
			ret = restore_rule(nsid);
		if (!ret)
			ret = restore_ipset(nsid);
		if (!ret)
			ret = restore_iptables(nsid);
		if (!opts.ve) {
			if (!ret)
				ret = restore_nftables(nsid);
		} else {
			if (!ret)
				ret = restore_nftables_vz(nsid);
		}
	}

	if (!ret)
		ret = restore_nf_ct(nsid, CR_FD_NETNF_CT);
	if (!ret)
		ret = restore_nf_ct(nsid, CR_FD_NETNF_EXP);

	if (!ret) {
		int fd = ns->ns_fd;

		ns->nsfd_id = fdstore_add(fd);
		if (ns->nsfd_id < 0)
			ret = -1;
		close(fd);
	}

	ns->ns_populated = true;

	return ret;
}

static int open_net_ns(struct ns_id *nsid)
{
	int fd;

	/* Pin one with a file descriptor */
	fd = open_proc(PROC_SELF, "ns/net");
	if (fd < 0)
		return -1;
	nsid->ns_fd = fd;

	return 0;
}

static int do_create_net_ns(struct ns_id *ns)
{
	int ret;

	if (ns->ext_key)
		ret = net_set_ext(ns);
	else
		ret = unshare(CLONE_NEWNET);

	if (ret) {
		pr_perror("Unable to create a new netns");
		return -1;
	}
	if (open_net_ns(ns))
		return -1;
	return 0;
}

struct net_create_arg {
	struct ns_id *uns;
	int root_nsfd;
};

static int __create_net_namespaces(void *arg)
{
	struct net_create_arg *nca = (struct net_create_arg *)arg;
	struct ns_id *uns = nca->uns, *netns;

	if (uns && uns != root_user_ns) {
		int ufd;

		ufd = fdstore_get(uns->user.nsfd_id);
		if (ufd < 0) {
			pr_err("Can't get user ns %d\n", uns->id);
			return 1;
		}

		if (setns(ufd, CLONE_NEWUSER) < 0) {
			pr_perror("Can't set user ns %d", uns->id);
			close(ufd);
			return 1;
		}

		close(ufd);

		if (prepare_userns_creds() < 0) {
			pr_err("Can't prepare creds\n");
			return 1;
		}
	}

	/* Pin one with a file descriptor */
	for (netns = ns_ids; netns != NULL; netns = netns->next) {
		if (netns->nd != &net_ns_desc)
			continue;
		if (netns->user_ns != uns)
			continue;

		if (netns->type == NS_ROOT) {
			netns->ns_fd = nca->root_nsfd;
		} else {
			if (do_create_net_ns(netns))
				return 1;
		}
	}

	return 0;
}

static int __prepare_net_namespaces(void *arg)
{
	struct ns_id *nsid;

	if (prepare_xtable_lock())
		return 1;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &net_ns_desc)
			continue;

		if (switch_ns_by_fd(nsid->ns_fd, &net_ns_desc, NULL))
			goto err;

		if (prepare_net_ns_first_stage(nsid))
			goto err;

		nsid->net.nlsk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
		if (nsid->net.nlsk < 0) {
			pr_perror("Can't create nlk socket");
			goto err;
		}

		nsid->net.genlsk = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
		if (nsid->net.genlsk < 0) {
			pr_perror("Can't open generic netlink socket");
			goto err;
		}
	}

	if (restore_links())
		goto err;

	for (nsid = ns_ids; nsid != NULL; nsid = nsid->next) {
		if (nsid->nd != &net_ns_desc)
			continue;

		if (switch_ns_by_fd(nsid->ns_fd, &net_ns_desc, NULL))
			goto err;

		if (prepare_net_ns_second_stage(nsid))
			goto err;

		close_safe(&nsid->net.nlsk);
		close_safe(&nsid->net.genlsk);
	}

	close_service_fd(NS_FD_OFF);

	return 0;
err:
	return 1;
}

int prepare_net_namespaces(void)
{
	struct net_create_arg nca;
	struct ns_id *uns;

	if (!(root_ns_mask & CLONE_NEWNET))
		return 0;

	nca.root_nsfd = open_proc(PROC_SELF, "ns/net");
	if (nca.root_nsfd < 0)
		return -1;

	if ((root_ns_mask & CLONE_NEWUSER)) {
		for (uns = ns_ids; uns != NULL; uns = uns->next) {
			if (uns->nd != &user_ns_desc)
				continue;
			nca.uns = uns;
			if (call_in_child_process(__create_net_namespaces, (void *)&nca))
				return -1;
		}
	}

	/* Create netnses with current userns owner for !CLONE_NEWUSER or old criu image */
	nca.uns = NULL;
	if (call_in_child_process(__create_net_namespaces, (void *)&nca))
		return -1;

	return call_in_child_process(__prepare_net_namespaces, NULL);
}

static int do_restore_task_net_ns(struct ns_id *nsid, struct pstree_item *current)
{
	int fd;

	if (!(root_ns_mask & CLONE_NEWNET))
		return 0;

	fd = fdstore_get(nsid->nsfd_id);
	if (fd < 0)
		return -1;

	if (setns(fd, CLONE_NEWNET)) {
		pr_perror("Can't restore netns");
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

int restore_task_net_ns(struct pstree_item *current)
{
	unsigned int id = current->ids->net_ns_id;
	struct ns_id *nsid;

	nsid = lookup_ns_by_id(id, &net_ns_desc);
	if (nsid == NULL) {
		pr_err("Can't find mount namespace %d\n", id);
		return -1;
	}

	BUG_ON(nsid->type == NS_CRIU);

	if (do_restore_task_net_ns(nsid, current))
		return -1;

	return 0;
}

int netns_keep_nsfd(void)
{
	int ns_fd, ret;

	if (!(root_ns_mask & CLONE_NEWNET))
		return 0;

	/*
	 * When restoring a net namespace we need to communicate
	 * with the original (i.e. -- init) one. Thus, prepare for
	 * that before we leave the existing namespaces.
	 */

	ns_fd = __open_proc(PROC_SELF, 0, O_RDONLY | O_CLOEXEC, "ns/net");
	if (ns_fd < 0)
		return -1;

	ret = install_service_fd(NS_FD_OFF, ns_fd);
	if (ret < 0)
		pr_err("Can't install ns net reference\n");
	else
		pr_info("Saved netns fd for links restore\n");

	return ret >= 0 ? 0 : -1;
}

struct ipt_restore_arg {
	bool ipv6;
	char *buf;
	int size;
};

/*
 * If we want to modify iptables, we need to received the current
 * configuration, change it and load a new one into the kernel.
 * iptables can change or add only one rule.
 * iptables-restore allows to make a few changes for one iteration,
 * so it works faster.
 */
int __iptables_restore(void *arg)
{
	struct ipt_restore_arg *iptra = (struct ipt_restore_arg *)arg;
	int pfd[2], ret = -1;
	char *cmd4[] = { "iptables-restore", "-w", "--noflush", NULL };
	char *cmd6[] = { "ip6tables-restore", "-w", "--noflush", NULL };
	char **cmd = iptra->ipv6 ? cmd6 : cmd4;
	int userns_pid = -1;

	if (pipe(pfd) < 0) {
		pr_perror("Unable to create pipe");
		return -1;
	}

	if (write(pfd[1], iptra->buf, iptra->size) < iptra->size) {
		pr_perror("Unable to write iptables configugration");
		goto err;
	}
	close_safe(&pfd[1]);

	/*
	 * In nested netns we don't want to messup with host's xtables lock,
	 * so we create new mntns (safe as we are in fork) with overmounted
	 * host's xtables lock.
	 */
	if (__prepare_xtable_lock())
		goto err;

	/*
	 * iptables-restore has to be executed in a userns owner of network
	 * namespace, otherwise the kernel can return an error. One of these
	 * checks is in xt_owner.c:owner_check().
	 */
	if (root_ns_mask & CLONE_NEWUSER)
		userns_pid = root_item->pid->real;

	ret = cr_system_userns(pfd[0], -1, -1, cmd[0], cmd, 0, userns_pid);
err:
	close_safe(&pfd[1]);
	close_safe(&pfd[0]);
	return ret;
}

static int iptables_restore(bool ipv6, char *buf, int size)
{
	struct ipt_restore_arg iptra = {
		.ipv6 = ipv6,
		.buf = buf,
		.size = size
	};

	return call_in_child_process(__iptables_restore, (void *)&iptra);
}

static inline int nftables_lock_network_internal(void)
{
#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
	struct nft_ctx *nft;
	int ret = 0;
	char table[32];
	char buf[128];

	if (nftables_get_table(table, sizeof(table)))
		return -1;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return -1;

	snprintf(buf, sizeof(buf), "create table %s", table);
	if (NFT_RUN_CMD(nft, buf))
		goto err2;

	snprintf(buf, sizeof(buf), "add chain %s output { type filter hook output priority 0; policy drop; }", table);
	if (NFT_RUN_CMD(nft, buf))
		goto err1;

	snprintf(buf, sizeof(buf), "add rule %s output meta mark " __stringify(SOCCR_MARK) " accept", table);
	if (NFT_RUN_CMD(nft, buf))
		goto err1;

	snprintf(buf, sizeof(buf), "add chain %s input { type filter hook input priority 0; policy drop; }", table);
	if (NFT_RUN_CMD(nft, buf))
		goto err1;

	snprintf(buf, sizeof(buf), "add rule %s input meta mark " __stringify(SOCCR_MARK) " accept", table);
	if (NFT_RUN_CMD(nft, buf))
		goto err1;

	goto out;

err1:
	snprintf(buf, sizeof(buf), "delete table %s", table);
	NFT_RUN_CMD(nft, buf);
err2:
	ret = -1;
	pr_err("Locking network failed using nftables\n");
out:
	nft_ctx_free(nft);
	return ret;
#else
	pr_err("CRIU was built without libnftables support\n");
	return -1;
#endif
}

static int iptables_network_lock_internal(void)
{
	char conf[] = "*filter\n"
		      ":CRIU - [0:0]\n"
		      "-I INPUT -j CRIU\n"
		      "-I OUTPUT -j CRIU\n"
		      "-A CRIU -m mark --mark " __stringify(SOCCR_MARK) " -j ACCEPT\n"
									"-A CRIU -j DROP\n"
									"COMMIT\n";
	int ret = 0;

	ret |= iptables_restore(false, conf, sizeof(conf) - 1);
	if (kdat.ipv6)
		ret |= iptables_restore(true, conf, sizeof(conf) - 1);

	if (ret)
		pr_err("Locking network failed: iptables-restore returned %d. "
		       "This may be connected to disabled "
		       "CONFIG_NETFILTER_XT_MARK kernel build config "
		       "option.\n",
		       ret);

	return ret;
}

int network_lock_internal(void)
{
	int ret = 0, nsret;

	if (switch_ns(root_item->pid->real, &net_ns_desc, &nsret))
		return -1;

	if (opts.network_lock_method == NETWORK_LOCK_IPTABLES)
		ret = iptables_network_lock_internal();
	else if (opts.network_lock_method == NETWORK_LOCK_NFTABLES)
		ret = nftables_lock_network_internal();

	if (restore_ns(nsret, &net_ns_desc))
		ret = -1;

	return ret;
}

static inline int nftables_network_unlock(void)
{
#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
	int ret = 0;
	struct nft_ctx *nft;
	char table[32];
	char buf[128];

	if (nftables_get_table(table, sizeof(table)))
		return -1;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return -1;

	snprintf(buf, sizeof(buf), "delete table %s", table);
	if (NFT_RUN_CMD(nft, buf))
		ret = -1;

	nft_ctx_free(nft);
	return ret;
#else
	pr_err("CRIU was built without libnftables support\n");
	return -1;
#endif
}

static int iptables_network_unlock_internal(void)
{
	char conf[] = "*filter\n"
		      ":CRIU - [0:0]\n"
		      "-D INPUT -j CRIU\n"
		      "-D OUTPUT -j CRIU\n"
		      "-X CRIU\n"
		      "COMMIT\n";
	int ret = 0;

	ret |= iptables_restore(false, conf, sizeof(conf) - 1);
	if (kdat.ipv6)
		ret |= iptables_restore(true, conf, sizeof(conf) - 1);

	return ret;
}

static int network_unlock_internal(void)
{
	int ret = 0, nsret;

	if (switch_ns(root_item->pid->real, &net_ns_desc, &nsret))
		return -1;

	if (opts.network_lock_method == NETWORK_LOCK_IPTABLES)
		ret = iptables_network_unlock_internal();
	else if (opts.network_lock_method == NETWORK_LOCK_NFTABLES)
		ret = nftables_network_unlock();

	if (restore_ns(nsret, &net_ns_desc))
		ret = -1;

	return ret;
}

int network_lock(void)
{
	pr_info("Lock network\n");

	/* Each connection will be locked on dump */
	if (!(root_ns_mask & CLONE_NEWNET)) {
		if (opts.network_lock_method == NETWORK_LOCK_NFTABLES)
			nftables_init_connection_lock();
		return 0;
	}

	if (run_scripts(ACT_NET_LOCK))
		return -1;

	if (network_lock_internal())
		return -1;
	return run_scripts(ACT_POST_NET_LOCK);
}

void network_unlock(void)
{
	pr_info("Unlock network\n");

	cpt_unlock_tcp_connections();
	rst_unlock_tcp_connections();

	if (root_ns_mask & CLONE_NEWNET) {
		/* coverity[check_return] */
		run_scripts(ACT_NET_UNLOCK);
		network_unlock_internal();
	} else if (opts.network_lock_method == NETWORK_LOCK_NFTABLES) {
		nftables_network_unlock();
	}
}

int veth_pair_add(char *in, char *out)
{
	cleanup_free char *e_str = NULL;

	e_str = xmalloc(200); /* For 3 IFNAMSIZ + 8 service characters */
	if (!e_str)
		return -1;
	snprintf(e_str, 200, "veth[%s]:%s", in, out);
	return add_external(e_str);
}

int macvlan_ext_add(struct external *ext)
{
	ext->data = (void *)(unsigned long)if_nametoindex(external_val(ext));
	if (ext->data == 0) {
		pr_perror("can't get ifindex of %s", ext->id);
		return -1;
	}

	return 0;
}

/*
 * The setns() syscall (called by switch_ns()) can be extremely
 * slow. If we call it two or more times from the same task the
 * kernel will synchonously go on a very slow routine called
 * synchronize_rcu() trying to put a reference on old namespaces.
 *
 * To avoid doing this more than once we pre-create all the
 * needed other-ns sockets in advance.
 */

static int prep_ns_sockets(struct ns_id *ns, bool for_dump)
{
	int nsret = -1, ret;
#ifdef CONFIG_HAS_SELINUX
	char *ctx;
#endif

	if (ns->type != NS_CRIU) {
		pr_info("Switching to %d's net for collecting sockets\n", ns->ns_pid);
		if (ns->ns_fd == -1) {
			if (switch_ns(ns->ns_pid, &net_ns_desc, &nsret))
				return -1;
		} else {
			if (switch_ns_by_fd(ns->ns_fd, &net_ns_desc, &nsret))
				return -1;
		}
	}

	if (for_dump) {
		ret = ns->net.nlsk = socket(PF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
		if (ret < 0) {
			pr_perror("Can't create sock diag socket");
			goto err_nl;
		}
	} else
		ns->net.nlsk = -1;

#ifdef CONFIG_HAS_SELINUX
	/*
	 * If running on a system with SELinux enabled the socket for the
	 * communication between parasite daemon and the main
	 * CRIU process needs to be correctly labeled.
	 * Initially this was motivated by Podman's use case: The container
	 * is usually running as something like '...:...:container_t:...:....'
	 * and CRIU started from runc and Podman will run as
	 * '...:...:container_runtime_t:...:...'. As the parasite will be
	 * running with the same context as the container process: 'container_t'.
	 * Allowing a container process to connect via socket to the outside
	 * of the container ('container_runtime_t') is not desired and
	 * therefore CRIU needs to label the socket with the context of
	 * the container: 'container_t'.
	 * So this first gets the context of the root container process
	 * and tells SELinux to label the next created socket with
	 * the same label as the root container process.
	 * For this to work it is necessary to have the correct SELinux
	 * policies installed. For Fedora based systems this is part
	 * of the container-selinux package.
	 */

	/*
	 * This assumes that all processes CRIU wants to dump are labeled
	 * with the same SELinux context. If some of the child processes
	 * have different labels this will not work and needs additional
	 * SELinux policies. But the whole SELinux socket labeling relies
	 * on the correct SELinux being available.
	 */
	if (kdat.lsm == LSMTYPE__SELINUX) {
		ret = getpidcon_raw(root_item->pid->real, &ctx);
		if (ret < 0) {
			pr_perror("Getting SELinux context for PID %d failed", root_item->pid->real);
			goto err_sq;
		}

		ret = setsockcreatecon(ctx);
		freecon(ctx);
		if (ret < 0) {
			pr_perror("Setting SELinux socket context for PID %d failed", root_item->pid->real);
			goto err_sq;
		}
	}
#endif

	ret = ns->net.seqsk = socket(PF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
	if (ret < 0) {
		pr_perror("Can't create seqsk for parasite");
		goto err_sq;
	}

	ret = 0;

#ifdef CONFIG_HAS_SELINUX
	/*
	 * Once the socket has been created, reset the SELinux socket labelling
	 * back to the default value of this process.
	 */
	if (kdat.lsm == LSMTYPE__SELINUX) {
		ret = setsockcreatecon_raw(NULL);
		if (ret < 0) {
			pr_perror("Resetting SELinux socket context to "
				  "default for PID %d failed",
				  root_item->pid->real);
			goto err_ret;
		}
	}
#endif

out:
	if (nsret >= 0 && restore_ns(nsret, &net_ns_desc) < 0) {
		nsret = -1;
		if (ret == 0)
			goto err_ret;
	}

	return ret;

err_ret:
	close(ns->net.seqsk);
err_sq:
	if (ns->net.nlsk >= 0)
		close(ns->net.nlsk);
err_nl:
	goto out;
}

static int netns_nr;
static int collect_net_ns(struct ns_id *ns, void *oarg)
{
	bool for_dump = (oarg == (void *)1);
	char id[64], *val;
	int ret;

	pr_info("Collecting netns %d/%d\n", ns->id, ns->ns_pid);

	snprintf(id, sizeof(id), "net[%u]", ns->kid);
	val = external_lookup_by_key(id);
	if (!IS_ERR_OR_NULL(val)) {
		pr_debug("The %s netns is external\n", id);
		ns->ext_key = val;
	}

	ret = prep_ns_sockets(ns, for_dump);
	if (ret)
		return ret;

	netns_nr++;

	if (!for_dump)
		return 0;

	return collect_sockets(ns);
}

int collect_net_namespaces(bool for_dump)
{
	fill_genl_families();

	return walk_namespaces(&net_ns_desc, collect_net_ns, (void *)(for_dump ? 1UL : 0));
}

struct ns_desc net_ns_desc = NS_DESC_ENTRY(CLONE_NEWNET, "net", NULL);

struct ns_id *net_get_root_ns(void)
{
	static struct ns_id *root_netns = NULL;

	if (root_netns)
		return root_netns;

	if (root_item->ids == NULL)
		return NULL;

	root_netns = lookup_ns_by_id(root_item->ids->net_ns_id, &net_ns_desc);

	return root_netns;
}

/*
 * socket_diag doesn't report unbound and unconnected sockets,
 * so we have to get their network namesapces explicitly
 */
struct ns_id *get_socket_ns(int lfd)
{
	struct ns_id *ns;
	struct stat st;
	int ns_fd;

	ns_fd = ioctl(lfd, SIOCGSKNS);
	if (ns_fd < 0) {
		/* backward compatibility with old kernels */
		if (netns_nr == 1)
			return net_get_root_ns();

		pr_perror("Unable to get a socket net namespace");
		return NULL;
	}
	if (fstat(ns_fd, &st)) {
		pr_perror("Unable to stat a network namespace");
		close(ns_fd);
		return NULL;
	}
	close(ns_fd);

	ns = lookup_ns_by_kid(st.st_ino, &net_ns_desc);
	if (ns == NULL) {
		pr_err("Unable to dump a socket from an external network namespace\n");
		return NULL;
	}

	return ns;
}

void check_has_netns_ioc(int fd, bool *kdat_val, const char *name)
{
	int ns_fd;

	ns_fd = ioctl(fd, SIOCGSKNS);
	*kdat_val = (ns_fd >= 0);

	if (ns_fd < 0)
		pr_warn("Unable to get %s network namespace\n", name);
	else
		close(ns_fd);
}

int kerndat_socket_netns(void)
{
	int sk;

	sk = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sk < 0) {
		pr_perror("Unable to create socket");
		return -1;
	}
	check_has_netns_ioc(sk, &kdat.sk_ns, "socket");
	close(sk);

	return 0;
}

static int move_to_bridge(struct external *ext, void *arg)
{
	int s = *(int *)arg;
	int ret;
	char *out, *br;
	struct ifreq ifr;

	out = external_val(ext);
	if (!out)
		return -1;

	br = strchr(out, '@');
	if (!br)
		return 0;

	*br = '\0';
	br++;

	{
		pr_debug("\tMoving dev %s to bridge %s\n", out, br);

		if (s == -1) {
			s = socket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
			if (s < 0) {
				pr_perror("Can't create control socket");
				return -1;
			}
		}

		/*
		 * Add the device to the bridge. This is equivalent to:
		 * $ brctl addif <bridge> <device>
		 */
		ifr.ifr_ifindex = if_nametoindex(out);
		if (ifr.ifr_ifindex == 0) {
			pr_perror("Can't get index of %s", out);
			ret = -1;
			goto out;
		}
		__strlcpy(ifr.ifr_name, br, IFNAMSIZ);
		ret = ioctl(s, SIOCBRADDIF, &ifr);
		if (ret < 0) {
			pr_perror("Can't add interface %s to bridge %s", out, br);
			goto out;
		}

		/*
		 * Make sure the device is up.  This is equivalent to:
		 * $ ip link set dev <device> up
		 */
		ifr.ifr_ifindex = 0;
		__strlcpy(ifr.ifr_name, out, IFNAMSIZ);
		ret = ioctl(s, SIOCGIFFLAGS, &ifr);
		if (ret < 0) {
			pr_perror("Can't get flags of interface %s", out);
			goto out;
		}

		ret = 0;
		if (ifr.ifr_flags & IFF_UP)
			goto out;

		ifr.ifr_flags |= IFF_UP;
		if (changeflags(s, out, ifr.ifr_flags) < 0)
			goto out;
		ret = 0;
	}
out:
	br--;
	*br = '@';
	*(int *)arg = s;
	return ret;
}

int move_veth_to_bridge(void)
{
	int sk = -1, ret;

	ret = external_for_each_type("veth", move_to_bridge, &sk);
	if (sk >= 0)
		close(sk);

	return ret;
}

#if NLA_TYPE_MAX < 14
#define NLA_S32 14
#endif

#ifndef NETNSA_MAX
/* Attributes of RTM_NEWNSID/RTM_GETNSID messages */
enum {
	NETNSA_NONE,
#define NETNSA_NSID_NOT_ASSIGNED -1
	NETNSA_NSID,
	NETNSA_PID,
	NETNSA_FD,
	__NETNSA_MAX,
};

#define NETNSA_MAX (__NETNSA_MAX - 1)
#endif

static struct nla_policy rtnl_net_policy[NETNSA_MAX + 1] = {
	[NETNSA_NONE] = { .type = NLA_UNSPEC },
	[NETNSA_NSID] = { .type = NLA_S32 },
	[NETNSA_PID] = { .type = NLA_U32 },
	[NETNSA_FD] = { .type = NLA_U32 },
};

static int nsid_cb(struct nlmsghdr *msg, struct ns_id *ns, void *arg)
{
	struct nlattr *tb[NETNSA_MAX + 1];
	int err;

	err = nlmsg_parse(msg, sizeof(struct rtgenmsg), tb, NETNSA_MAX, rtnl_net_policy);
	if (err < 0)
		return NL_STOP;

	if (tb[NETNSA_NSID])
		*((int *)arg) = nla_get_s32(tb[NETNSA_NSID]);

	return 0;
}

static int net_set_nsid(int rtsk, int fd, int nsid)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
		char msg[128];
	} req;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	req.nlh.nlmsg_type = RTM_NEWNSID;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	if (addattr_l(&req.nlh, sizeof(req), NETNSA_FD, &fd, sizeof(fd)))
		return -1;
	if (addattr_l(&req.nlh, sizeof(req), NETNSA_NSID, &nsid, sizeof(nsid)))
		return -1;

	if (do_rtnl_req(rtsk, &req, req.nlh.nlmsg_len, NULL, NULL, NULL, NULL) < 0)
		return -1;

	return 0;
}

static int __net_get_nsid(int rtsk, int pid, int fd, int *nsid)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
		char msg[128];
	} req;
	int32_t id = INT_MIN;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	req.nlh.nlmsg_type = RTM_GETNSID;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	if (fd == -1) {
		if (addattr_l(&req.nlh, sizeof(req), NETNSA_PID, &pid, sizeof(pid)))
			return -1;
	} else {
		if (addattr_l(&req.nlh, sizeof(req), NETNSA_FD, &fd, sizeof(fd)))
			return -1;
	}

	if (do_rtnl_req(rtsk, &req, req.nlh.nlmsg_len, nsid_cb, NULL, NULL, (void *)&id) < 0)
		return -1;

	if (id == INT_MIN)
		return -1;

	*nsid = id;

	return 0;
}

int net_get_nsid(int rtsk, int pid, int *nsid)
{
	return __net_get_nsid(rtsk, pid, -1, nsid);
}

static int nsid_link_info(struct ns_id *ns, struct net_link *link, struct newlink_req *req)
{
	NetDeviceEntry *nde = link->nde;
	struct rtattr *veth_data, *peer_data;
	struct ifinfomsg ifm;

	addattr_l(&req->h, sizeof(*req), IFLA_INFO_KIND, "veth", 4);

	veth_data = NLMSG_TAIL(&req->h);
	addattr_l(&req->h, sizeof(*req), IFLA_INFO_DATA, NULL, 0);
	peer_data = NLMSG_TAIL(&req->h);
	memset(&ifm, 0, sizeof(ifm));

	ifm.ifi_index = nde->peer_ifindex;
	addattr_l(&req->h, sizeof(*req), VETH_INFO_PEER, &ifm, sizeof(ifm));

	addattr_l(&req->h, sizeof(*req), IFLA_NET_NS_FD, &nde->peer_nsid, sizeof(int));
	peer_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)peer_data;
	veth_data->rta_len = (void *)NLMSG_TAIL(&req->h) - (void *)veth_data;

	return 0;
}

static int check_one_link_nsid(struct nlmsghdr *hdr, struct ns_id *ns, void *arg)
{
	bool *has_link_nsid = arg;
	struct ifinfomsg *ifi;
	int len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	struct nlattr *tb[IFLA_MAX + 1];

	ifi = NLMSG_DATA(hdr);

	if (len < 0) {
		pr_err("No iflas for link %d\n", ifi->ifi_index);
		return -1;
	}

	nlmsg_parse(hdr, sizeof(struct ifinfomsg), tb, IFLA_MAX, NULL);
	pr_info("\tLD: Got link %d, type %d\n", ifi->ifi_index, ifi->ifi_type);

	if (tb[IFLA_LINK_NETNSID])
		*has_link_nsid = true;

	return 0;
}

static int check_link_nsid(int rtsk, void *args)
{
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	pr_info("Dumping netns links\n");

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETLINK;
	req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	req.g.rtgen_family = AF_PACKET;

	return do_rtnl_req(rtsk, &req, sizeof(req), check_one_link_nsid, NULL, NULL, args);
}

int kerndat_link_nsid(void)
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		pr_perror("Unable to fork a process");
		return -1;
	}

	if (pid == 0) {
		bool has_link_nsid;
		NetDeviceEntry nde = NET_DEVICE_ENTRY__INIT;
		struct net_link link = {
			.created = false,
			.nde = &nde,
		};
		int nsfd, sk, ret;

		if (unshare(CLONE_NEWNET)) {
			pr_perror("Unable create a network namespace");
			exit(1);
		}

		nsfd = open_proc(PROC_SELF, "ns/net");
		if (nsfd < 0)
			exit(1);

		if (unshare(CLONE_NEWNET)) {
			pr_perror("Unable create a network namespace");
			exit(1);
		}

		sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
		if (sk < 0) {
			pr_perror("Unable to create a netlink socket");
			exit(1);
		}

		nde.type = ND_TYPE__VETH;
		nde.name = "veth";
		nde.ifindex = 10;
		nde.mtu = 1500;
		nde.peer_nsid = nsfd;
		nde.peer_ifindex = 11;
		nde.has_peer_ifindex = true;
		nde.has_peer_nsid = true;

		ret = restore_one_link(NULL, &link, sk, nsid_link_info, NULL);
		if (ret) {
			pr_err("Unable to create a veth pair: %d\n", ret);
			exit(1);
		}

		has_link_nsid = false;
		if (check_link_nsid(sk, &has_link_nsid)) {
			pr_err("check_link_nsid failed\n");
			exit(1);
		}

		if (!has_link_nsid) {
			pr_err("check_link_nsid succeeded but has_link_nsid is false\n");
			exit(5);
		}

		close(sk);

		exit(0);
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Unable to wait a process");
		return -1;
	}

	if (status) {
		pr_warn("NSID isn't reported for network links\n");
		return 0;
	}

	kdat.has_link_nsid = true;

	return 0;
}

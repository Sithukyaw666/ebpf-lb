//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "parse_helpers.h"

#define NUM_BACKENDS 2
#define ETH_ALEN 6
#define AF_INET 2

// upstream_server_ips
struct endpoints {
  __u32 ip;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, NUM_BACKENDS);
  __type(key, __u32);
  __type(value, struct endpoints);
} backends SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct endpoints);
} load_balancer SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} rr_state SEC(".maps");

// 4-tuple key for per-connection backend pinning
struct conn_key {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
};

// LRU hash: connection -> backend index
// LRU automatically evicts oldest entry when full, no explicit TTL needed
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct conn_key);
  __type(value, __u32);
} conntrack SEC(".maps");

// return next backend index via round-robin
static __always_inline int get_next_backend_idx(__u32 *out_idx) {
  __u32 key = 0;
  __u32 *last_idx = bpf_map_lookup_elem(&rr_state, &key);
  if (!last_idx)
    return -1;
  *out_idx = (*last_idx) % NUM_BACKENDS;
  __sync_fetch_and_add(last_idx, 1);
  return 0;
}
// check the error type at
// https://github.com/torvalds/linux/blob/e774d5f1bc27a85f858bce7688509e866f8e8a4e/include/uapi/linux/bpf.h#L7300

static __always_inline void log_fib_error(int rc) {
  switch (rc) {
  case BPF_FIB_LKUP_RET_BLACKHOLE:
    bpf_printk("FIB lookup failed: BLACKHOLE route. Check 'ip r'.");
    break;
  case BPF_FIB_LKUP_RET_UNREACHABLE:
    bpf_printk("FIB lookup failed: UNREACHABLE route.");
    break;
  case BPF_FIB_LKUP_RET_PROHIBIT:
    bpf_printk("FIB lookup failed: PROHIBITED route.");
    break;
  case BPF_FIB_LKUP_RET_NOT_FWDED:
    bpf_printk("FIB lookup failed: NOT_FORWARDED route. Destination might be "
               "on same subnet");
    break;
  case BPF_FIB_LKUP_RET_FWD_DISABLED:
    bpf_printk("FIB lookup failed: FORWARDING_DISABLED. Enable via sysctl");
    break;
  case BPF_FIB_LKUP_RET_UNSUPP_LWT:
    bpf_printk(
        "FIB lookup failed: UNSUPPORTED_PACKET. fwd requires encapsulation");
    break;
  case BPF_FIB_LKUP_RET_NO_NEIGH:
    bpf_printk(
        "FIB lookup failed: NO NEIGHBOUR FOUND. Populate the cache with ping");
    break;
  case BPF_FIB_LKUP_RET_FRAG_NEEDED:
    bpf_printk("FIB lookup failed: FRAGMENTATION NEEDED. Packet exceed MTU");
    break;
  case BPF_FIB_LKUP_RET_NO_SRC_ADDR:
    bpf_printk("FIB lookup failed: NO SOURCE ADDR FOUND. Make sure source "
               "interface has legit ip");
    break;
  default:
    bpf_printk(
        "FIB lookup failed: rc=%d (unknown). Check routing and ARP/NDP config",
        rc);
    break;
  }
}
// see the bpf_fib_lookup struct in
// https://github.com/libbpf/libbpf/blob/dd92bef7f6c7a00bb0312554119b6d9cf38e4f32/include/uapi/linux/bpf.h#L7315
// see the xdp_md struct in
// https://github.com/libbpf/libbpf/blob/dd92bef7f6c7a00bb0312554119b6d9cf38e4f32/include/uapi/linux/bpf.h#L6559
static __always_inline int fib_lookup_v4_full(struct xdp_md *ctx,
                                              struct bpf_fib_lookup *fib,
                                              __u32 src, __u32 dst,
                                              __u16 tot_len) {
  // zero and populate only what full lookup need
  __builtin_memset(fib, 0, sizeof(*fib));
  // hardcode the family for ipv4 only
  fib->family = AF_INET;
  // src addr of the packet
  fib->ipv4_src = src;
  // dst addr of the packet
  fib->ipv4_dst = dst;
  // hardcode the protocol for tcp only
  fib->l4_protocol = IPPROTO_TCP;
  // total length of the packet (header + payload)
  fib->tot_len = tot_len;
  // ingress interface for the lookup
  fib->ifindex = ctx->ingress_ifindex;

  return bpf_fib_lookup(ctx, fib, sizeof(*fib), 0);
}
// calculate the checksum
// checksum 16 bit
// helper funtion return 64 bit
// need to fold (keep the last 16 bit and add carry)
// 4 loop since 16*4 64 (maximum number to loop)
static __always_inline __u16 recalc_ip_checksum(struct iphdr *ip) {
  // clear checksum for recalculation
  ip->check = 0;

  __u64 csum =
      bpf_csum_diff(NULL, 0, (unsigned int *)ip, sizeof(struct iphdr), 0);

#pragma unroll
  for (int i = 0; i < 4; i++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

SEC("xdp")
int xdp_loadbalancer(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct hdr_cursor nh;
  nh.pos = data;

  // parse the eth headers
  struct ethhdr *eth;
  int eth_type = parse_ethhdr(&nh, data_end, &eth);

  /*
   * only lb ipv4 (ETH_P_IP), for all or ipv4 (ETH_P_ALL or ETH_P_IPV6)
   * bpf_htons -> change the host byte order(based on host endian) to network
   * byte order (big endian) comparing value inside network packet with the host
   * constant
   */
  if (eth_type != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  // parse the ip headers
  struct iphdr *ip;
  parse_iphdr(&nh, data_end, &ip);
  // if no data -> pass
  if ((void *)(ip + 1) > data_end) {
    return XDP_PASS;
  }

  // only for tcp
  if (ip->protocol != IPPROTO_TCP) {
    return XDP_PASS;
  }

  // parse tcp headers
  struct tcphdr *tcp;
  parse_tcphdr(&nh, data_end, &tcp);
  if ((void *)(tcp + 1) > data_end) {
    return XDP_PASS;
  }

  // hardcode the port number for simplicity

  if (tcp->dest != bpf_htons(8000)) {
    return XDP_PASS;
  }

  // conntrack: pin each connection to one backend for the lifetime of the TCP
  // session so that all three-way handshake packets and subsequent data reach
  // the same backend
  struct conn_key ckey = {
    .src_ip   = ip->saddr,
    .dst_ip   = ip->daddr,
    .src_port = tcp->source,
    .dst_port = tcp->dest,
  };

  __u32 backend_idx;
  __u32 *stored_idx = bpf_map_lookup_elem(&conntrack, &ckey);

  if (stored_idx) {
    // existing connection: reuse the pinned backend
    backend_idx = *stored_idx;

    // evict on FIN or RST so the slot is freed for future connections
    if (tcp->fin || tcp->rst)
      bpf_map_delete_elem(&conntrack, &ckey);
  } else {
    // new connection: only SYN starts a valid TCP session
    if (!tcp->syn)
      return XDP_PASS;

    // pick next backend via round-robin and pin it
    if (get_next_backend_idx(&backend_idx) < 0)
      return XDP_ABORTED;

    bpf_map_update_elem(&conntrack, &ckey, &backend_idx, BPF_ANY);
  }

  struct endpoints *backend = bpf_map_lookup_elem(&backends, &backend_idx);
  if (!backend) {
    return XDP_ABORTED;
  }

  struct bpf_fib_lookup fib = {};

  int rc = fib_lookup_v4_full(ctx, &fib, ip->daddr, backend->ip,
                              bpf_ntohs(ip->tot_len));

  if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
    log_fib_error(rc);
    return XDP_ABORTED;
  }

  /*
   * we are using ipip encapsulation for DSR layer 3
   * simply rewriting the src and dst work but lb become bottleneck for handling
   * both request and response client -> lb -> backend, backend -> lb -> client
   * making upstream server return directly to client is ideal approach for high
   * performance can only rewrite the dest ip and pass to backend but client
   * will drop response packet if req packet dst and res packet src ip are
   * different without rewriting the dest or src ip but mac addr rewriting ,
   * need virtual ip to share for both lb and backends but backends and lb must
   * be in the same layer 2 network use ipip encapsulation for lb and backend
   * can exist in different layer 2 network
   */

  /*
   * make room for new outer ipv4 header (20bytes) between eth and inner ipv4
   * headers use negative delta for expending , since data-pointer move left ,
   * leaving more room
   */
  int adj = bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct iphdr));
  if (adj < 0) {
    bpf_printk("Failed to adjust packet header");
    return XDP_ABORTED;
  }

  // recompute data pointers after adjusting the headers
  void *new_data_end = (void *)(long)ctx->data_end;
  void *new_data = (void *)(long)ctx->data;

  struct ethhdr *new_eth = new_data;
  if ((void *)(new_eth + 1) > new_data_end) {
    return XDP_ABORTED;
  }

  // outer ipv4 header lives right after ethernet
  struct iphdr *outer = (void *)(new_eth + 1);
  if ((void *)(outer + 1) > new_data_end) {
    return XDP_ABORTED;
  }

  // inner ipv4 header lives right after outer
  struct iphdr *inner = (void *)(outer + 1);
  if ((void *)(inner + 1) > new_data_end) {
    return XDP_ABORTED;
  }

  // update the packet eth header with backend mac addr from the arp table
  __builtin_memcpy(new_eth->h_source, fib.smac, ETH_ALEN);
  __builtin_memcpy(new_eth->h_dest, fib.dmac, ETH_ALEN);
  new_eth->h_proto = bpf_htons(ETH_P_IP); // ipv4

  // build outer ipv4 header
  __u16 inner_len = bpf_ntohs(inner->tot_len);
  __u16 outer_len = (__u16)(inner_len + sizeof(struct iphdr));

  outer->version = 4; // ipv4
  outer->ihl = 5;     // 20 bytes
  outer->tos = 0;     //(type of service) best effort
  outer->tot_len = bpf_htons(outer_len);
  outer->id = 0;
  outer->frag_off = 0; // packet pagination offset
  outer->ttl = 64;
  outer->protocol =
      IPPROTO_IPIP; // for kernel ipip module to check and proceed decapsulation

  __u32 lbkey = 0;
  struct endpoints *lb = bpf_map_lookup_elem(&load_balancer, &lbkey);
  if (!lb) {
    return XDP_ABORTED;
  }
  // this is only for routing the encapsulated packet
  outer->saddr = lb->ip;
  outer->daddr = backend->ip;
  outer->check = 0; // initialise

  /*
   * need to recalculate the layer3 checksum since we build the outer ip header
   * from scratch since we are operating layer below kernel network stack, every
   * changes in the packet headers need to recalculate the checksum
   */
  outer->check = recalc_ip_checksum(outer);

  /*
   * we don't need to recalculate the ethernet frame checksum after updating the
   * mac address bacause ethernet frame checksum (FCS) isn't in the header but
   * instead is automatically recomputed by the NIC hardware when packet is
   * transmitted
   */
  return XDP_TX;
}
char _license[] SEC("license") = "GPL";

/* xdp_both.c
 *
 * This file contains the XDP program code to forward profinet traffic
 * bidirectionally between the high level PLC and the flexbot PLC
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <stdbool.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "profinet-forwarder.h"
#include "perf_event_macros.h"

struct bpf_map_def SEC("maps") perf_event_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int)
};
/* re-use just one of these to avoid using more stack space */
static struct perf_event_data p_event;

#define DCP_RESPONSE_LENGTH 108
#define DCP_RESPONSE_IP_START_OFFSET 96
#define DCP_RESPONSE_NETMASK_OFFSET 100
#define DCP_RESPONSE_GATEWAY_OFFSET 104
#define DCP_GET_IP_TYPE_OFFSET 0x1A
#define DCP_GET_IP_OFFSET 0x20
#define DCP_GET_NETMASK_OFFSET 0x24
#define DCP_GET_GATEWAY_OFFSET 0x28
#define LLDP_PROFIBUS_MAC_OFFSET 0x129

#define PROFINET_ETHERTYPE 0x8892
#define LLDP_ETHERTYPE 0x88CC

#define EPHEMERAL_PORT_THRESHOLD 32768

/* used for first byte of the profinet frame id */
#define PROFINET_CYCLIC_TYPE 0x80
#define PROFINET_ACYCLIC_TYPE 0xFE
/* used for second byte of the profinet frame id */
#define PROFINET_PNIO_ALARM_SUBTYPE 0x01
#define PROFINET_DCP_IDENT_SUBTYPE 0xFE
#define PROFINET_GET_SET_SUBTYPE 0xFD

#define VLAN_VID_MASK 0x0fff /* VLAN Identifier */

#define length(array) (sizeof(array)/sizeof(*(array)))

// Thresholds for wired communication jitter
static const unsigned long long PNIO_MIN_NS = 64 * 1000 * 1000;
static const unsigned long long PNIO_MAX_NS = 192 * 1000 * 1000;

struct bpf_map_def SEC("maps") interface_map = {
    .type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 2,
};

struct bpf_map_def SEC("maps") macaddr_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = 6,
    .max_entries = 2,
};

struct bpf_map_def SEC("maps") ipaddr_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = 4,
    .max_entries = 2,
};

struct dcp_state {
    unsigned char fb_plc_mac[ETH_ALEN];
    unsigned char hl_plc_mac[ETH_ALEN];
    bool hl_mac_set;
    bool fb_mac_set;
    __be32 ipv4_flexbot_device;
    __be32 ipv4_safety_server;
};

struct bpf_map_def SEC("maps") dcp_state_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(struct dcp_state),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") profinet_timing_data_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(struct profinet_timing_data),
    .max_entries = 1,
};

static const __u16 known_ethertypes[] = {
    PROFINET_ETHERTYPE, // profinet
    0x0800, // IPv4 packet
    0x0806, // ARP
    LLDP_ETHERTYPE, // LLDP
};
static int report_ethtype_counter = 20;

static const unsigned char pn_multicast[ETH_ALEN] = {0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00};

/* linux/if_vlan.h have not exposed this as UAPI, thus mirror some here
 *
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct _vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct parse_pkt {
    __u16 l3_proto;
    __u16 l3_offset;
    __u16 vlan_outer;
    __u16 vlan_inner;
    __u8 vlan_outer_offset;
    __u8 vlan_inner_offset;
    __be32 ipv4_src;
    __be32 ipv4_dest;
    __be16 ipv4_srcport;
    __be16 ipv4_dstport;
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
};

/* Parse IPv4 packet to get SRC, DST IP and protocol */
static inline int parse_ipv4(void *data, __u64 nh_off, void *data_end, __be32 *src, __be32 *dest,
    __be16* srcport, __be16* destport)
{
    /* bounds check on data size */
    if (data + nh_off + sizeof(struct iphdr) + 4 > data_end) {
        return false;
    }

    struct iphdr *iph = data + nh_off;

    *src = iph->saddr;
    *dest = iph->daddr;
    __be16* port_ptr = (__be16*)(iph + 1);
    *srcport = bpf_ntohs(*port_ptr);
    *destport = bpf_ntohs(*(port_ptr + 1));

    return iph->protocol;
}

static __always_inline bool parse_eth_frame(struct ethhdr *eth, void *data_end,
                                            struct parse_pkt *pkt)
{
    __u16 eth_type;
    __u8 offset;

    offset = sizeof(*eth);
    /* Make sure packet is large enough for parsing eth + 2 VLAN headers */
    if ((void *)eth + offset + (2 * sizeof(struct _vlan_hdr)) > data_end)
        return false;

    /* get the mac addresses since we're range checked safe here */
    __builtin_memcpy(pkt->h_dest, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(pkt->h_source, eth->h_source, ETH_ALEN);

    eth_type = eth->h_proto;

    /* Handle outer VLAN tag */
    if (eth_type == bpf_htons(ETH_P_8021Q) || eth_type == bpf_htons(ETH_P_8021AD)) {
        struct _vlan_hdr *vlan_hdr;

        vlan_hdr = (void *)eth + offset;
        pkt->vlan_outer_offset = offset;
        pkt->vlan_outer = bpf_ntohs(vlan_hdr->h_vlan_TCI) & VLAN_VID_MASK;
        eth_type = vlan_hdr->h_vlan_encapsulated_proto;
        offset += sizeof(*vlan_hdr);
    }

    /* Handle inner (double) VLAN tag */
    if (eth_type == bpf_htons(ETH_P_8021Q) || eth_type == bpf_htons(ETH_P_8021AD)) {
        struct _vlan_hdr *vlan_hdr;

        vlan_hdr = (void *)eth + offset;
        pkt->vlan_inner_offset = offset;
        pkt->vlan_inner = bpf_ntohs(vlan_hdr->h_vlan_TCI) & VLAN_VID_MASK;
        eth_type = vlan_hdr->h_vlan_encapsulated_proto;
        offset += sizeof(*vlan_hdr);
    }

    pkt->l3_proto = bpf_ntohs(eth_type); /* Convert to host-byte-order */
    pkt->l3_offset = offset;

    /* if this is an IPv4 packet, parse the IP address out */
    if (eth_type == bpf_htons(ETH_P_IP)) {
        parse_ipv4(eth, pkt->l3_offset, data_end, &(pkt->ipv4_src), &(pkt->ipv4_dest),
            &(pkt->ipv4_srcport), &(pkt->ipv4_dstport));
    }

    return true;
}

/****************************** INBOUND PROGRAM ******************************/

SEC("program_in")
int xdp_prog_in(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct parse_pkt pkt = {0};
    struct ethhdr *eth = data;
    char *dest;
    int *ifindex;
    struct dcp_state *dcp;
    struct profinet_timing_data *pn_timing;
    int key = 0;
    __u8 *mac_in;
    __u8 *mac_out;

    //bpf_perf(PROGRAM_IN, event_incoming_packet);

    if (!parse_eth_frame(data, data_end, &pkt)) {
        bpf_perf(PROGRAM_IN, event_unparsable_frame);
        return XDP_ABORTED;
    }

    key = INTERNAL_INTERFACE_INDEX;
    ifindex = bpf_map_lookup_elem(&interface_map, &key);
    if (!ifindex || (*ifindex < 0)) {
        bpf_perf(PROGRAM_IN, event_interface_map_fail);
        return XDP_PASS;
    }

    key = IN_MAC_INDEX;
    mac_in = bpf_map_lookup_elem(&macaddr_map, &key);
    if (!mac_in) {
        bpf_perf(PROGRAM_IN, event_inbound_mac_lookup_fail);
        return XDP_PASS;
    }

    key = OUT_MAC_INDEX;
    mac_out = bpf_map_lookup_elem(&macaddr_map, &key);
    if (!mac_out) {
        bpf_perf(PROGRAM_IN, event_outbound_mac_lookup_fail);
        return XDP_PASS;
    }

    key = 0;
    dcp = bpf_map_lookup_elem(&dcp_state_map, &key);
    if (!dcp) {
        bpf_perf(PROGRAM_IN, event_dcp_state_map_fail);
        return XDP_PASS;
    }

    key = 0;
    pn_timing = bpf_map_lookup_elem(&profinet_timing_data_map, &key);
    if (!pn_timing) {
        bpf_perf(PROGRAM_IN, event_profinet_timing_map_fail);
        return XDP_PASS;
    }

    if (pkt.l3_proto == PROFINET_ETHERTYPE) {
        __u8 profinet_frameID[2];
        // range check for profinet service type
        if ((data + pkt.l3_offset + 2) > data_end)
            return XDP_ABORTED;

        profinet_frameID[0] = *((__u8 *)data + pkt.l3_offset);
        profinet_frameID[1] = *((__u8 *)data + pkt.l3_offset + 1);

        if (profinet_frameID[0] == PROFINET_CYCLIC_TYPE)
        {
            // get timing data for cyclic traffic
            unsigned long long cyclic_rx_time = bpf_ktime_get_ns();
            unsigned long long cyclic_rx_delta = cyclic_rx_time - pn_timing->program_in_time;
            __u16 timing_incoming_index = pn_timing->frame_in_index;
            // protect range, because eBPF verification code hates everything
            if (timing_incoming_index >= INCOMING_FRAME_TIME_MAP_COUNT)
                timing_incoming_index = 0;
            pn_timing->frame_in_deltas[timing_incoming_index++] = cyclic_rx_delta;
            // wrap around if necessary
            if (timing_incoming_index == INCOMING_FRAME_TIME_MAP_COUNT) {
                pn_timing->frame_in_index = 0;
            } else {
                pn_timing->frame_in_index = timing_incoming_index;
            }
            pn_timing->program_in_time = cyclic_rx_time;
            pn_timing->program_in_count++;
        }

        /* only display frame id debug information when it is not cyclic and also not a DCP subtype.
         * note that we want to avoid spamming the debug log here with incoming DCP because the frame
         * uses layer 2 multicast, which means all the bots on that VLAN are going to observe the packet.
         */
        if ((profinet_frameID[0] != PROFINET_CYCLIC_TYPE)
         && (profinet_frameID[1] != PROFINET_DCP_IDENT_SUBTYPE))
        {
            /* detect and log profinet alarm types */
            if ((profinet_frameID[0] == PROFINET_ACYCLIC_TYPE)
             && (profinet_frameID[1] == PROFINET_PNIO_ALARM_SUBTYPE)) {
                bpf_perf(PROGRAM_IN, event_pnio_alarm);
            } else {
                bpf_perf2(PROGRAM_IN, event_profinet_frame_id, profinet_frameID[0], profinet_frameID[1]);
            }
        }

        if ((profinet_frameID[0] == PROFINET_ACYCLIC_TYPE)
         && (profinet_frameID[1] == PROFINET_DCP_IDENT_SUBTYPE)) {
            /* send through packet unmodified, local port will be set as promiscuous so
               that the response will be processed despite having different destination.
               note: DCP request is multicast so the destination mac is unmodified here. */

            return bpf_redirect_map(&interface_map, INTERNAL_INTERFACE_INDEX, 0);
        }

        if ((profinet_frameID[0] == PROFINET_ACYCLIC_TYPE)
         && (profinet_frameID[1] == PROFINET_GET_SET_SUBTYPE)) {
            bpf_perf(PROGRAM_IN, event_dcp_get_set);

            /* change the destination mac for this non-identity profinet frame */
            if (dcp->fb_mac_set) {
                __builtin_memcpy(eth->h_dest, dcp->fb_plc_mac, ETH_ALEN);
                bpf_perf(PROGRAM_IN, event_fb_plc_known);
            } else {
                bpf_perf(PROGRAM_IN, event_fb_plc_unknown);
            }

            if (!dcp->hl_mac_set)
            {
                bpf_perf(PROGRAM_IN, event_hl_mac_from_dcp);
                __builtin_memcpy(dcp->hl_plc_mac, eth->h_source, ETH_ALEN);
                dcp->hl_mac_set = true;
            }

            return bpf_redirect_map(&interface_map, INTERNAL_INTERFACE_INDEX, 0);
        }

        if (dcp->fb_mac_set)
        {
            __builtin_memcpy(eth->h_dest, dcp->fb_plc_mac, ETH_ALEN);
        }
        /* other profinet type not special cased */
        return bpf_redirect_map(&interface_map, INTERNAL_INTERFACE_INDEX, 0);
    }

    if (pkt.l3_proto == ETH_P_IP)
    {
        if (pkt.ipv4_dstport == 34964)
        {
            /* really just useful for debugging at this point */
            __u8 *ip = (__u8 *)&pkt.ipv4_src;
            bpf_perf4(PROGRAM_IN, event_safety_server_ip, ip[0], ip[1], ip[2], ip[3]);
            dcp->ipv4_safety_server = pkt.ipv4_src;
        }
    }

    return XDP_PASS;
}

/****************************** OUTBOUND PROGRAM ******************************/
SEC("program_out")
int xdp_prog_out(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct parse_pkt pkt = {0};
    struct ethhdr *eth = data;
    char *dest;
    int *ifindex;
    struct dcp_state *dcp;
    struct profinet_timing_data *pn_timing;
    int key = 0;
    __u8 *mac_in;
    __u8 *mac_out;
    __u32 *ext_ip_addr;
    __u32 *ext_netmask_addr;

    //bpf_perf(PROGRAM_OUT, event_outgoing_packet);

    if (!parse_eth_frame(data, data_end, &pkt)) {
        bpf_perf(PROGRAM_OUT, event_unparsable_frame);
        return XDP_ABORTED;
    }

    key = EXTERNAL_INTERFACE_INDEX;
    ifindex = bpf_map_lookup_elem(&interface_map, &key);
    if (!ifindex || (*ifindex < 0)) {
        bpf_perf(PROGRAM_OUT, event_interface_map_fail);
        return XDP_PASS;
    }

    key = IN_MAC_INDEX;
    mac_in = bpf_map_lookup_elem(&macaddr_map, &key);
    if (!mac_in) {
        bpf_perf(PROGRAM_OUT, event_inbound_mac_lookup_fail);
        return XDP_PASS;
    }

    key = OUT_MAC_INDEX;
    mac_out = bpf_map_lookup_elem(&macaddr_map, &key);
    if (!mac_out) {
        bpf_perf(PROGRAM_OUT, event_outbound_mac_lookup_fail);
        return XDP_PASS;
    }

    key = 0;
    dcp = bpf_map_lookup_elem(&dcp_state_map, &key);
    if (!dcp) {
        bpf_perf(PROGRAM_OUT, event_dcp_state_map_fail);
        return XDP_PASS;
    }

    key = IP_MAP_INDEX;
    ext_ip_addr = bpf_map_lookup_elem(&ipaddr_map, &key);
    if (!ext_ip_addr) {
        bpf_perf(PROGRAM_OUT, event_ip_map_fail);
        return XDP_PASS;
    }

    key = NETMASK_MAP_INDEX;
    ext_netmask_addr = bpf_map_lookup_elem(&ipaddr_map, &key);
    if (!ext_netmask_addr) {
        bpf_perf(PROGRAM_OUT, event_ip_map_fail);
        return XDP_PASS;
    }

    key = 0;
    pn_timing = bpf_map_lookup_elem(&profinet_timing_data_map, &key);
    if (!pn_timing) {
        bpf_perf(PROGRAM_OUT, event_profinet_timing_map_fail);
        return XDP_PASS;
    }

    bool matched_type = false;
    for (__u8 i = 0; i < length(known_ethertypes); i++)
    {
        if (pkt.l3_proto == known_ethertypes[i])
        {
            matched_type = true;
            break;
        }
    }
    if (!matched_type)
    {
        if (report_ethtype_counter > 0)
        {
            bpf_perf1(PROGRAM_OUT, event_unknown_ethertype, pkt.l3_proto);
            report_ethtype_counter--;
        }
        // we don't recognize this type of packet so just pass it
        return XDP_PASS;
    }

    // program flow here is to make it easy for the verifier to check this
    while (1) {
        /* check if the packet is IP type */
        if (pkt.l3_proto == ETH_P_IP) {
            /* check if the 6-byte flexbot PLC mac address is at a specific offset in frame */
            struct iphdr *iph;
            iph = (struct iphdr *)(eth + 1);
            if (iph + 1 > (struct iphdr*) data_end)
                return XDP_PASS;

            /* loosely qualify a packet we might match (is udp & ephemeral ports) */
            if ((dcp->fb_mac_set) && (iph->protocol == (17) /* udp */)
             && (pkt.ipv4_srcport > EPHEMERAL_PORT_THRESHOLD)
             && (pkt.ipv4_dstport > EPHEMERAL_PORT_THRESHOLD))
            {
                // Confirm frame is large enough to check for pnio_cm response
                if ((data + 0x00A8 + ETH_ALEN + 1) > data_end) {
                    return XDP_PASS;
                }

                // IPv4 frame, check for siemens MAC address at offset 0x00A8
                __u8 *fb_offset = data + 0x00A8;
                if ((*(fb_offset + 0) == dcp->fb_plc_mac[0]) &&
                    (*(fb_offset + 1) == dcp->fb_plc_mac[1]) &&
                    (*(fb_offset + 2) == dcp->fb_plc_mac[2]) &&
                    (*(fb_offset + 3) == dcp->fb_plc_mac[3]) &&
                    (*(fb_offset + 4) == dcp->fb_plc_mac[4]) &&
                    (*(fb_offset + 5) == dcp->fb_plc_mac[5])) {
                    bpf_perf1(PROGRAM_OUT, event_pniocm_response, data_end - data);
                    __builtin_memcpy(fb_offset, mac_in, ETH_ALEN);

                    /* set a zero udp checksum to make this packet be accepted */
                    /* the high level PLC will accept the "missing" (0 value) checksum  */
                    struct udphdr *udp;
                    udp = (struct udphdr *)(iph + 1);
                    udp->check = 0;
                }

                /* the packet is now passed for iptables (potentially modified content) */
                return XDP_PASS;
            }

            break;
        }

        /* handle profinet ethertype */
        if (pkt.l3_proto == PROFINET_ETHERTYPE) {
            __u8 profinet_frameID[2];
            // range check for profinet service type bytes
            if ((data + pkt.l3_offset + 2) > data_end)
                break;

            profinet_frameID[0] = *((__u8 *)data + pkt.l3_offset);
            profinet_frameID[1] = *((__u8 *)data + pkt.l3_offset + 1);

            if (profinet_frameID[0] == PROFINET_CYCLIC_TYPE)
            {
                // get timing data for cyclic traffic
                unsigned long long cyclic_rx_time = bpf_ktime_get_ns();
                int delta_rx_time = (int)(cyclic_rx_time - pn_timing->program_out_time);
                pn_timing->program_out_time = cyclic_rx_time;
                pn_timing->program_out_count++;
                if ((delta_rx_time < PNIO_MIN_NS) || (delta_rx_time > PNIO_MAX_NS))
                {
                    bpf_perf1(PROGRAM_OUT, event_pnio_timing_threshold, delta_rx_time);
                }
            }

            /* detect and log profinet alarm types */
            if ((profinet_frameID[0] == PROFINET_ACYCLIC_TYPE)
             && (profinet_frameID[1] == PROFINET_PNIO_ALARM_SUBTYPE))
            {
                bpf_perf(PROGRAM_OUT, event_pnio_alarm);
            }

            if ((profinet_frameID[0] == 0xfe) && (profinet_frameID[1] == 0xff)) {
                // found a DCP response
                bpf_perf1(PROGRAM_OUT, event_dcp_response, data_end - data);
                bpf_perf6(PROGRAM_OUT, event_l2_dest, pkt.h_dest[0], pkt.h_dest[1], pkt.h_dest[2],
                    pkt.h_dest[3], pkt.h_dest[4], pkt.h_dest[5]);

                // store the information in the shared map
                bpf_perf(PROGRAM_OUT, event_fb_plc_from_dcp);
                __builtin_memcpy(dcp->fb_plc_mac, pkt.h_source, ETH_ALEN);
                dcp->fb_mac_set = true;

                // check that response is long enough to contain the IP block information
                if ((data + DCP_RESPONSE_LENGTH) > data_end)
                    break;

                dcp->ipv4_flexbot_device = *(__u32 *)(data + (DCP_RESPONSE_IP_START_OFFSET));
                __u8 *ip = (__u8 *)&dcp->ipv4_flexbot_device;
                bpf_perf4(PROGRAM_OUT, event_dcp_fb_ip, ip[0], ip[1], ip[2], ip[3]);

                /* replace packet fields with our configuration */
                *(__u32 *)(data + (DCP_RESPONSE_IP_START_OFFSET)) = *ext_ip_addr;
                *(__u32 *)(data + (DCP_RESPONSE_NETMASK_OFFSET)) = *ext_netmask_addr;
                //*(__u32 *)(data + (DCP_RESPONSE_GATEWAY_OFFSET)) = bpf_htonl(0xc0a82842);
            }

            if ((profinet_frameID[0] == 0xfe) && (profinet_frameID[1] == 0xfd)) {
                bpf_perf1(PROGRAM_OUT, event_dcp_response, data_end - data);
                __builtin_memcpy(eth->h_source, mac_in, ETH_ALEN);

                /* look for possible IP response type */
                if ((data + 0x30) > data_end) {
                    bpf_perf(PROGRAM_OUT, event_dcp_get_size_fail);
                    return bpf_redirect_map(&interface_map, EXTERNAL_INTERFACE_INDEX, 0);
                }
                __u16 get_type = *(__u16 *)(data + (DCP_GET_IP_TYPE_OFFSET));
                if (get_type != 0x0201) {
                    bpf_perf(PROGRAM_OUT, event_dcp_get_type_fail);
                    return bpf_redirect_map(&interface_map, EXTERNAL_INTERFACE_INDEX, 0);
                }

                /* replace packet fields with our configuration */
                *(__u32 *)(data + (DCP_GET_IP_OFFSET)) = *ext_ip_addr;
                *(__u32 *)(data + (DCP_GET_NETMASK_OFFSET)) = *ext_netmask_addr;
                //*(__u32 *)(data + (DCP_GET_GATEWAY_OFFSET)) = bpf_htonl(0x0a000102);

                return bpf_redirect_map(&interface_map, EXTERNAL_INTERFACE_INDEX, 0);
            }

            /* very likely a PNIO packet at this point */
            /* packet is to be forwarded, set L2 source address in header */
            __builtin_memcpy(eth->h_source, mac_in, ETH_ALEN);

            return bpf_redirect_map(&interface_map, EXTERNAL_INTERFACE_INDEX, 0);
        }
        break;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

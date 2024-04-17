#pragma once

// these define the indexes used in the bpf maps for interfaces
#define INTERNAL_INTERFACE_INDEX 0
#define EXTERNAL_INTERFACE_INDEX 1

// these define the indexes used in the bpf maps for mac addresses
#define IN_MAC_INDEX 0
#define OUT_MAC_INDEX 1

// indexes used to track the IP and netmask for the wifi interface
#define IP_MAP_INDEX 0
#define NETMASK_MAP_INDEX 1

struct perf_event_data {
    __u32 event_data[6];
    __u16 event_id;
    __u8 bpf_program_num;
    __u8 parameter_count;
};

#define INCOMING_FRAME_TIME_MAP_COUNT 20
struct profinet_timing_data {
    __u64 program_in_time;
    __u64 program_in_count;
    __u64 program_out_time;
    __u64 program_out_count;
    __u64 frame_in_deltas[INCOMING_FRAME_TIME_MAP_COUNT];
    __u16 frame_in_index;
};

enum perf_event_ids {
    event_outgoing_packet = 0,
    event_unparsable_frame,
    event_inbound_mac_lookup_fail,
    event_outbound_mac_lookup_fail,
    event_interface_map_fail,
    event_dcp_state_map_fail,
    event_packet_type,
    event_dcp_ident_request,
    event_dcp_get_set,
    event_dcp_get_set_reply,
    event_dcp_response,
    event_dcp_fb_ip,
    event_profinet_frame_id,
    event_fb_plc_known,
    event_fb_plc_unknown,
    event_hl_mac_from_dcp,
    event_safety_server_ip,
    event_ip_map_fail,
    event_pniocm_response,
    event_fb_plc_from_dcp,
    event_l2_dest,
    event_bot_mac,
    event_dcp_get_size_fail,
    event_dcp_get_type_fail,
    event_mac_from_lldp,
    event_incoming_packet,
    event_unknown_ethertype,
    event_profinet_timing_map_fail,
    event_pnio_alarm,
    event_pnio_timing_threshold,
};

/*
 * The eBPF program only needs access to the above perf_event_ids,
 * the strings are used by the loader code only but are associated
 * with above ids and so included here.  Including it would increase
 * size for eBPF compiled output.
 */
#ifdef PN_FORWARD_LOADER
const char* perf_event_strings [] = {
    "Outgoing packet\n",
    "Unable to parse frame\n",
    "Inbound mac not found\n",
    "Outbound mac not found\n",
    "Interface state map not found\n",
    "DCP state map not found\n",
    "Packet ethtype: %04X\n",
    "redirecting DCP : Ident Request\n",
    "redirecting incoming DCP: get/set command\n",
    "forwarding DCP: get/set response\n",
    "! DCP response identified (lengh = %d)\n",
    "flexbot IP address from DCP: %d.%d.%d.%d\n",
    "! profinet-frameID: %x %x\n",
    "using known low level controller destination\n",
    "low level controller L2 addr not known!\n",
    "using incoming get/set as HL controller origin\n",
    "PNIO_CM request, HL safety server ip: %d.%d.%d.%d\n",
    "IP/NETMASK map lookup failure\n",
    "PNIO_CM response, replacing PLC mac with APB adapter (length = %d)\n",
    "! setting dcp state hardware addresses from DCP response\n",
    "L2 desination mac is: %02X:%02X:%02X:%02X:%02X:%02X\n",
    "Bot PLC mac is: %02X:%02X:%02X:%02X:%02X:%02X\n",
    "DCP get frame is too small\n",
    "DCP get type mismatched\n",
    "LLDP packet used to set internal plc mac\n",
    "Incoming packet\n",
    "Ethertype not recognized %04X\n",
    "Profinet timing map not found\n",
    "Profinet Alarm\n",
    "PNIO timing anomoly: %d ms\n",
};
#endif

#define PROGRAM_IN 0
#define PROGRAM_OUT 1
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <pthread.h>

#define PN_FORWARD_LOADER
#include "profinet-forwarder.h"
//#include "perf_event_strings.h"

#include <time.h>
#include <fcntl.h>
#include <signal.h>

#define STR_(x) #x
#define STR(x) STR_(x)
#define DEFAULT_PROG_PATH (EBPF_OBJ_DIR "/profinet-forwarder-ebpf.o")

/* perf output */
static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
    struct perf_event_data* e = data;

    (void) ctx;
    (void) cpu;
    (void) size;

    if (e->bpf_program_num == PROGRAM_IN) {
        printf(">> PROG_IN  >> ");
    }
    if (e->bpf_program_num == PROGRAM_OUT) {
        printf("<< PROG_OUT << ");
    }
    if (e->event_id == event_pnio_timing_threshold)
    {
        // special case to apply scalar to milliseconds
        printf(perf_event_strings[event_pnio_timing_threshold], e->event_data[0] / 1000000);
        return;
    }
    switch (e->parameter_count)
    {
        case 0:
            printf(perf_event_strings[e->event_id]);
        break;
        case 1:
            printf(perf_event_strings[e->event_id], e->event_data[0]);
        break;
        case 2:
            printf(perf_event_strings[e->event_id], e->event_data[0], e->event_data[1]);
        break;
        case 3:
            printf(perf_event_strings[e->event_id], e->event_data[0], e->event_data[1],
                e->event_data[2]);
        break;
        case 4:
            printf(perf_event_strings[e->event_id], e->event_data[0], e->event_data[1],
                e->event_data[2], e->event_data[3]);
        break;
        case 5:
            printf(perf_event_strings[e->event_id], e->event_data[0], e->event_data[1],
                e->event_data[2], e->event_data[3], e->event_data[4]);
        break;
        case 6:
            printf(perf_event_strings[e->event_id], e->event_data[0], e->event_data[1],
                e->event_data[2], e->event_data[3], e->event_data[4], e->event_data[5]);
        break;
    }
}

static void print_bpf_lost(void *ctx, int cpu, __u64 size)
{
    (void) ctx;
    (void) cpu;
    (void) size;

	printf("lost perf samples\n");
}
/* perf output */

static void get_interface_mac(const char *interface, uint8_t *mac)
{
    char addr_file_string[80];
    snprintf(addr_file_string, sizeof(addr_file_string), "/sys/class/net/%s/address", interface);
    FILE *addr_file = fopen(addr_file_string, "r");
    if (!addr_file) {
        fprintf(stderr, "Unable to open address file for: %s\n", interface);
        exit(1);
    }
    if (fscanf(addr_file, "%" SCNx8 ":%" SCNx8 ":%" SCNx8 ":%" SCNx8 ":%" SCNx8 ":%" SCNx8, &mac[0],
               &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        fprintf(stderr, "Parser error scanning interface mac for: %s\n", interface);
        exit(1);
    }
}

static unsigned long long get_nsecs(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

static void* pnio_timing(void* x)
{
    struct profinet_timing_data prev_update = {0};
    int time_map_fd = *(int*)(x);
    bool warning_status = false;
    const int warmup_count = 20; // wait until we have some traffic
    const int low_traffic_threshold = 4; // ~ half the expected 1s rate (7.8125/sec)

    while(1)
    {
        struct profinet_timing_data pn_timing;
        int key = 0;
        int ret = bpf_map_lookup_elem(time_map_fd, &key, &pn_timing);

        if ((ret == 0) && (pn_timing.program_in_count > warmup_count))
        {
            int prog_in_delta = (int)(pn_timing.program_in_count - prev_update.program_in_count);

            if (prog_in_delta < low_traffic_threshold)
            {
                if (!warning_status)
                {
                    unsigned long long ns_since_last_inbound = get_nsecs() - pn_timing.program_in_time;
                    int ms_since_last_inbound = (int)(ns_since_last_inbound / 1000000);
                    printf("Low PNIO traffic warning +in: %d  last message in: %d ms.\n", prog_in_delta, ms_since_last_inbound);
                    // also print out the array in order
                    int frame_in_count = INCOMING_FRAME_TIME_MAP_COUNT;
                    unsigned short frame_in_index = pn_timing.frame_in_index;
                    printf("Frame In Separation Timing ");
                    while (frame_in_count > 0)
                    {
                        // print nanoseconds converted to milliseconds
                        printf(":%d", (int)(pn_timing.frame_in_deltas[frame_in_index] / 1000000));
                        frame_in_count--;
                        frame_in_index = ((frame_in_index + 1) == INCOMING_FRAME_TIME_MAP_COUNT) ?
                            0 : frame_in_index + 1;
                    }
                    printf("\n");
                    warning_status = true;
                }
            } else {
                warning_status = false;
            }
        }

        memcpy(&prev_update, &pn_timing, sizeof(struct profinet_timing_data));
        sleep(1);
    }

    return NULL;
}

int main(int argc, char const *argv[])
{
    __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    int ret;
    int err, prog_fd_external, prog_fd_internal;
    int ifindex_external;
    int ifindex_internal;

    struct bpf_object *obj_shared = NULL;
    struct bpf_program *prog_external;
    struct bpf_program *prog_internal;

    int key = 0;
    int tx_port_map_fd;
    int mac_map_fd;

    // I/O buffering for stdout off, needed for journal to
    // properly log debug messages without large time delays
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 3) {
        printf("usage: %s EXTERNAL_INTERFACE INTERNAL_INTERFACE\n", argv[0]);
        return 1;
    }

    if ((ifindex_external = if_nametoindex(argv[1])) < 1) {
        fprintf(stderr, "unable to find interface EXTERNAL_INTERFACE interface index\n");
        return 1;
    }

    if ((ifindex_internal = if_nametoindex(argv[2])) < 1) {
        fprintf(stderr, "unable to find interface INTERNAL_INTERFACE interface index\n");
        return 1;
    }

    /* inbound mac */
    uint8_t external_mac[6];
    get_interface_mac(argv[1], external_mac);
    printf("External MAC for (%s): %02x:%02x:%02x:%02x:%02x:%02x\n", argv[1], external_mac[0],
           external_mac[1], external_mac[2], external_mac[3], external_mac[4], external_mac[5]);

    uint8_t internal_mac[6];
    get_interface_mac(argv[2], internal_mac);
    printf("Internal MAC for (%s): %02x:%02x:%02x:%02x:%02x:%02x\n", argv[2], internal_mac[0],
           internal_mac[1], internal_mac[2], internal_mac[3], internal_mac[4], internal_mac[5]);

    /* increase rlimit for memlock */
    struct rlimit rlim = {
        .rlim_cur = 512UL << 20,
        .rlim_max = 512UL << 20,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    printf("----------\n");

    const char *kprog_path = getenv("PROFINET_FORWARDER_PROG");
    if (!kprog_path)
	    kprog_path = DEFAULT_PROG_PATH;

    /* load both programs as single object */
    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .file = kprog_path,
        .expected_attach_type = 0,
    };
    err = bpf_prog_load_xattr(&prog_load_attr, &obj_shared, &prog_fd_external);
    if (err) {
        fprintf(stderr, "bpf_prog_load() failed for file: %s\n", prog_load_attr.file);
        return EXIT_FAILURE;
    }

    prog_external = bpf_program__next(NULL, obj_shared);
    prog_internal = bpf_program__next(prog_external, obj_shared);

    prog_fd_external = bpf_program__fd(prog_external);
    prog_fd_internal = bpf_program__fd(prog_internal);

    printf("bpf programs loaded.\n");
    printf("----------\n");

    /********** UPDATE MAP DATA **********/
    {
        /* interfaces map */
        tx_port_map_fd = bpf_object__find_map_fd_by_name(obj_shared, "interface_map");
        if (tx_port_map_fd < 0) {
            printf("bpf_object__find_map_fd_by_name failed\n");
            return 1;
        }
        printf("setting ifindex_internal: %d\n", ifindex_internal);
        key = INTERNAL_INTERFACE_INDEX;
        ret = bpf_map_update_elem(tx_port_map_fd, &key, &ifindex_internal, 0);
        if (ret) {
            perror("bpf_update_elem");
            return 1;
        }
        printf("setting ifindex_external: %d\n", ifindex_external);
        key = EXTERNAL_INTERFACE_INDEX;
        ret = bpf_map_update_elem(tx_port_map_fd, &key, &ifindex_external, 0);
        if (ret) {
            perror("bpf_update_elem");
            return 1;
        }

        /* mac address map */
        mac_map_fd = bpf_object__find_map_fd_by_name(obj_shared, "macaddr_map");
        if (mac_map_fd < 0) {
            printf("bpf_object__find_map_fd_by_name failed\n");
            return 1;
        }
        key = IN_MAC_INDEX;
        ret = bpf_map_update_elem(mac_map_fd, &key, &external_mac, 0);
        if (ret) {
            perror("bpf_update_elem: external_mac");
            return 1;
        }
        key = OUT_MAC_INDEX;
        ret = bpf_map_update_elem(mac_map_fd, &key, &internal_mac, 0);
        if (ret) {
            perror("bpf_update_elem: internal_mac");
            return 1;
        }
        printf("bpf map writing complete for external program\n");

        tx_port_map_fd = bpf_object__find_map_fd_by_name(obj_shared, "interface_map");
        if (tx_port_map_fd < 0) {
            printf("bpf_object__find_map_fd_by_name failed\n");
            return 1;
        }
        printf("bpf map writing complete for internal program\n");
    }

    printf("----------\n");

    /********** INBOUND PROGRAM SET LINK **********/
    /*      wireless lan -> wired ethernet    */
    printf("wireless lan index: %d\n", ifindex_external);
    if (bpf_set_link_xdp_fd(ifindex_external, prog_fd_external, xdp_flags) < 0) {
        printf("ERROR: link set xdp fd failed on %d\n", ifindex_external);
        return 1;
    }

    /********** OUTBOUND PROGRAM SET LINK **********/
    /*      wired ethernet -> wireless lan     */
    printf("wired ethernet index: %d\n", ifindex_internal);
    if (bpf_set_link_xdp_fd(ifindex_internal, prog_fd_internal, xdp_flags) < 0) {
        printf("ERROR: link set xdp fd failed on %d\n", ifindex_internal);
        return 1;
    }

    /* configure APB membership for L2 PN-DCP multicast on the external interface */
    {
        printf("opening packet socket for L2 multicast\n");
        struct packet_mreq mreq;
        int pk_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (pk_socket < 0) {
            perror("socket");
            return 1;
        }

        memset(&mreq, 0, sizeof(mreq));
        mreq.mr_type = PACKET_MR_MULTICAST;
        mreq.mr_ifindex = ifindex_external;
        mreq.mr_alen = ETH_ALEN;
        const unsigned char pn_multicast[ETH_ALEN] = {0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00};
        memcpy(mreq.mr_address, pn_multicast, ETH_ALEN);

        printf("mreq.mr_address is: %02x:%02x:%02x:%02x:%02x:%02x\n", pn_multicast[0],
               pn_multicast[1], pn_multicast[2], pn_multicast[3], pn_multicast[4], pn_multicast[5]);

        if (setsockopt(pk_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq))) {
            perror("setsockopt MR_MULTICAST");
            return 1;
        }

        struct ifreq ifr;
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, argv[1], IFNAMSIZ-1);

        /* ip address map */
        int ip_map_fd = bpf_object__find_map_fd_by_name(obj_shared, "ipaddr_map");
        if (ip_map_fd < 0) {
            printf("bpf_object__find_map_fd_by_name failed\n");
            return 1;
        }

        /* perf setup */
        struct perf_buffer_opts pb_opts = {};
        //struct bpf_program *prog_in;
        //struct bpf_program *prog_out;
        struct perf_buffer *pb;
        int map_fd, ret = 0;

        map_fd = bpf_object__find_map_fd_by_name(obj_shared, "perf_event_map");
        if (map_fd < 0) {
            fprintf(stderr, "ERROR: finding a map in obj file failed\n");
            return 1;
        }

        /* timing map setup */
        int timing_fd;
        timing_fd = bpf_object__find_map_fd_by_name(obj_shared, "profinet_timing_data_map");
        if (timing_fd < 0) {
            fprintf(stderr, "ERROR: finding a map in obj file failed\n");
            return 1;
        }

        pthread_t pnio_timing_thread;
        int res = pthread_create(&pnio_timing_thread, NULL, pnio_timing, &timing_fd);
        if (res)
        {
            fprintf(stderr, "pnio timing thread start error %d\n", res);
            return 1;
        }

        pb_opts.sample_cb = print_bpf_output;
        pb_opts.lost_cb = print_bpf_lost;
        pb = perf_buffer__new(map_fd, 16, &pb_opts);
        ret = libbpf_get_error(pb);
        if (ret) {
            printf("failed to setup perf_buffer: %d\n", ret);
            return 1;
        }
        printf("completed perf event setup\n");
        /* end perf setup */

        for(;;) {
            //printf("starting poll\n");
            perf_buffer__poll(pb, 1000);
            //printf("ended poll\n");

            /* check on external interface IP address and keep bpf map updated */
            int ioctl_ret = ioctl(pk_socket, SIOCGIFADDR, &ifr);
            if (ioctl_ret == 0)
            {
                uint32_t ipv4_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
                key = IP_MAP_INDEX;
                ret = bpf_map_update_elem(ip_map_fd, &key, &ipv4_addr, 0);
                if (ret) {
                    perror("bpf_update_elem: ip addr");
                    return 1;
                }
            }

            /* check on external interface netmask */
            ioctl_ret = ioctl(pk_socket, SIOCGIFNETMASK, &ifr);
            if (ioctl_ret == 0)
            {
                uint32_t netmask_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
                key = NETMASK_MAP_INDEX;
                ret = bpf_map_update_elem(ip_map_fd, &key, &netmask_addr, 0);
                if (ret) {
                    perror("bpf_update_elem: ip addr");
                    return 1;
                }
            }

            //sleep(10);
        }
    }

	return 0;
}

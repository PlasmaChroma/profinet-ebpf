#pragma once
/*
 *  attempted setting this up with variable argument list macros first
 *  but this was more straightforward and debugging the other method
 *  was not going well
 */
#define BPF_PERF_SETUP(prog, event) \
    p_event.bpf_program_num = prog; \
    p_event.event_id = event;
#define BPF_EVENT_CALL bpf_perf_event_output(ctx, &perf_event_map, BPF_F_CURRENT_CPU, &p_event, sizeof(p_event));
#define bpf_perf(prog, event)              \
    ({                                     \
        BPF_PERF_SETUP(prog, event)        \
        p_event.parameter_count = 0;       \
        BPF_EVENT_CALL                     \
    })
#define bpf_perf1(prog, event, p1)         \
    ({                                     \
        BPF_PERF_SETUP(prog, event)        \
        p_event.parameter_count = 1;       \
        p_event.event_data[0] = p1;        \
        BPF_EVENT_CALL                     \
    })
#define bpf_perf2(prog, event, p1, p2)     \
    ({                                     \
        BPF_PERF_SETUP(prog, event)        \
        p_event.parameter_count = 2;       \
        p_event.event_data[0] = p1;        \
        p_event.event_data[1] = p2;        \
        BPF_EVENT_CALL                     \
    })
#define bpf_perf3(prog, event, p1, p2, p3) \
    ({                                     \
        BPF_PERF_SETUP(prog, event)        \
        p_event.parameter_count = 3;       \
        p_event.event_data[0] = p1;        \
        p_event.event_data[1] = p2;        \
        p_event.event_data[2] = p3;        \
        BPF_EVENT_CALL                     \
    })
#define bpf_perf4(prog, event, p1, p2, p3, p4) \
    ({                                         \
        BPF_PERF_SETUP(prog, event)            \
        p_event.parameter_count = 4;           \
        p_event.event_data[0] = p1;            \
        p_event.event_data[1] = p2;            \
        p_event.event_data[2] = p3;            \
        p_event.event_data[3] = p4;            \
        BPF_EVENT_CALL                         \
    })
#define bpf_perf5(prog, event, p1, p2, p3, p4, p5) \
    ({                                             \
        BPF_PERF_SETUP(prog, event)                \
        p_event.parameter_count = 5;               \
        p_event.event_data[0] = p1;                \
        p_event.event_data[1] = p2;                \
        p_event.event_data[2] = p3;                \
        p_event.event_data[3] = p4;                \
        p_event.event_data[4] = p5;                \
        BPF_EVENT_CALL                             \
    })
#define bpf_perf6(prog, event, p1, p2, p3, p4, p5, p6) \
    ({                                                 \
        BPF_PERF_SETUP(prog, event)                    \
        p_event.parameter_count = 6;                   \
        p_event.event_data[0] = p1;                    \
        p_event.event_data[1] = p2;                    \
        p_event.event_data[2] = p3;                    \
        p_event.event_data[3] = p4;                    \
        p_event.event_data[4] = p5;                    \
        p_event.event_data[5] = p6;                    \
        BPF_EVENT_CALL                                 \
    })
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENT 200
struct ent { u32 pid; float x,y,z,sx,sy,w; u8 vis; };

volatile const u64 lib_base = 0;
volatile const u32 target_pid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct ent[MAX_ENT]);
} pc_arr SEC(".maps");

SEC("fexit/exit_to_user_mode")
int BPF_PROG(on_exit_user)
{
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    if (tid != target_pid) return 0;
    u64 world,level,actors; u32 cnt;
    bpf_probe_read_user(&world, 8, (void *)(lib_base + 0x12AFBBF8));
    bpf_probe_read_user(&level, 8, (void *)(world + 0x90));
    bpf_probe_read_user(&actors,8, (void *)(level + 0xA0));
    bpf_probe_read_user(&cnt,   4, (void *)(level + 0xA8));
    if (cnt > MAX_ENT) cnt = MAX_ENT;
    u32 k = 0;
    struct ent *out = bpf_map_lookup_elem(&pc_arr, &k);
    if (!out) return 0;
    #pragma unroll
    for (int i = 0; i < MAX_ENT; i++) {
        if (i >= cnt) { out[i].pid = 0; continue; }
        u64 obj; bpf_probe_read_user(&obj, 8, (void *)(actors + i*8));
        if (obj < 0x10000000) { out[i].pid = 0; continue; }
        float state; bpf_probe_read_user(&state, 4, (void *)(obj + 0x1368));
        if (state != 479.5f) { out[i].pid = 0; continue; }
        float pos[3]; bpf_probe_read_user(pos, 12, (void *)(obj + 0x268 + 0x1B0));
        float mat[16]; u64 mx; bpf_probe_read_user(&mx, 8, (void *)(lib_base + 0x12ACB840));
        bpf_probe_read_user(&mx, 8, (void *)(mx + 0x20)); mx += 0x270;
        bpf_probe_read_user(mat, sizeof(mat), (void *)mx);
        float wc = pos[0]*mat[12] + pos[1]*mat[13] + pos[2]*mat[14] + mat[15];
        if (wc < 0.1f) { out[i].pid = 0; continue; }
        float inv = 1.0f/wc;
        out[i].sx = 1200*(1.0f + (pos[0]*mat[0]+pos[1]*mat[1]+pos[2]*mat[2]+mat[3])*inv/90.0f);
        out[i].sy =  540*(1.0f - (pos[0]*mat[4]+pos[1]*mat[5]+pos[2]*mat[6]+mat[7])*inv/90.0f);
        out[i].w  = 30.0f; out[i].vis = 1;
        out[i].x = pos[0]; out[i].y = pos[1]; out[i].z = pos[2];
        out[i].pid = tid;
    }
    return 0;
}
char _license[] SEC("license") = "GPL";

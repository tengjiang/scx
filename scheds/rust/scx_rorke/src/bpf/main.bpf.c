#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * const volatiles are set during initialization
 */

const volatile u32 debug;

static u64 slice_ns = SCX_SLICE_DFL;

s32 BPF_STRUCT_OPS(rorke_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	return 0;
}

void BPF_STRUCT_OPS(rorke_enqueue, struct task_struct *p, u64 enq_flags)
{
}

void BPF_STRUCT_OPS(rorke_dispatch, s32 cpu, struct task_struct *prev)
{
}

void BPF_STRUCT_OPS(rorke_runnable, struct task_struct *p, u64 enq_flags)
{
}

void BPF_STRUCT_OPS(rorke_running, struct task_struct *p)
{
}

void BPF_STRUCT_OPS(rorke_stopping, struct task_struct *p, bool runnable)
{
}

void BPF_STRUCT_OPS(rorke_quiescent, struct task_struct *p, u64 deq_flags)
{
}

s32 BPF_STRUCT_OPS(rorke_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	return 0;
}

void BPF_STRUCT_OPS(rorke_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rorke_init)
{
	return 0;
}

void BPF_STRUCT_OPS(rorke_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(rorke, .select_cpu = (void *)rorke_select_cpu,
	       .enqueue = (void *)rorke_enqueue,
	       .dispatch = (void *)rorke_dispatch,
	       .runnable = (void *)rorke_runnable,
	       .running = (void *)rorke_running,
	       .stopping = (void *)rorke_stopping,
	       .quiescent = (void *)rorke_quiescent,
	       .init_task = (void *)rorke_init_task,
	       .exit_task = (void *)rorke_exit_task, .init = (void *)rorke_init,
	       .exit = (void *)rorke_exit, .name = "rorke");

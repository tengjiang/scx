/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Rorke: A special purpose scheduler for hypervisors
 * TODO: Add a proper description
 *
 * Copyright(C) 2024 Vahab Jabrayilov<vjabrayilov@cs.columbia.edu>
 * Influenced by the scx_central scheduler
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

enum {
	FALLBACK_DSQ_ID = 0,
	US_TO_NS = 1000LLU,
	/* TODO: make timer interval configurable */
	TIMER_INTERVAL_NS = 100 * US_TO_NS,
};

/*
 * Init parameters
 * const volatiles are set again during initialization
 * here we assign values just to pass the verifier
 */
const volatile s32 central_cpu = 0;
const volatile u32 nr_cpus = 1;
const volatile u32 nr_vms = 1;
const volatile u64 slice_ns = SCX_SLICE_DFL;
const volatile u32 debug = 0;
const volatile u64 vms[MAX_VMS];
const volatile u64 cpu_to_vm[MAX_CPUS];

bool timer_pinned = true;
u64 nr_total, nr_locals, nr_queued, nr_lost_pids;
u64 nr_timers, nr_dispatches, nr_mismatches, nr_retries;
u64 nr_overflows;

/* Exit information */
UEI_DEFINE(uei);

struct central_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct central_timer);
} central_timer SEC(".maps");

s32 BPF_STRUCT_OPS(rorke_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	/*
     * Steer wakeups to the central CPU to avoid disturbing other CPUs.
     * NOTE: This is a simple implementation. A more sophisticated approach
     * would check to directly steer to the previously assigned CPU if idle.
     */
	return central_cpu;
}

void BPF_STRUCT_OPS(rorke_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 pid = p->pid;
	s32 tgid = p->tgid;

	__sync_fetch_and_add(&nr_total, 1);

	/*
	 * Push per-cpu kthreads at the head of local dsq's and preempt the
	 * corresponding CPU. This ensures that e.g. ksoftirqd isn't blocked
	 * behind other threads which is necessary for forward progress
	 * guarantee as we depend on the BPF timer which may run from ksoftirqd.
	 */
	if ((p->flags & PF_KTHREAD) && p->nr_cpus_allowed == 1) {
		__sync_fetch_and_add(&nr_locals, 1);
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_INF,
				 enq_flags | SCX_ENQ_PREEMPT);
		return;
	}

    /* TODO: error checking */
    scx_bpf_dispatch(p, tgid, SCX_SLICE_INF, enq_flags);

    __sync_fetch_and_add(&nr_queued, 1);
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

/*
 * At every TIMER_INTERVAL_NS, preempts all CPUs other than central.
 */
static int central_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	u64 now = bpf_ktime_get_ns();
	u64 nr_to_kick = nr_queued;
	s32 i, curr_cpu;

	curr_cpu = bpf_get_smp_processor_id();
	if (timer_pinned && (curr_cpu != central_cpu)) {
		scx_bpf_error(
			"Central Timer ran on CPU %d, not central CPU %d\n",
			curr_cpu, central_cpu);
		return 0;
	}

	/* TODO: check removing nr_timers */
	bpf_for(i, 0, nr_cpus)
	{
		s32 cpu = (nr_timers + i) % nr_cpus;

		if (cpu == central_cpu)
			continue;

		if (scx_bpf_dsq_nr_queued(FALLBACK_DSQ_ID) ||
		    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu))
			;
		else if (nr_to_kick)
			nr_to_kick--;
		else
			continue;

		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
	}

	bpf_timer_start(timer, TIMER_INTERVAL_NS, BPF_F_TIMER_CPU_PIN);
	__sync_fetch_and_add(&nr_timers, 1);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rorke_init)
{
	u32 key = 0, i;
	struct bpf_timer *timer;
	int ret;

	ret = scx_bpf_create_dsq(FALLBACK_DSQ_ID, -1);
	if (ret)
		return ret;

	/* Create DSQ per VM */
	bpf_for(i, 0, nr_vms)
	{
		ret = scx_bpf_create_dsq(vms[i], -1);
		if (ret) {
			scx_bpf_error("failed to create DSQ for VM %d", vms[i]);
			return ret;
		}
	}

	/* Setup timer */
	timer = bpf_map_lookup_elem(&central_timer, &key);
	if (!timer)
		return -ESRCH;

	if (bpf_get_smp_processor_id() != central_cpu) {
		scx_bpf_error("init from non-central cpu");
		return EINVAL;
	}

	bpf_timer_init(timer, &central_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, central_timerfn);

	ret = bpf_timer_start(timer, TIMER_INTERVAL_NS, BPF_F_TIMER_CPU_PIN);
	/*
     * BPF_F_TIMER_CPU_PIN is not supported in all kernels (>= 6.7). If we're
     * running on an older kernel, it'll return -EINVAL
     * Retry w/o BPF_F_TIMER_CPU_PIN
     */
	if (ret == -EINVAL) {
		timer_pinned = false;
		ret = bpf_timer_start(timer, TIMER_INTERVAL_NS, 0);
	}
	if (ret)
		scx_bpf_error("bpf_timer_start failed (%d)", ret);
	return ret;
}

void BPF_STRUCT_OPS(rorke_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(rorke,
	       /*
		    * We are offloading all scheduling decisions to the central CPU
		    * and thus being the last task on a given CPU doesn't mean
		    * anything special. Enqueue the last tasks like any other tasks.
		    */
	       .flags = SCX_OPS_ENQ_LAST,
	       .select_cpu = (void *)rorke_select_cpu,
	       .enqueue = (void *)rorke_enqueue,
	       .dispatch = (void *)rorke_dispatch,
	       .runnable = (void *)rorke_runnable,
	       .running = (void *)rorke_running,
	       .stopping = (void *)rorke_stopping,
	       .quiescent = (void *)rorke_quiescent,
	       .init_task = (void *)rorke_init_task,
	       .exit_task = (void *)rorke_exit_task, .init = (void *)rorke_init,
	       .exit = (void *)rorke_exit, .name = "rorke");

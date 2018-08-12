/*
 *  Copyright (C) 2018 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "lib/probes/comm.h"

BPF_PERF_OUTPUT(comm_events);

int syscall__execve(struct pt_regs *ctx,
	const char __user *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;

	struct comm_event event = {
		.pid = pid,
	};

	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	pid2comm_map.update(&pid, &event);
	comm_events.perf_submit(ctx, &event, sizeof(event));

	return 0;
}

int syscall__ret_execve(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	pid2comm_map.delete(&pid);

	return 0;
}

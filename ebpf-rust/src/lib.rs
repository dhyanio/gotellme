#![no_std]
#![no_main]

use aya_bpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

#[tracepoint(name = "sys_enter_execve")]
pub fn trace_execve(ctx: TracePointContext) -> u32 {
    match try_trace_execve(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_trace_execve(ctx: TracePointContext) -> Result<(), i32> {
    let pid: u32 = unsafe { ctx.read_at(0)? };
    let mut comm = [0u8; 16];
    unsafe {
        ctx.read_at_into(8, &mut comm)?;
    }

    info!(&ctx, "Execve detected: PID={} Command={:?}", pid, comm);
    Ok(())
}

use aya::{
    Ebpf,
    maps::RingBuf,
    programs::TracePoint,
};
use sentry_types::{EVENT_HEADER_SIZE_U32, EventHeader, EventKind};
use std::{env, error::Error, fs, process::Command, thread, time::Duration};

fn main() -> Result<(), Box<dyn Error>> {
    let object_path = env::args().nth(1).ok_or("missing BPF object path")?;
    let object = fs::read(object_path)?;
    let mut ebpf = Ebpf::load(&object)?;
    for (program_name, tracepoint_name) in [
        ("capture_exec", "sched_process_exec"),
        ("capture_fork", "sched_process_fork"),
        ("capture_exit", "sched_process_exit"),
    ] {
        let program: &mut TracePoint = ebpf
            .program_mut(program_name)
            .ok_or_else(|| format!("{program_name} program not found"))?
            .try_into()?;
        program.load()?;
        program.attach("sched", tracepoint_name)?;
    }
    let mut events = RingBuf::try_from(ebpf.take_map("events").ok_or("events map not found")?)?;
    let status = Command::new("/bin/true").status()?;
    if !status.success() {
        return Err("trigger command failed".into());
    }
    let mut received = 0_u8;
    for _ in 0..100 {
        while let Some(event) = events.next() {
            let header = EventHeader::decode(&event)
                .map_err(|error| format!("invalid Sentry event header: {error:?}"))?;
            if header.event_size != EVENT_HEADER_SIZE_U32 {
                return Err("unexpected Sentry event header".into());
            }
            received |= match header.kind {
                EventKind::Exec if header.tgid != 0 && header.tid != 0 => 1,
                EventKind::Fork
                    if header.tgid == 0 && header.tid != 0 && header.parent_tgid != 0 =>
                {
                    2
                }
                EventKind::Exit if header.tgid != 0 && header.tid != 0 => 4,
                EventKind::Exec | EventKind::Fork | EventKind::Exit => {
                    return Err("invalid lifecycle identity fields".into());
                }
                _ => 0,
            };
        }
        if received == 7 {
            println!("Aya exec/fork/exit tracepoint and ring-buffer probe succeeded");
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err(format!("missing lifecycle events (received mask {received:#05b})").into())
}

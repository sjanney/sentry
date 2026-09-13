use libbpf_rs::{MapCore, ObjectBuilder, RingBufferBuilder, TracepointCategory};
use sentry_types::{EVENT_HEADER_SIZE_U32, EventHeader, EventKind};
use std::{cell::Cell, env, error::Error, process::Command, time::Duration};

fn main() -> Result<(), Box<dyn Error>> {
    let object_path = env::args().nth(1).ok_or("missing BPF object path")?;
    let object = ObjectBuilder::default().open_file(object_path)?.load()?;
    let mut links = Vec::new();
    for (program_name, tracepoint_name) in [
        ("capture_exec", "sched_process_exec"),
        ("capture_fork", "sched_process_fork"),
        ("capture_exit", "sched_process_exit"),
    ] {
        links.push(
            object
                .progs_mut()
                .find(|program| program.name().to_str() == Some(program_name))
                .ok_or_else(|| format!("{program_name} program not found"))?
                .attach_tracepoint(TracepointCategory::Sched, tracepoint_name)?,
        );
    }
    let events = object
        .maps()
        .find(|map| map.name().to_str() == Some("events"))
        .ok_or("events map not found")?;
    let received = Cell::new(0_u8);
    let mut builder = RingBufferBuilder::new();
    builder.add(&events, |event| {
        let Ok(header) = EventHeader::decode(event) else {
            return 1;
        };
        if header.event_size != EVENT_HEADER_SIZE_U32 {
            return 1;
        }
        let bit = match header.kind {
            EventKind::Exec if header.tgid != 0 && header.tid != 0 => 1,
            EventKind::Fork
                if header.tgid == 0 && header.tid != 0 && header.parent_tgid != 0 =>
            {
                2
            }
            EventKind::Exit if header.tgid != 0 && header.tid != 0 => 4,
            EventKind::Exec | EventKind::Fork | EventKind::Exit => return 1,
            _ => 0,
        };
        received.set(received.get() | bit);
        0
    })?;
    let ring_buffer = builder.build()?;
    let status = Command::new("/bin/true").status()?;
    if !status.success() {
        return Err("trigger command failed".into());
    }
    for _ in 0..10 {
        ring_buffer.poll(Duration::from_millis(100))?;
        if received.get() == 7 {
            println!("libbpf-rs exec/fork/exit tracepoint and ring-buffer probe succeeded");
            return Ok(());
        }
    }
    Err(format!(
        "missing lifecycle events (received mask {:#05b})",
        received.get()
    )
    .into())
}

use libbpf_rs::{MapCore, ObjectBuilder, RingBufferBuilder, TracepointCategory};
use std::{cell::Cell, env, error::Error, process::Command, time::Duration};

fn main() -> Result<(), Box<dyn Error>> {
    let object_path = env::args().nth(1).ok_or("missing BPF object path")?;
    let object = ObjectBuilder::default().open_file(object_path)?.load()?;
    let _link = object
        .progs_mut()
        .find(|program| program.name().to_str() == Some("capture_exec"))
        .ok_or("capture_exec program not found")?
        .attach_tracepoint(TracepointCategory::Sched, "sched_process_exec")?;
    let events = object
        .maps()
        .find(|map| map.name().to_str() == Some("events"))
        .ok_or("events map not found")?;
    let received = Cell::new(false);
    let mut builder = RingBufferBuilder::new();
    builder.add(&events, |event| {
        received.set(event.len() == 20);
        0
    })?;
    let ring_buffer = builder.build()?;
    let status = Command::new("/bin/true").status()?;
    if !status.success() {
        return Err("trigger command failed".into());
    }
    ring_buffer.poll(Duration::from_secs(1))?;
    if !received.get() {
        return Err("no valid tracepoint event was received".into());
    }
    println!("libbpf-rs tracepoint load, attach, and ring-buffer consumption succeeded");
    Ok(())
}

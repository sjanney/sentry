use aya::{
    Ebpf,
    maps::RingBuf,
    programs::TracePoint,
};
use std::{env, error::Error, fs, process::Command, thread, time::Duration};

fn main() -> Result<(), Box<dyn Error>> {
    let object_path = env::args().nth(1).ok_or("missing BPF object path")?;
    let object = fs::read(object_path)?;
    let mut ebpf = Ebpf::load(&object)?;
    let program: &mut TracePoint = ebpf
        .program_mut("capture_exec")
        .ok_or("capture_exec program not found")?
        .try_into()?;

    program.load()?;
    let _link = program.attach("sched", "sched_process_exec")?;
    let mut events = RingBuf::try_from(ebpf.take_map("events").ok_or("events map not found")?)?;
    let status = Command::new("/bin/true").status()?;
    if !status.success() {
        return Err("trigger command failed".into());
    }
    for _ in 0..100 {
        if let Some(event) = events.next() {
            if event.len() != 20 {
                return Err(format!("unexpected event size: {}", event.len()).into());
            }
            println!("Aya tracepoint load, attach, and ring-buffer consumption succeeded");
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err("no tracepoint event was received".into())
}

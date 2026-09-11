use aya::{programs::TracePoint, Ebpf};
use std::{env, error::Error, fs};

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
    println!("Aya tracepoint load and attach succeeded");
    Ok(())
}

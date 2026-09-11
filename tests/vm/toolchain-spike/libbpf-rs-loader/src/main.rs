use libbpf_rs::{ObjectBuilder, TracepointCategory};
use std::{env, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    let object_path = env::args().nth(1).ok_or("missing BPF object path")?;
    let object = ObjectBuilder::default().open_file(object_path)?.load()?;
    let program = object
        .progs_mut()
        .find(|program| program.name().to_str() == Some("capture_exec"))
        .ok_or("capture_exec program not found")?;
    let _link = program.attach_tracepoint(TracepointCategory::Sched, "sched_process_exec")?;
    println!("libbpf-rs tracepoint load and attach succeeded");
    Ok(())
}

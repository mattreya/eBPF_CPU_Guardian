use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::TracePoint,
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use guardian_common::GuardianEvent;
use clap::Parser;
use log::{info, warn, error};
use tokio::signal;
use tokio::sync::mpsc;

mod analysis;
mod cgroups;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// CPU limit percentage (10-100)
    #[arg(short, long, default_value = "20")]
    cpu_limit: u32,

    /// Behavioral score threshold for detection
    #[arg(short, long, default_value = "100")]
    threshold: u32,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    env_logger::init();

    // This will include the eBPF object file at compile time.
    #[cfg(debug_assertions)]
    let bpf_data = include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/guardian"
    );
    #[cfg(not(debug_assertions))]
    let bpf_data = include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/guardian"
    );

    let mut bpf = Ebpf::load(bpf_data)?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program_exec: &mut TracePoint = bpf.program_mut("guardian_exec").unwrap().try_into()?;
    program_exec.load()?;
    program_exec.attach("syscalls", "sys_enter_execve")?;

    let program_open: &mut TracePoint = bpf.program_mut("guardian_openat").unwrap().try_into()?;
    program_open.load()?;
    program_open.attach("syscalls", "sys_enter_openat")?;

    let program_connect: &mut TracePoint = bpf.program_mut("guardian_connect").unwrap().try_into()?;
    program_connect.load()?;
    program_connect.attach("syscalls", "sys_enter_connect")?;

    let bpf: &'static mut Ebpf = Box::leak(Box::new(bpf));

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS").unwrap())?;

    let (tx, mut rx) = mpsc::channel(1024);

    for cpu_id in online_cpus().map_err(|e| anyhow::anyhow!("{}: {}", e.0, e.1))? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let tx = tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| bytes::BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                match buf.read_events(&mut buffers).await {
                    Ok(events) => {
                        for i in 0..events.read {
                            let buf = &buffers[i];
                            let event = unsafe { (buf.as_ptr() as *const GuardianEvent).read_unaligned() };
                            if let Err(_) = tx.send(event).await {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Error reading events: {}", e);
                        break;
                    }
                }
            }
        });
    }

    let cpu_limit = args.cpu_limit;
    let threshold = args.threshold;

    tokio::spawn(async move {
        let mut analyzer = analysis::Analyzer::new(threshold);
        let cgroup_manager = cgroups::CgroupManager::new();

        while let Some(event) = rx.recv().await {
            if let Some(pid) = analyzer.handle_event(event) {
                info!("Bot detected! PID: {}. Throttling to {}% CPU", pid, cpu_limit);
                if let Err(e) = cgroup_manager.apply_limit(pid, cpu_limit) {
                    error!("Failed to apply cgroup limit to PID {}: {}", pid, e);
                }
            }
        }
    });

    info!("CPU Guardian started. CPU Limit: {}%, Threshold: {}", cpu_limit, threshold);
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

use std::default;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use log::info;
use scx_utils::compat;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::LogRecorderBuilder;
use scx_utils::UserExitInfo;

#[derive(Debug, Parser)]
struct Opts {
    /// Enable verbose output including libbpf details.
    /// Specify multiple times to increase verbosity.
    #[clap(short='v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts) -> Result<Self> {
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 0);
        init_libbpf_logging(None);
        info!("Initializing scx_rorke");
        let mut skel = scx_ops_open!(skel_builder, rorke).unwrap();

        // eBPF field init goes here
        //
        let mut skel = scx_ops_load!(skel, rorke, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, rorke)?);
        info!("scx_rorke started");

        Ok(Self { skel, struct_ops })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {}
        self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    let llv = match opts.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        llv,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Failed to set Ctrl-C handler")?;

    // LogRecorderBuilder::new()
    //     .with_reporting_interval(Duration::from_secs(1))
    //     .install()
    //     .expect("Failed to install log recorder");

    loop {
        let mut sched = Scheduler::init(&opts)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}

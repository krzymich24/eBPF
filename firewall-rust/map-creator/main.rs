use aya::{
    include_bytes_aligned,
    maps::HashMap,
    Bpf,
};
use log::{info, warn};
use aya_log::BpfLogger;
use std::net::Ipv4Addr;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Load the eBPF object file at compile-time
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/map-manager"
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/map-manager"
    ))?;

    // Initialize the eBPF logger
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp =
    bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;

    // Create a rule map
    let mut rule_map: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("rule").unwrap())?;

    // Insert a sample rule into the map
    let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).into();
    rule_map.insert(block_addr, 0, 0)?;

    info!("Rule map created. Waiting for Ctrl-C...");

    // Wait for Ctrl+C signal
    signal::ctrl_c().await?;

    info!("Exiting...");

    Ok(())
}

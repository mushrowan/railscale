//! railscale benchmark runner

use clap::Parser;
use railscale_bench::{harness::Harness, report};

/// protocol-level benchmarks for railscale
#[derive(Parser)]
#[command(name = "railscale-bench")]
struct Cli {
    /// number of simulated nodes
    #[arg(short, long, default_value = "100")]
    nodes: usize,

    /// scenarios to run (registration, map-poll, all)
    #[arg(short, long, default_value = "all")]
    scenario: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    println!("railscale-bench: {} nodes\n", cli.nodes);

    let mut harness = Harness::new().await;

    let run_reg = cli.scenario == "all" || cli.scenario == "registration";
    let run_map = cli.scenario == "all" || cli.scenario == "map-poll";

    if run_reg {
        let result = harness.bench_registration(cli.nodes).await;
        report::print_result(&result);
    } else {
        // need nodes registered for map poll
        harness.bench_registration(cli.nodes).await;
    }

    if run_map {
        let result = harness.bench_map_poll().await;
        report::print_result(&result);
    }
}

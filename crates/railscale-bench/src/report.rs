//! benchmark result reporting

use crate::harness::BenchResult;

/// print a benchmark result as a formatted table
pub fn print_result(result: &BenchResult) {
    println!("── {} ({} nodes) ──", result.scenario, result.node_count);
    println!("  total:    {:>10.2?}", result.total());
    println!("  mean:     {:>10.2?}", result.mean());
    println!("  min:      {:>10.2?}", result.min());
    println!("  p50:      {:>10.2?}", result.p50());
    println!("  p95:      {:>10.2?}", result.p95());
    println!("  p99:      {:>10.2?}", result.p99());
    println!("  max:      {:>10.2?}", result.max());
    println!("  ops/sec:  {:>10.1}", result.ops_per_sec());
    println!();
}

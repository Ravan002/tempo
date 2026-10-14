//! Re-execute frozen eras with their own workers before the live binary continues.

use crate::eras;
use clap::{ArgMatches, FromArgMatches as _};
use eyre::{OptionExt as _, Result, ensure};
use reth_cli_commands::common::{AccessRights, EnvironmentArgs};
use reth_cli_runner::CliRunner;
use reth_ethereum::tasks::RuntimeConfig;
use reth_storage_api::{BlockHashReader as _, BlockNumReader as _};
use std::{ffi::OsString, num::NonZeroUsize, ops::ControlFlow};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_metabinary::process::run_child;
use tempo_node::TempoNode;
use tokio::process::Command;

/// Marks a worker's own re-execution, so a misconfigured catalog cannot delegate it again.
const WORKER_ERA_ENV: &str = "TEMPO_RE_EXECUTE_ERA";

/// Runs the parts of a `re-execute` range owned by frozen eras in their workers, in block order.
/// Returns arguments restricting the live binary to the remaining range, or breaks if none remains.
pub(crate) fn prepare(
    matches: &ArgMatches,
    args: Vec<OsString>,
) -> Result<ControlFlow<(), Option<Vec<OsString>>>> {
    let Some(("re-execute", command)) = matches.subcommand() else {
        return Ok(ControlFlow::Continue(None));
    };
    let environment = EnvironmentArgs::<TempoChainSpecParser>::from_arg_matches(command)?;
    let schedule = match eras::release_schedule(&environment.chain)? {
        Some(schedule) if std::env::var_os(WORKER_ERA_ENV).is_none() => schedule,
        _ => return Ok(ControlFlow::Continue(None)),
    };
    let runner = CliRunner::try_with_runtime_config(
        RuntimeConfig::default().with_cpu_cores(NonZeroUsize::MIN),
    )?;
    let best = {
        let factory = environment
            .init::<TempoNode>(AccessRights::RO, runner.runtime())?
            .provider_factory;
        let provider = factory.provider()?;
        let best = provider.best_block_number()?;
        for checkpoint in schedule.eras.iter().filter_map(|era| era.checkpoint) {
            ensure!(
                checkpoint.number > best
                    || provider.block_hash(checkpoint.number)? == Some(checkpoint.hash),
                "era checkpoint {} is not canonical",
                checkpoint.number
            );
        }
        best
    };

    // Reth re-executes `from..to`, clamping `to` to the best block. Genesis has no parent state.
    let to = command.get_one::<u64>("to").copied();
    let limit = to.map_or(best, |to| to.min(best));
    let start = (*command.get_one::<u64>("from").expect("defaulted")).max(1);
    let (program, args) = args.split_first().ok_or_eyre("missing program name")?;
    runner.block_on(async {
        let mut from = start;
        for era in &schedule.eras {
            let Some(binary) = &era.binary else { break };
            let end = era
                .checkpoint
                .ok_or_eyre("frozen era has no checkpoint")?
                .number
                + 1;
            let until = end.min(limit);
            if from < until {
                eprintln!("Re-executing blocks {from}..{until} with {}", era.name);
                let mut worker = Command::new(binary);
                worker
                    .args(range_args(args, from, Some(until)))
                    .env(WORKER_ERA_ENV, &era.name);
                let Some(status) = run_child(&era.name, &mut worker).await? else {
                    return Ok(ControlFlow::Break(()));
                };
                ensure!(
                    status.success(),
                    "{} re-execution exited with {status}",
                    era.name
                );
            }
            from = from.max(end);
        }
        Ok(if from == start {
            ControlFlow::Continue(None)
        } else if from < limit {
            let live = std::iter::once(program.clone()).chain(range_args(args, from, to));
            ControlFlow::Continue(Some(live.collect()))
        } else {
            ControlFlow::Break(())
        })
    })
}

/// The operator's arguments with the block range replaced.
fn range_args(args: &[OsString], from: u64, to: Option<u64>) -> Vec<OsString> {
    let mut args = args.iter();
    let mut ranged = Vec::new();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--from" | "--to") => {
                args.next();
            }
            Some(arg) if arg.starts_with("--from=") || arg.starts_with("--to=") => {}
            _ => ranged.push(arg.clone()),
        }
    }
    ranged.push(format!("--from={from}").into());
    ranged.extend(to.map(|to| format!("--to={to}").into()));
    ranged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_arguments_replace_operator_bounds() {
        let args = |args: &[&str]| args.iter().map(OsString::from).collect::<Vec<_>>();
        let operator = args(&[
            "re-execute",
            "--from",
            "0",
            "--datadir=/a b",
            "--to=200",
            "-v",
        ]);
        assert_eq!(
            range_args(&operator, 1, Some(100)),
            args(&["re-execute", "--datadir=/a b", "-v", "--from=1", "--to=100"])
        );
        assert_eq!(
            range_args(&args(&["re-execute"]), 100, None),
            args(&["re-execute", "--from=100"])
        );
    }
}

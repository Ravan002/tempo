//! Shared test fixtures.
//!
//! Threshold certificates need a dealt DKG output, which is expensive to
//! reproduce and easy to get subtly wrong. Both the follower driver and the
//! `tempo/1` actor need one, so it lives here rather than in either.

use std::{future::Future, iter::repeat_with};

use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf::Scheme,
        types::{Finalization, Finalize, Proposal},
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt as dkg,
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_math::algebra::Random as _;
use commonware_parallel::Sequential;
use commonware_runtime::deterministic;
use commonware_utils::{N3f1, TryFromIterator as _, ordered};
use futures::future::LocalBoxFuture;
use rand_core::CryptoRng;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

use crate::consensus::Digest;

/// A dealt DKG output together with signers able to form a quorum over it.
pub(crate) struct DkgFixture {
    pub(crate) outcome: OnchainDkgOutcome,
    pub(crate) schemes: Vec<Scheme<PublicKey, MinSig>>,
}

pub(crate) fn dkg_fixture(rng: &mut impl CryptoRng, epoch: Epoch) -> DkgFixture {
    let player_keys = repeat_with(|| PrivateKey::random(&mut *rng))
        .take(4)
        .collect::<Vec<_>>();
    let players = ordered::Set::try_from_iter(
        player_keys
            .iter()
            .map(|private_key| private_key.public_key()),
    )
    .expect("test players should be unique");

    let (output, shares) =
        dkg::deal::<_, _, N3f1>(&mut *rng, Mode::NonZeroCounter, players).expect("test DKG");

    let schemes = shares
        .into_iter()
        .map(|(_, share)| {
            Scheme::signer(
                crate::config::NAMESPACE,
                output.players().clone(),
                output.public().clone(),
                share,
            )
            .expect("test share should match the public polynomial")
        })
        .collect();

    let outcome = OnchainDkgOutcome {
        epoch: epoch.get(),
        next_players: output.players().clone(),
        output,
        is_next_full_dkg: false,
    };

    DkgFixture { outcome, schemes }
}

/// Builds a finalization certificate over an arbitrary payload.
pub(crate) fn make_certificate(
    payload: Digest,
    epoch: Epoch,
    view: u64,
    schemes: &[Scheme<PublicKey, MinSig>],
) -> Finalization<Scheme<PublicKey, MinSig>, Digest> {
    let proposal = Proposal::new(Round::new(epoch, View::new(view)), View::zero(), payload);
    let votes = schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("signer should sign"))
        .collect::<Vec<_>>();

    Finalization::from_finalizes(
        &schemes[0],
        commonware_utils::non_empty![@&votes],
        &Sequential,
    )
    .expect("all test signers form a quorum")
}

/// Runs deterministic tests without compiling the runtime loop for each test future.
pub(crate) trait TestRunner {
    /// Starts the runtime with a type-erased root task, preserving borrowed test data.
    fn start<'a, TTask, TFuture>(self, task: TTask) -> TFuture::Output
    where
        TTask: FnOnce(deterministic::Context) -> TFuture + 'a,
        TFuture: Future + 'a;
}

impl TestRunner for deterministic::Runner {
    fn start<'a, TTask, TFuture>(self, task: TTask) -> TFuture::Output
    where
        TTask: FnOnce(deterministic::Context) -> TFuture + 'a,
        TFuture: Future + 'a,
    {
        // Erase both types: boxing only the future still instantiates the runtime
        // once per closure passed to Runner::start.
        let task: Box<
            dyn FnOnce(deterministic::Context) -> LocalBoxFuture<'a, TFuture::Output> + 'a,
        > = Box::new(move |context| Box::pin(task(context)));
        commonware_runtime::Runner::start(self, task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{cell::Cell, rc::Rc, time::Duration};

    use commonware_runtime::Clock as _;

    #[test]
    fn runner_preserves_borrowed_non_send_futures_and_outputs() {
        let value = String::from("borrowed output");
        let calls = Rc::new(Cell::new(0));
        let output = deterministic::Runner::timed(Duration::from_secs(1)).start(|context| {
            let value = &value;
            let calls = &calls;
            async move {
                context.sleep(Duration::from_millis(1)).await;
                calls.set(calls.get() + 1);
                value.as_str()
            }
        });
        assert_eq!(output, value);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    #[should_panic(expected = "root test panic")]
    fn runner_propagates_panics() {
        deterministic::Runner::default().start(|_| async {
            panic!("root test panic");
        });
    }
}

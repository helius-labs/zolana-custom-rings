# CI

The `ci` workflow runs on pushes to `main`, pull request changes and manual dispatch.
Draft pull requests run the Zolana pin check and skip the test jobs.

Manual dispatch defaults to `validation=full` and runs the complete localnet matrix and TypeScript live tests.
Set `validation=sanity` to run `just test-custom-ring-sanity` as the localnet suite.
That mode omits TypeScript live tests and keeps the build, lint, unit, package and documentation checks.
It reports `ci sanity result`, which does not replace the required `ci result` check.

The localnet matrix runs each shape and full capacity sweep of `program-tests/custom-ring/tests/ring_shapes.rs` as its own job.
Those sweeps prove every catalog key.

Dispatch the final pushed branch after the Zolana pin passes its release source check and the pinned proving keys are public.
The `prover` and `ring-indexer` workflows have separate manual dispatches.
The prover workflow requires the pinned keys for its installed circuit and anonymous tag checks.
The sanity mode does not run those workflows.

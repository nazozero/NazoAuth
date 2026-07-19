# Property-test regression corpus

The files under `support/` are minimized inputs previously found by `proptest`.
They are committed intentionally: `proptest` replays them before generating new
cases, so a defect that once failed remains a deterministic regression test.

This directory is test data, not a runtime cache. It is not copied into the
production container or included in the server binaries. Do not delete a seed
merely because the current implementation passes it. Remove one only when the
corresponding property no longer exists and the same boundary is covered by a
replacement test.

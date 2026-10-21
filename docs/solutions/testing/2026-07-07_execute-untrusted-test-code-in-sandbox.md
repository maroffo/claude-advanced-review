# ABOUTME: How to run LLM-authored test code without giving it the host
# ABOUTME: Ephemeral network-less container + a status that keeps unverifiable findings visible

# Problem

The reviewer LLMs propose a red-green test to prove each bug finding. To keep
a finding, the pipeline must actually run that test. But the test is a string
authored by a model that just read an untrusted diff, so running it on the
host with `pytest`/`npm test`/`go test` is arbitrary code execution (CWE-94/95)
with the operator's credentials in reach. Syntax and relevance checks do not
constrain runtime behavior.

# Solution

Execute the proposed test in an ephemeral, locked-down container, per detected
toolchain, with no host fallback:

```
docker run --rm --network none --pids-limit 256 --memory 1g \
  --read-only --tmpfs /tmp \
  -v <project>:/workspace:ro -v <test-file>:/review/<name>:ro \
  -w /workspace <toolchain-image> <run test with in-container timeout>
```

Toolchain -> image map is a module constant (python:3.12-slim, node:22-slim,
golang:1.23, rust:1-slim, ruby:3-slim). Classify the outcome into three, not
two:

- test **fails** in the sandbox -> bug demonstrated, finding survives (red).
- test **passes** -> not demonstrated, dropped (unproven).
- sandbox **cannot deliver a verdict** (docker/image/deps missing, timeout,
  exit 125/126/127/124, `ModuleNotFoundError`/`Cannot find module`/... in
  output) -> new status `sandbox_unavailable`: the finding SURVIVES, reason
  recorded, and it flows to the human like the old `skipped`.

Signatures for "infra/deps missing" are deliberately specific so a genuine
`AssertionError` (pytest exit 1) is never misread as a missing dependency.

# Why It Works

`--network none` plus `--read-only` plus pid/memory caps means the worst a
malicious test can do is spin briefly inside a throwaway container with no
egress and no writable host filesystem; the credentials it wanted are on the
host it cannot reach. The three-way outcome is what makes it safe to adopt:
collapsing "couldn't run it" into either "proven" or "dropped" would let a
sandbox that is merely missing a dependency silently change the finding set.
Keeping `sandbox_unavailable` as a first-class, surviving status preserves the
finding and the fact that we could not verify it.

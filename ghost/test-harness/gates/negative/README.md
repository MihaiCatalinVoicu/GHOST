# Negative fixtures for CI gates

Each file here intentionally violates a rule. `scripts/gates/self-test.sh` runs every gate with
`GHOST_ROOT` pointed at this directory and fails if a gate lets the fixture pass. Nothing here is
compiled or shipped.

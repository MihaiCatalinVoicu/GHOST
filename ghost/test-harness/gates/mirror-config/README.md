# Fixture roots for `mirror-config.sh` (G-D10)

Each root mirrors `infra/mirror/` (the entrypoint carrying the nginx configuration and the
compose file). Run by `scripts/gates/self-test.sh` through the GHOST_D10_ROOT hook.

| Root | Expected |
|---|---|
| `good` | passes: the full no-log line list, two listeners, per-service `logging: driver: none` |
| `bad-access-log` | fails: a kept access log (the staging tree's real gap, in isolation) |

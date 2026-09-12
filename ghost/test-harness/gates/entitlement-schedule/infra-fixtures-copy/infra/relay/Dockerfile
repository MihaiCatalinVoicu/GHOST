# Negative fixture (entitlement-schedule.sh): the relay image copies a schedule kept under an infra
# tests/fixtures directory (a directory name hides no second copy).
FROM debian:bookworm-slim
COPY infra/relay/tests/fixtures/protocol/entitlement/schedule.ghes /etc/ghost/schedule.ghes

# Negative fixture (entitlement-schedule.sh): the relay image takes its schedule from a second
# repository path instead of protocol/entitlement/schedule.ghes.
FROM debian:bookworm-slim
COPY infra/relay/schedule.ghes /etc/ghost/schedule.ghes

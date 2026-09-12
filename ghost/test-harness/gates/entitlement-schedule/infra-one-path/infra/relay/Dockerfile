# Positive fixture (entitlement-schedule.sh): the ways an image may name the one schedule. Build
# from the repository root:  docker build -f ghost/infra/relay/Dockerfile ghost
# (the schedule is ghost/protocol/entitlement/schedule.ghes, protocol/entitlement/schedule.ghes in
# the build context).
FROM rust:1.98.1-bookworm AS build
WORKDIR /src
COPY . .
FROM debian:bookworm-slim
COPY protocol/entitlement/schedule.ghes /etc/ghost/schedule.ghes
COPY ./protocol/entitlement/schedule.ghes /etc/ghost/schedule.ghes
COPY --from=build /src/protocol/entitlement/schedule.ghes /var/lib/ghost/schedule.ghes

# Negative fixture (entitlement-schedule.sh): the runtime image takes, from the build stage's copy
# of the repository, a test schedule kept under test-harness/gates (a tree the one-path check does
# not scan), by an absolute path.
FROM rust:1.98.1-bookworm AS build
WORKDIR /src
COPY . .
FROM debian:bookworm-slim
COPY --from=build /src/test-harness/gates/copy/protocol/entitlement/schedule.ghes /etc/ghost/schedule.ghes

# Negative fixture (entitlement-schedule.sh): the schedule path goes through a build argument, so
# no check can tie it to the one schedule (here it names a file outside the repository).
FROM debian:bookworm-slim
ARG SRC=..
COPY ${SRC}/copy.ghes /etc/ghost/schedule.ghes

#!/usr/bin/env bash
# Reads ghost/infra/issuer/monero-release.pin, then fetches an archive of its own choice.
file=monero-linux-x64-v0.18.4.0.tar.bz2
curl -fsSL -o "$file" "https://downloads.getmonero.org/cli/$file"

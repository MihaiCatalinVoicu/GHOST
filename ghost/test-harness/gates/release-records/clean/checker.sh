#!/bin/sh
case "$1" in
  *checker-refused*) echo 'RECORDS_BAD stagenet' >&2; exit 1 ;;
  *) echo 'RECORDS_OK network=stagenet roots=1 newest=1 signers=skip anchors=skip' ;;
esac

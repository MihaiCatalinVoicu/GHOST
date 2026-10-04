# no-logging.sh fixture for the media crate (gate G-M7, Phase 11 design faza11-media.md §13.1, §16.1)

`client-core/media/src/lib.rs` holds a logging macro and a print macro; `no-logging.sh`, which reads
every client-core crate's sources, must report both lines of that file (`self-test.sh`).

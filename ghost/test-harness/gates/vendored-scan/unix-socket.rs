// G-R8 scanner fixture: a local socket, which the network names of std::net do not cover.
// One site: UnixStream, line 5.

pub fn dial() -> bool {
    std::os::unix::net::UnixStream::connect("/tmp/ghost").is_ok()
}

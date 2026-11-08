# ghost-builder — the pinned build environment for release ceremonies
# (docs/design/faza14-distribution.md §6, gate G-D2, decision D11). Recipe A's host half
# and Android half both run inside this image so every environment — A, B, C and the
# owner's independent rebuild (RK1 step 2) — shares identical toolchain bytes, not
# merely version numbers.
#
# D11 compliance: every toolchain input is fetched directly (no sdkmanager, no rustup)
# and verified against the digest recorded below and in pins.txt; the processor count
# every tool sees is pinned to 2 (JAVA_TOOL_OPTIONS / CARGO_BUILD_JOBS / Gradle workers —
# not `docker run --cpus`, which Docker refuses above the host count); build paths are
# fixed by build-release.sh's remap (work dir -> /build).
#
# Bump policy: never retag in place. A toolchain change is a new pins.txt entry, a new
# image tag (24.04-<n+1>), and a re-measured selfcheck before any ceremony uses it.
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac

ENV DEBIAN_FRONTEND=noninteractive
# The apt archive is a moving target: a version the pins name can disappear from the live
# archive between two image builds (measured 2026-11-08: ca-certificates=20260816ubuntu0.24.04.2
# gone from the live archive ten days after the pins were taken). Every apt source therefore
# points at the pinned Ubuntu snapshot (pins.txt: apt-snapshot), and the exact package
# versions below are recorded there — the same discipline as the toolchain archives.
# noble-security is absent from the snapshot service at this timestamp (one index always
# 404s); no pinned package needs it (verified: every pin resolves from main/updates alone).
RUN rm -f /etc/apt/sources.list.d/ubuntu.sources \
    && printf '%s\n' \
      'deb https://snapshot.ubuntu.com/ubuntu/20261026T000000Z noble main restricted universe multiverse' \
      'deb https://snapshot.ubuntu.com/ubuntu/20261026T000000Z noble-updates main restricted universe multiverse' \
      > /etc/apt/sources.list
# Exact apt versions as of the base-image snapshot; pins.txt records them. gcc/glibc
# versions are part of the release environment exactly like rustc's. Error-Mode=any turns
# a missing index into a hard failure instead of a half-updated cache.
RUN apt-get update -o APT::Update::Error-Mode=any \
    && apt-get install -y --no-install-recommends \
      build-essential=12.10ubuntu1 \
      ca-certificates=20260816ubuntu0.24.04.2 \
      curl=8.5.0-2ubuntu10.16 \
      git=1:2.43.0-1ubuntu7.4 \
      g++-mingw-w64-x86-64=13.2.0-6ubuntu1+26.1 \
      pkg-config=1.8.1-2build1 \
      protobuf-compiler=3.21.12-8.2ubuntu0.4 \
      unzip=6.0-28ubuntu4.1 \
      zip=3.0-13ubuntu0.2 \
    && rm -rf /var/lib/apt/lists/*

# --- Processor-count pin (D11): every JVM, cargo and Gradle sees 2 processors. ---
# HOME=/home/builder: a real, unique path. The leak check in scripts/build-native.sh greps
# the .so for $HOME's spellings; the distroless container default (/, or /tmp via tmpfs)
# is a substring of legitimate embedded strings (e.g. temp-dir constants) and trips it.
ENV JAVA_TOOL_OPTIONS="-XX:ActiveProcessorCount=2" \
    GRADLE_OPTS="-Dorg.gradle.workers.max=2" \
    CARGO_BUILD_JOBS=2 \
    HOME=/home/builder
# AGP writes under $HOME (.android, caches); the runtime user (image consumers run as
# arbitrary uids) must be able to create it.
RUN mkdir -p /home/builder && chmod 1777 /home/builder

# --- JDK (Temurin 17, official SHA-256 from the Adoptium API) ---
ARG JDK_URL=https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.21%2B9/OpenJDK17U-jdk_x64_linux_hotspot_17.0.21_9.tar.gz
ARG JDK_SHA256=8b9b611d917e3dfd8419d3566b5949226f69b052fed7e109c1368add1dfe8711
RUN curl -fSL "$JDK_URL" -o /tmp/jdk.tar.gz \
    && echo "$JDK_SHA256  /tmp/jdk.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/jdk && tar -xzf /tmp/jdk.tar.gz -C /opt/jdk --strip-components=1 \
    && rm /tmp/jdk.tar.gz
ENV JAVA_HOME=/opt/jdk \
    PATH=/opt/jdk/bin:$PATH

# --- Rust 1.98.1 (direct dist archives; sha256 from static.rust-lang.org) + Android std ---
ARG RUST_SHA256=24ba1338a2d35c5a3247936546429e163fa674d726102af18bdf624582c57aea
ARG RUST_STD_AARCH64_SHA256=ba22ece6e6c2051bc20c05b2d7e809ec9fe1e656b02033424db30deca084c4a9
ARG RUST_STD_X86_64_SHA256=8bb372f26cc9813d3685a1bbd73ff04de8e3d4aeb6f3779c354436c594d3f013
RUN curl -fSL https://static.rust-lang.org/dist/rust-1.98.1-x86_64-unknown-linux-gnu.tar.gz -o /tmp/rust.tar.gz \
    && echo "$RUST_SHA256  /tmp/rust.tar.gz" | sha256sum -c - \
    && mkdir -p /tmp/rust && tar -xzf /tmp/rust.tar.gz -C /tmp/rust --strip-components=1 \
    && /tmp/rust/install.sh --prefix=/opt/rust --without=rust-docs \
    && rm -rf /tmp/rust /tmp/rust.tar.gz
RUN curl -fSL https://static.rust-lang.org/dist/rust-std-1.98.1-aarch64-linux-android.tar.gz -o /tmp/std-a.tar.gz \
    && echo "$RUST_STD_AARCH64_SHA256  /tmp/std-a.tar.gz" | sha256sum -c - \
    && mkdir -p /tmp/std-a && tar -xzf /tmp/std-a.tar.gz -C /tmp/std-a --strip-components=1 \
    && /tmp/std-a/install.sh --prefix=/opt/rust \
    && rm -rf /tmp/std-a /tmp/std-a.tar.gz
RUN curl -fSL https://static.rust-lang.org/dist/rust-std-1.98.1-x86_64-linux-android.tar.gz -o /tmp/std-x.tar.gz \
    && echo "$RUST_STD_X86_64_SHA256  /tmp/std-x.tar.gz" | sha256sum -c - \
    && mkdir -p /tmp/std-x && tar -xzf /tmp/std-x.tar.gz -C /tmp/std-x --strip-components=1 \
    && /tmp/std-x/install.sh --prefix=/opt/rust \
    && rm -rf /tmp/std-x /tmp/std-x.tar.gz
# ghost-verify's public targets (design §6.1 kinds 19-22; pins.txt). The musl stds build
# the static Linux binaries from the exported public tree; the windows-gnu std is pinned
# for when the mingw-w64 linker lands (build-release.sh's GHOST_RELEASE_CROSS guard fails
# loudly on the Windows target until then — see pins.txt's note).
ARG RUST_STD_X86_64_MUSL_SHA256=ac111ad77967e98d0362e49a2c19121f3f54e4e68c247b90995e665687ebede8
ARG RUST_STD_AARCH64_MUSL_SHA256=630ed4ccdc9877864aa3bd8689161dffd8987c7a923bf01e50c7d8affef7ae47
ARG RUST_STD_WINDOWS_GNU_SHA256=0cda26447df0749bc84044be8c8083ac4dc87bf137c11cc31ec9673a6e2e0344
RUN curl -fSL https://static.rust-lang.org/dist/rust-std-1.98.1-x86_64-unknown-linux-musl.tar.gz -o /tmp/std-xm.tar.gz \
    && echo "$RUST_STD_X86_64_MUSL_SHA256  /tmp/std-xm.tar.gz" | sha256sum -c - \
    && mkdir -p /tmp/std-xm && tar -xzf /tmp/std-xm.tar.gz -C /tmp/std-xm --strip-components=1 \
    && /tmp/std-xm/install.sh --prefix=/opt/rust \
    && rm -rf /tmp/std-xm /tmp/std-xm.tar.gz
RUN curl -fSL https://static.rust-lang.org/dist/rust-std-1.98.1-aarch64-unknown-linux-musl.tar.gz -o /tmp/std-am.tar.gz \
    && echo "$RUST_STD_AARCH64_MUSL_SHA256  /tmp/std-am.tar.gz" | sha256sum -c - \
    && mkdir -p /tmp/std-am && tar -xzf /tmp/std-am.tar.gz -C /tmp/std-am --strip-components=1 \
    && /tmp/std-am/install.sh --prefix=/opt/rust \
    && rm -rf /tmp/std-am /tmp/std-am.tar.gz
RUN curl -fSL https://static.rust-lang.org/dist/rust-std-1.98.1-x86_64-pc-windows-gnu.tar.gz -o /tmp/std-w.tar.gz \
    && echo "$RUST_STD_WINDOWS_GNU_SHA256  /tmp/std-w.tar.gz" | sha256sum -c - \
    && mkdir -p /tmp/std-w && tar -xzf /tmp/std-w.tar.gz -C /tmp/std-w --strip-components=1 \
    && /tmp/std-w/install.sh --prefix=/opt/rust \
    && rm -rf /tmp/std-w /tmp/std-w.tar.gz
# The musl C cross toolchains (pins.txt's musl_cc lines; musl.cc static builds, hashed at
# pin time). ghost-verify's static Linux targets link through these; cc-rs also finds them
# by the target-triple name via PATH. Extraction keeps a fixed path for the cargo config.
ARG MUSL_X86_64_SHA256=c5d410d9f82a4f24c549fe5d24f988f85b2679b452413a9f7e5f7b956f2fe7ea
ARG MUSL_AARCH64_SHA256=c909817856d6ceda86aa510894fa3527eac7989f0ef6e87b5721c58737a06c38
RUN curl -fSL https://musl.cc/x86_64-linux-musl-cross.tgz -o /tmp/musl-x.tgz \
    && echo "$MUSL_X86_64_SHA256  /tmp/musl-x.tgz" | sha256sum -c - \
    && mkdir -p /opt/musl-x86_64 && tar -xzf /tmp/musl-x.tgz -C /opt/musl-x86_64 --strip-components=1 \
    && rm -f /tmp/musl-x.tgz
RUN curl -fSL https://musl.cc/aarch64-linux-musl-cross.tgz -o /tmp/musl-a.tgz \
    && echo "$MUSL_AARCH64_SHA256  /tmp/musl-a.tgz" | sha256sum -c - \
    && mkdir -p /opt/musl-aarch64 && tar -xzf /tmp/musl-a.tgz -C /opt/musl-aarch64 --strip-components=1 \
    && rm -f /tmp/musl-a.tgz
# The linker wiring under CARGO_HOME (appended — this file may gain other sections): the
# musl targets link with the toolchains above; host and Android builds are untouched (no
# default target is set).
RUN mkdir -p /opt/cargo && touch /opt/cargo/config.toml \
    && printf '%s\n' \
         '[target.x86_64-unknown-linux-musl]' \
         'linker = "/opt/musl-x86_64/bin/x86_64-linux-musl-gcc"' \
         '' \
         '[target.aarch64-unknown-linux-musl]' \
         'linker = "/opt/musl-aarch64/bin/aarch64-linux-musl-gcc"' \
         >> /opt/cargo/config.toml
ENV PATH=/opt/rust/bin:/opt/musl-x86_64/bin:/opt/musl-aarch64/bin:$PATH \
    CARGO_HOME=/opt/cargo
RUN mkdir -p /opt/cargo && chmod -R a+w /opt/cargo /opt/rust /opt/musl-x86_64 /opt/musl-aarch64

# cargo-ndk 4.1.2, same pin as scripts/build-native.sh and CI (--locked: the crate's own
# Cargo.lock decides its deps; the image's rustc compiles it).
RUN cargo install cargo-ndk --version 4.1.2 --locked

# --- Android SDK, direct archives (official SHA-1 from dl.google.com repository2-*.xml) ---
# Layout matches sdkmanager's: build-tools/<v>, platforms/android-<v>, platform-tools,
# cmdline-tools/latest, ndk/<version>. No sdkmanager, no license flow.
ARG SDK=https://dl.google.com/android/repository
ARG CT_SHA1=d313adb7aedccf6cf0cfca51ec180f0059f5f8f8
ARG PT_SHA1=477254aa5f903c15cf51001717bdf347fb6b53e0
ARG P370_SHA1=ed8ebf7f8822a4de5686d427f237d2fa30ff7410
ARG P372_SHA1=4bec12a02162ff6852df50b5fcf8ee762b050966
ARG BT37_SHA1=70954e99f4c3d9d46ee70fa32624672fe7cd6ebe
ARG BT36_SHA1=b0b6376977657e8ad9b969bacf4093601da2c6fb
ARG NDK_SHA1=5107f898313790e449e87eee2183d9a20602dee9
RUN mkdir -p /opt/android-sdk && cd /tmp \
    && curl -fSL $SDK/commandlinetools-linux-11076708_latest.zip -o ct.zip \
    && echo "$CT_SHA1  ct.zip" | sha1sum -c - \
    && mkdir ctd && unzip -q ct.zip -d ctd && mkdir -p /opt/android-sdk/cmdline-tools/latest \
    && mv ctd/cmdline-tools/* /opt/android-sdk/cmdline-tools/latest/ \
    && curl -fSL $SDK/platform-tools_r37.0.1-linux.zip -o pt.zip \
    && echo "$PT_SHA1  pt.zip" | sha1sum -c - \
    && mkdir ptd && unzip -q pt.zip -d ptd \
    && mv ptd/platform-tools /opt/android-sdk/platform-tools \
    && rm -rf ct.zip ctd pt.zip ptd
RUN cd /tmp \
    && curl -fSL $SDK/platform-37.0_r02.zip -o p.zip \
    && echo "$P370_SHA1  p.zip" | sha1sum -c - \
    && mkdir pd && unzip -q p.zip -d pd \
    && mkdir -p /opt/android-sdk/platforms \
    && mv pd/android-37.0 /opt/android-sdk/platforms/android-37.0 \
    && curl -fSL $SDK/platform-37.2_r01.zip -o p2.zip \
    && echo "$P372_SHA1  p2.zip" | sha1sum -c - \
    && mkdir p2d && unzip -q p2.zip -d p2d \
    && mv p2d/android-37.2 /opt/android-sdk/platforms/android-37.2 \
    && curl -fSL $SDK/build-tools_r37_linux.zip -o b37.zip \
    && echo "$BT37_SHA1  b37.zip" | sha1sum -c - \
    && mkdir b37d && unzip -q b37.zip -d b37d && mkdir -p /opt/android-sdk/build-tools/37.0.0 \
    && mv b37d/*/* /opt/android-sdk/build-tools/37.0.0/ \
    && curl -fSL $SDK/build-tools_r36_linux.zip -o b36.zip \
    && echo "$BT36_SHA1  b36.zip" | sha1sum -c - \
    && mkdir b36d && unzip -q b36.zip -d b36d && mkdir -p /opt/android-sdk/build-tools/36.0.0 \
    && mv b36d/*/* /opt/android-sdk/build-tools/36.0.0/ \
    && rm -rf p.zip pd p2.zip p2d b37.zip b37d b36.zip b36d
RUN cd /tmp \
    && curl -fSL $SDK/android-ndk-r30-linux.zip -o ndk.zip \
    && echo "$NDK_SHA1  ndk.zip" | sha1sum -c - \
    && unzip -q ndk.zip -d ndkd \
    && mkdir -p /opt/android-sdk/ndk \
    && mv ndkd/android-ndk-r30 /opt/android-sdk/ndk/30.0.16248370 \
    && rm -rf ndk.zip ndkd
ENV ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    ANDROID_NDK_HOME=/opt/android-sdk/ndk/30.0.16248370

# License markers: with a manual-install SDK there is no sdkmanager --licenses step; AGP
# refuses to build without these. The values are the public accepted-marker hashes every
# sdkmanager --licenses writes; baking them into the builder = the owner accepting the
# SDK license terms for builds run inside this image.
RUN mkdir -p /opt/android-sdk/licenses \
    && echo "24333f8a63b6825ea9c5514f83c2829b004d1fee" > /opt/android-sdk/licenses/android-sdk-license \
    && echo "84831b9409646a918e30573bab4c9c91346d8abd" > /opt/android-sdk/licenses/android-sdk-preview-license \
    && echo "d975f751698a77b662f1254ddbeed3901e976f5a" > /opt/android-sdk/licenses/intel-android-extra-license

# package.xml install metadata: AGP's SDK loader only registers components that carry it,
# and sdkmanager normally writes it at install time. These files are generated from the
# SAME pinned repository2 manifests the archive sha1 values above come from (the generator
# is infra/builder/gen-package-xml.py; outputs validated field-by-field against
# sdkmanager-installed samples), so a manual-install SDK is indistinguishable from a
# managed one — without ever running sdkmanager.
COPY package-xml/platforms_android-37.0.xml /opt/android-sdk/platforms/android-37.0/package.xml
COPY package-xml/platforms_android-37.2.xml /opt/android-sdk/platforms/android-37.2/package.xml
COPY package-xml/build-tools_37.0.0.xml /opt/android-sdk/build-tools/37.0.0/package.xml
COPY package-xml/build-tools_36.0.0.xml /opt/android-sdk/build-tools/36.0.0/package.xml
COPY package-xml/platform-tools.xml /opt/android-sdk/platform-tools/package.xml
COPY package-xml/cmdline-tools_12.0.xml /opt/android-sdk/cmdline-tools/latest/package.xml
COPY package-xml/ndk_30.0.16248370.xml /opt/android-sdk/ndk/30.0.16248370/package.xml

WORKDIR /src

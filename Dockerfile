FROM debian:sid-slim

RUN apt update && apt upgrade -y && \
  apt install -y python3 python3-pip python3-venv \
  lsb-release wget software-properties-common gnupg \
  git \
  build-essential libtool autotools-dev automake pkg-config bsdmainutils \
  libevent-dev libboost-dev libsqlite3-dev \
  ccache \
  vim \
  curl

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh
RUN ./llvm.sh 18 all

ENV LLVM_CONFIG=llvm-config-18
RUN git clone --branch stable https://github.com/AFLplusplus/AFLplusplus
RUN cd AFLplusplus && make PERFORMANCE=1 install -j$(nproc)

RUN git clone https://github.com/dergoegge/semsan.git
RUN cd semsan/ && cargo install --path . --verbose

RUN git clone --branch "27.x" https://github.com/bitcoin/bitcoin.git

# Build libbitcoinconsensus with -fsanitize=fuzzer-no-link, i.e. for fuzzing with libFuzzer
ENV CC clang-18
ENV CXX clang++-18
ENV LDFLAGS "-fuse-ld=lld"
ENV CCACHE_DIR /ccache/
RUN --mount=type=cache,target=/ccache/ \
  cd bitcoin && ./autogen.sh && \
  ./configure --with-sanitizers=fuzzer-no-link --disable-tests --disable-bench --disable-wallet && \
  make -j$(nproc) && \
  cp src/.libs/libbitcoinconsensus.a /libbitcoinconsensus_libfuzzer.a && \
  cp src/secp256k1/.libs/libsecp256k1.a /libsecp256k1_libfuzzer.a

# Build libbitcoinconsensus with afl-clang, i.e. for fuzzing with afl++ or semsan
ENV CC afl-clang-fast
ENV CXX afl-clang-fast++
RUN --mount=type=cache,target=/ccache/ \
  cd bitcoin && make clean && ./autogen.sh && \
  ./configure --disable-tests --disable-bench --disable-wallet && \
  make -j$(nproc) && \
  cp src/.libs/libbitcoinconsensus.a /libbitcoinconsensus_afl.a && \
  cp src/secp256k1/.libs/libsecp256k1.a /libsecp256k1_afl.a

WORKDIR /workspace

COPY FuzzedDataProvider.h bitcoinconsensus.h harness.cpp banned_syms.txt .
RUN python3 -m venv .venv

# Build the harness for libfuzzer
RUN clang++-18 -fuse-ld=lld -fsanitize=fuzzer harness.cpp /libbitcoinconsensus_libfuzzer.a /libsecp256k1_libfuzzer.a -o fuzz_libfuzzer
# Build the harness for afl++
RUN afl-clang-fast++ -fuse-ld=lld -fsanitize=fuzzer harness.cpp /libbitcoinconsensus_afl.a /libsecp256k1_afl.a -o fuzz_afl

# cp fuzz_afl fuzz_afl_p
# muttfuzz "semsan ./fuzz_afl_p ./fuzz_afl fuzz --seeds /share/corpus --solutions ./semsan-solutions/" ./fuzz_afl \
#   --time_per_mutant 45 --reachability_check_cmd "find /share/corpus -type f -exec ./fuzz_afl {} +" \
#   --score --avoid_repeats --budget 3600 --avoid_mutating_file ./banned_syms.txt --verbose

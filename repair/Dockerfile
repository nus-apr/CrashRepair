FROM christimperley/llvm11
WORKDIR /tmp/crashrepair
COPY . .
ARG INSTALL_TO=/opt/crashrepair
RUN mkdir -p /opt/crashrepair/bin \
 && mkdir build \
 && cd build \
 && cmake \
      -G Ninja \
      -DCMAKE_CXX_COMPILER=/opt/llvm11/bin/clang++ \
      -DCMAKE_LINKER=/opt/llvm11/bin/lld \
      -DCMAKE_INSTALL_PREFIX="${INSTALL_TO}" \
      -DCMAKE_CXX_FLAGS="-std=c++14 -I/opt/llvm11/include -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS" \
      .. \
 && ninja \
 && ninja install \
 && rm -rf /tmp/*

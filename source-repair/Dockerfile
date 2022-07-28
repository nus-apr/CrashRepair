FROM christimperley/llvm11 AS mutator
WORKDIR /tmp/crashrepair
ARG INSTALL_TO=/opt/crashrepair

# z3
COPY extern/z3 extern/z3
RUN cd extern/z3 \
 && mkdir build \
 && cd build \
 && cmake \
       -G Ninja \
      -DCMAKE_CXX_COMPILER=g++ \
      -DCMAKE_INSTALL_PREFIX="${INSTALL_TO}" \
      .. \
 && ninja \
 && ninja install

# crashrepairfix
COPY . .
RUN mkdir -p /opt/crashrepair/bin \
 && mkdir build \
 && cd build \
 && cmake \
      -G Ninja \
      -DCMAKE_CXX_COMPILER=g++ \
      -DCMAKE_INSTALL_PREFIX="${INSTALL_TO}" \
      -DCMAKE_CXX_FLAGS="-w -Wno-error -I/opt/llvm11/include -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS" \
      .. \
 && ninja \
 && ninja install \
 && rm -rf /tmp/*


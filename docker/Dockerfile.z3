FROM crepair:builder
ENV Z3_VERSION=z3-4.8.4
WORKDIR /z3
RUN wget -qO- https://github.com/Z3Prover/z3/archive/${Z3_VERSION}.tar.gz | tar xz --strip-components=1 && \
    python scripts/mk_make.py --prefix=/opt/z3 && \
    cd build && \
    make && \
    make install
ENV PATH "/opt/z3/bin:${PATH}"
ENV LD_LIBRARY_PATH "/opt/z3/lib:${LD_LIBRARY_PATH}"
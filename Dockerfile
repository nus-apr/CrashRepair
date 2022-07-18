FROM ubuntu:18.04
MAINTAINER Ridwan Shariffdeen <ridwan@comp.nus.edu.sg>
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y && apt-get autoremove -y
RUN apt-get install -y build-essential \
                       curl \
                       cmake \
                       git \
                       libcap-dev \
                       libgoogle-perftools-dev \
                       libncurses5-dev \
                       libtcmalloc-minimal4 \
                       libssl-dev \
                       nano \
                       psmisc  \
                       python \
                       software-properties-common \
                       unzip \
                       vim \
                       wget \
                       zlib1g-dev

ENV LLVM_VERSION=6.0
RUN apt-get install -y clang-${LLVM_VERSION} \
                       llvm-${LLVM_VERSION} \
                       llvm-${LLVM_VERSION}-dev \
                       llvm-${LLVM_VERSION}-tools

ENV Z3_VERSION=4.8.4
WORKDIR /z3
RUN wget -qO- https://github.com/Z3Prover/z3/archive/z3-${Z3_VERSION}.tar.gz | tar xz --strip-components=1 && \
    python scripts/mk_make.py && \
    cd build && \
    make && \
    make install
ENV PATH=/usr/lib/llvm-${LLVM_VERSION}/bin/:${PATH}
ENV KLEE_UCLIBC_VERSION=klee_0_9_29
WORKDIR /klee-uclibc
RUN git clone https://github.com/klee/klee-uclibc.git . && \
    git checkout ${KLEE_UCLIBC_VERSION} && \
    CC=clang ./configure --make-llvm-lib && \
    make -j2
ENV KLEE_VERSION=2.0
WORKDIR /klee
ARG KLEE_REVISION=54c7487
RUN git clone https://github.com/rshariffdeen/klee.git source \
 && cd source \
 && git checkout "${KLEE_REVISION}"
RUN mkdir build && \
    cd build && \
    cmake \
        -DENABLE_SOLVER_Z3=ON \
        -DENABLE_POSIX_RUNTIME=ON \
        -DENABLE_KLEE_UCLIBC=ON \
        -DKLEE_UCLIBC_PATH=/klee-uclibc \
        -DENABLE_UNIT_TESTS=OFF \
        -DENABLE_SYSTEM_TESTS=OFF \
            ../source && \
    make
ENV PATH=/klee/build/bin/:${PATH}
ENV LLVM_COMPILER=clang
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y  --no-install-recommends --force-yes \
    bear \
    python3.8 \
    python3.8-dev \
    python3-pip \
    python3-setuptools

RUN python3.8 -m pip install --upgrade pip
RUN python3.8 -m pip --disable-pip-version-check --no-cache-dir install setuptools
RUN python3.8 -m pip --disable-pip-version-check --no-cache-dir install pylint
RUN python3.8 -m pip --disable-pip-version-check --no-cache-dir install cython
RUN python3.8 -m pip --disable-pip-version-check --no-cache-dir install pysmt==0.9.0
RUN pysmt-install --z3 --confirm-agreement
RUN python3.8 -m pip --disable-pip-version-check --no-cache-dir install funcy
RUN python3.8 -m pip --disable-pip-version-check --no-cache-dir install six
RUN python3.8 -m pip --disable-pip-version-check --no-cache-dir install numpy==1.19.1
RUN python3.8 -m pip --disable-pip-version-check --no-cache-dir install wllvm; return 0;

## Install PyPy JITC
RUN add-apt-repository -y ppa:pypy/ppa
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y  --no-install-recommends --force-yes \
    gfortran \
    pypy3 \
    pypy3-dev

RUN pypy3 -m easy_install cython
RUN pypy3 -m easy_install setuptools
#RUN pypy3 -m easy_install pysmt==0.9.0
#RUN pysmt-install --z3 --confirm-agreement
RUN pypy3 -m easy_install funcy
RUN pypy3 -m easy_install six
RUN pypy3 -m easy_install numpy==1.19.1
RUN pypy3 -m easy_install wllvm
RUN python3 -m easy_install wllvm

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y  --no-install-recommends --force-yes \
    clang-tidy \
    clang-10
# ARG CACHEBUST=1
# RUN git clone https://github.com/rshariffdeen/CPR.git /CPR
ADD . /CrashRepair
WORKDIR /CrashRepair
RUN ln -s /CrashRepair/bin/crepair /usr/bin/crepair
ENV CREPAIR_CC=/CrashRepair/compiler/crepair-cc
ENV CREPAIR_CXX=/CrashRepair/compiler/crepair-cxx

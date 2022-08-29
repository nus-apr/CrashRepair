FROM ubuntu:18.04
ARG DEBIAN_FRONTEND=noninteractive
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

# note that GCC 9 must be installed to obtain a newer glibc, but we don't need to use GCC 9 by default
RUN apt-get update -qq \
 && apt-get upgrade -y \
 && apt-get autoremove -y \
 && apt-get install -y --no-install-recommends  \
      apt-transport-https \
      build-essential \
      cmake \
      curl \
      g++ \
      gcc \
      git \
      libboost-all-dev \
      libcap-dev \
      libgoogle-perftools-dev \
      libncurses5-dev \
      libssl-dev \
      libtcmalloc-minimal4 \
      nano \
      ninja-build \
      psmisc  \
      python \
      python3 \
      python3-pip \
      software-properties-common \
      unzip \
      vim \
      wget \
      zlib1g-dev \
 && wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null \
  | gpg --dearmor - \
  | tee /etc/apt/trusted.gpg.d/kitware.gpg > /dev/null \
 && apt-add-repository 'deb https://apt.kitware.com/ubuntu/ xenial main' \
 && add-apt-repository -y ppa:ubuntu-toolchain-r/test \
 && apt-get update -qq \
 && apt-get install -y \
      gcc-9 \
      g++-9 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

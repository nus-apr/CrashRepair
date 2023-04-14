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
 && apt-get install -y \
      jbigkit-bin \
      libfreetype6-dev \
      libgmp-dev \
      libgmp10 \
      libjbig-dev \
      libjbig0 \
      libreadline-dev \
      libreadline5 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# install experiment dependencies
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends  \
      autoconf \
      automake \
      autopoint \
      bear \
      bison \
      ca-certificates \
      cmake \
      curl \
      flex \
      g++-multilib \
      gcc-multilib \
      gettext \
      git \
      gperf \
      libass-dev \
      libbz2-dev \
      libbz2-dev \
      libc6-dev-i386 \
      libfreetype6 \
      libfreetype6-dev \
      libgdbm-dev \
      libgdbm-dev \
      libglib2.0-dev \
      libjpeg-dev \
      libldap-dev \
      liblzma-dev \
      libncurses-dev \
      libnuma-dev \
      libpciaccess-dev \
      libpython-dev \
      libpython3-dev \
      libreadline-gplv2-dev \
      libsdl1.2-dev  \
      libsqlite-dev \
      libsqlite3-dev \
      libsqlite3-dev \
      libsqlite3-dev \
      libssl-dev \
      libssl-dev \
      libtool \
      libvdpau-dev \
      libx11-dev \
      libxcb-shm0-dev \
      libxcb-xfixes0-dev \
      libxcb1-dev \
      libxml2-dev \
      libxml2-dev \
      m4 \
      mercurial \
      mercurial \
      nano \
      nasm \
      openssl \
      pkg-config \
      psmisc \
      psmisc \
      python3 \
      rsync \
      subversion \
      tcl-dev \
      texinfo \
      tix-dev \
      tk-dev \
      unzip \
      wget \
      xutils-dev \
      yasm

# install automake 1.16+
# RUN cd /tmp \
#  && wget -O /tmp/automake.tgz -nv https://ftp.gnu.org/gnu/automake/automake-1.16.3.tar.gz \
#  && tar -xf automake.tgz \
#  && cd automake* \
#  && ./configure \
#  && make \
#  && make install \
#  && rm -rf /tmp/automake*

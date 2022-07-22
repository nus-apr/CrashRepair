FROM ubuntu:18.04
MAINTAINER Ridwan Shariffdeen <ridwan@comp.nus.edu.sg>
ARG DEBIAN_FRONTEND=noninteractive
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8
RUN apt-get update && apt-get upgrade -y && apt-get autoremove -y
RUN apt-get install -y --no-install-recommends  \
       apt-transport-https \
       build-essential \
       curl \
       cmake \
       g++ \
       gcc \
       git \
       libboost-all-dev \
       libcap-dev \
       libgoogle-perftools-dev \
       libncurses5-dev \
       libtcmalloc-minimal4 \
       libssl-dev \
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
       zlib1g-dev

RUN apt-get clean && rm -rf /var/lib/apt/lists/*

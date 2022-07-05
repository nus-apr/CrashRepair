# note that we build on top of xenial to ensure maximum glibc compatibility
# - see https://pyinstaller.org/en/stable/usage.html#making-gnu-linux-apps-forward-compatible
# - alternatively, we could try to use staticx on the pyinstaller-generated binary
FROM ubuntu:xenial-20210416 AS shim
ARG DEBIAN_FRONTEND=noninteractive
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

RUN apt-get update -qq \
 && apt-key adv --refresh-keys --keyserver keyserver.ubuntu.com \
 && apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      curl \
      g++ \
      gcc \
      git \
      libbz2-dev \
      libffi-dev \
      liblzma-dev \
      libncursesw5-dev \
      libreadline-dev \
      libsqlite3-dev \
      libssl-dev \
      libxml2-dev \
      libxmlsec1-dev \
      llvm \
      make \
      software-properties-common \
      tk-dev \
      wget \
      xz-utils \
      zlib1g-dev

# install pyenv
ARG PYENV_GIT_TAG=v2.2.5
RUN curl https://pyenv.run | bash
ENV PATH "/root/.pyenv/bin:$PATH"

# install python 3.9 via pyenv
RUN eval "$(pyenv init --path)" \
 && eval "$(pyenv init -)" \
 && export CFLAGS="-fPIC ${CFLAGS:-}" \
 && export PYTHON_CONFIGURE_OPTS="--enable-shared" \
 && pyenv install 3.9.11 \
 && pyenv global 3.9.11 \
 && pip install pipenv==2022.6.7

# install package and convert to a portable executable
WORKDIR /tmp/crashrepair
COPY python /tmp/crashrepair
RUN eval "$(pyenv init --path)" \
 && eval "$(pyenv init -)" \
 && pipenv install -e . \
 && pipenv run pyinstaller --onefile shim.py \
 && mkdir -p /opt/crashrepair/bin \
 && cp ./dist/shim /opt/crashrepair/bin \
 && mv /opt/crashrepair/bin/shim /opt/crashrepair/bin/crashrepairfix \
 && rm -rf /tmp/*


FROM christimperley/llvm11 AS pass
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


FROM ubuntu:xenial-20210416 AS finished
WORKDIR /opt/crashrepair
COPY --from=pass /opt/crashrepair /opt/crashrepair
COPY --from=shim /opt/crashrepair/bin /opt/crashrepair/bin

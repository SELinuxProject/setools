FROM ubuntu:20.04

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends python3 python3-pip gcc flex bison swig libgl1 qt5-default qt5-assistant libxcb-util1 ruby pkg-config curl make build-essential

COPY requirements.txt /tmp/pip-tmp/
RUN pip3 --disable-pip-version-check --no-cache-dir install -r /tmp/pip-tmp/requirements.txt \
   && rm -rf /tmp/pip-tmp

RUN apt-get -y install --no-install-recommends libpcre3-dev

RUN mkdir /tmp/libsepol \
    && cd /tmp/libsepol \
    && curl -L https://github.com/SELinuxProject/selinux/releases/download/20200710/libsepol-3.1.tar.gz | tar -xz \
    && cd libsepol-3.1 \
    && make -j LIBDIR=/usr/lib64 SHLIBDIR=/lib64 install \
    && rm -r /tmp/libsepol

RUN mkdir /tmp/selinux \
    && cd /tmp/selinux \
    && curl -L https://github.com/SELinuxProject/selinux/releases/download/20200710/libselinux-3.1.tar.gz | tar -xz \
    && cd libselinux-3.1 \
    && make -j LIBDIR=/usr/lib64 SHLIBDIR=/lib64 install \
    && rm -r /tmp/selinux

RUN apt-get -y install --no-install-recommends python3-dev
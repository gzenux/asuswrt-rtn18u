FROM ubuntu:16.04

LABEL maintainer="YiJun Chen <gzenux@gmail.com>"


# install basic packages
RUN dpkg --add-architecture i386 && apt-get update && apt-get install -y locales sudo

# install required packages
RUN apt-get update && apt-get install -y \
	autogen autopoint \
	binutils-dev bison build-essential \
	cmake \
	device-tree-compiler docbook-xsl-* dos2unix \
	flex \
	g++-multilib gawk gengetopt git gperf gtk-doc-tools \
	intltool \
	libtool libtool-bin lzma lzma-dev \
	mtd-utils \
	python \
	sharutils shtool \
	texinfo tofrodos \
	u-boot-tools uuid-dev \
	xsltproc xutils-dev \
	libglib2.0-dev liblzma-dev liblzo2-dev \
	libncurses5-dev \
	libstdc++5

# install 32-bit packages in Ubuntu amd64
RUN apt-get update && apt-get install -y \
	lib32ncurses5 lib32stdc++6 lib32z1 \
	libc6-dev-i386 \
	libelf1:i386 \
	libncurses5:i386


# get arguments
ARG UID=1000
ARG USER=user
ARG HOME=/home/${USER}
ARG LANG=en_US.UTF-8
ARG LANGUAGES="zh_TW.UTF-8 ${LANG}"

# set environment variables
ENV USER ${USER}
ENV LANG ${LANG}
ENV LANGUAGE ${LANG}


# generate locale
RUN locale-gen $LANGUAGES

# use bash as default shell
RUN echo "dash dash/sh boolean false" | debconf-set-selections && dpkg-reconfigure -f noninteractive dash

# Add user and switch to the user
RUN mkdir -p $(dirname ${HOME}) && useradd -m -u ${UID} -d ${HOME} ${USER} && passwd -d ${USER} && \
gpasswd -a ${USER} sudo && sed -i 's:%sudo\tALL=(ALL\:ALL) ALL:%sudo\tALL=NOPASSWD\: ALL:g' /etc/sudoers


USER ${USER}
WORKDIR ${HOME}

CMD ["/bin/bash"]

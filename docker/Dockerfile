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
	libtool lzma lzma-dev \
	mtd-utils \
	python \
	sharutils shtool \
	texinfo tofrodos \
	u-boot-tools uuid-dev \
	xsltproc \
	libglib2.0-dev liblzma-dev liblzo2-dev \
	libncurses5-dev \
	libstdc++5

# install 32-bit packages in Ubuntu amd64
RUN apt-get update && apt-get install -y \
	lib32ncurses5 lib32stdc++6 lib32z1 \
	libc6-dev-i386 \
	libelf1:i386 \
	libncurses5:i386


# Add user and switch to the user
ARG UID=1000
ARG USER=user
ARG HOME=/home/${USER}
RUN useradd -m -u ${UID} -d ${HOME} ${USER} && passwd -d ${USER} && \
gpasswd -a ${USER} sudo && sed -i 's:%sudo\tALL=(ALL\:ALL) ALL:%sudo\tALL=NOPASSWD\: ALL:g' /etc/sudoers

USER ${USER}
WORKDIR ${HOME}

CMD ["/bin/bash"]

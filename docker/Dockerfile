FROM ubuntu:16.04
LABEL maintainer="YiJun Chen <gzenux@gmail.com>"


# Update repository and install packages
RUN dpkg --add-architecture i386 && apt-get update && apt-get install -y --no-install-recommends \
	autogen \
	autopoint \
	binutils-dev \
	bison \
	build-essential \
	cmake \
	device-tree-compiler \
	docbook-xsl-* \
	dos2unix \
	flex \
	gawk \
	gengetopt \
	git \
	g++-multilib \
	gperf \
	gtk-doc-tools \
	intltool \
	lib32ncurses5 \
	lib32stdc++6 \
	lib32z1 \
	libc6-dev-i386 \
	libelf1:i386 \
	libglib2.0-dev \
	libltdl-dev \
	liblzma-dev \
	liblzo2-dev \
	libncurses5-dev \
	libncurses5:i386 \
	libstdc++5 \
	libtool \
	libtool-bin \
	locales \
	lzma \
	lzma-dev \
	mtd-utils \
	python \
	sharutils \
	shtool \
	sudo \
	texinfo \
	tofrodos \
	u-boot-tools \
	uuid-dev \
	xsltproc \
	xutils-dev


#
# Configure the system
#
# Generate locale
ARG LANG=en_US.UTF-8
ARG LANGUAGES=zh_TW.UTF-8
RUN locale-gen ${LANGUAGES} ${LANG}
ENV LANG=${LANG} LANGUAGE=${LANG} LC_ALL=${LANG}

# Use bash as default shell
RUN echo "dash dash/sh boolean false" | debconf-set-selections && dpkg-reconfigure -f noninteractive dash

# Clean up the resources
RUN rm -rf /var/lib/apt/lists/*


COPY src/docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["bash"]

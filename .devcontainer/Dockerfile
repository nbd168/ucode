FROM mcr.microsoft.com/devcontainers/base:debian

# Build, test and packaging dependencies (see debian/control and tests/)
RUN apt-get update \
	&& export DEBIAN_FRONTEND=noninteractive \
	&& apt-get install -y --no-install-recommends \
		sudo \
		build-essential \
		clang \
		cmake \
		debhelper \
		devscripts \
		gdb \
		libffi-dev \
		libclang-rt-dev \
		libjson-c-dev \
		libmd-dev \
		lintian \
		pkgconf \
		python3 \
		python3-venv \
		valgrind \
		zlib1g-dev \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# OpenWrt libraries required by the ubus, uci, uloop, rtnl and nl80211 modules;
# these are not packaged by Debian, so build them from source.
ARG OPENWRT_GIT=https://git.openwrt.org/project
RUN set -e; \
	build() { \
		name="$1"; shift; \
		git clone --depth 1 "$OPENWRT_GIT/$name.git" "/tmp/$name"; \
		cmake -S "/tmp/$name" -B "/tmp/$name/build" \
			-DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_BUILD_TYPE=Release "$@"; \
		cmake --build "/tmp/$name/build" -j"$(nproc)"; \
		cmake --install "/tmp/$name/build"; \
		rm -rf "/tmp/$name"; \
	}; \
	build libnl-tiny; \
	build libubox -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF; \
	build ubus -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF; \
	build uci -DBUILD_LUA=OFF; \
	ldconfig

# The workspace is bind-mounted at /workspaces/<repo>; make its parent writable
# by the remote user so sibling directories can be created inside the container
# (they live only in the container, not on the host).
RUN install -d -o vscode -g vscode /workspaces

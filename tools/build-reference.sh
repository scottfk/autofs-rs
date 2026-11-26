#!/bin/bash
# build-reference.sh - build upstream C automount, libautofs.so and its modules at the pinned release, for the differential tests
#
# 20261126 - Created by Claude (claude.ai, Anthropic) - scottfk
#
# Usage: tools/build-reference.sh [DIR]
#
# DIR defaults to ../autofs (next to this checkout), which is where the tests
# will look (override with AUTOFS_REFERENCE=/path/to/autofs). The sources are
# the autofs-5.1.9 release tarball plus Gentoo's autofs-5.1.9-c99.patch, what
# net-fs/autofs-5.1.9-r2 builds. The configure flags are the ebuild's for
# hydra's USE="-ldap +libtirpc -mount-locking -sasl -selinux -systemd".

set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
dir=${1:-$here/../autofs}
rel=$(cat "$here/tools/REFERENCE_TAG")
distdir=${DISTDIR:-/var/cache/distfiles}
tarball=$distdir/$rel.tar.xz
url=https://www.kernel.org/pub/linux/daemons/autofs/v5/$rel.tar.xz
patch=${GENTOO_FILESDIR:-/var/db/repos/gentoo/net-fs/autofs/files}/autofs-5.1.9-c99.patch

if [[ ! -f $dir/configure.ac ]]; then
	if [[ ! -f $tarball ]]; then
		tarball=$(mktemp -d)/$rel.tar.xz
		curl -fsSL -o "$tarball" "$url"
	fi
	mkdir -p "$dir"
	tar -xJf "$tarball" -C "$dir" --strip-components=1
	patch -d "$dir" -p1 < "$patch"
fi
cd "$dir"
if [[ ! -f Makefile.conf ]]; then
	# As the ebuild does (tc-export AR, RANLIB, CONFIG_SHELL).
	CONFIG_SHELL=/bin/bash \
	AR=${AR:-ar} RANLIB=$(type -P "${RANLIB:-ranlib}") \
	CFLAGS="${CFLAGS:--O3 -pipe -march=native}" \
	LDFLAGS="${LDFLAGS:--Wl,-O1 -Wl,--as-needed -Wl,-z,pack-relative-relocs}" \
	/bin/bash ./configure -q --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
		--libdir=/usr/lib64 \
		--with-confdir=/etc/conf.d --with-mapdir=/etc/autofs \
		--without-dmalloc --without-openldap --with-libtirpc \
		--without-sasl --disable-mount-locking --without-systemd \
		--without-hesiod --disable-ext-env --enable-sloppy-mount \
		--enable-force-shutdown --enable-ignore-busy
fi
make -s STRIP=: DONTSTRIP=1 -j"$(nproc)"
echo "reference: $dir (daemon/automount lib/libautofs.so modules/*.so)"

#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Test the signature check in install.sh with a fake curl and a fake cosign.
# The fake cosign accepts a bundle only when the bundle names the exact
# certificate identity that install.sh passes. A bundle signed for another
# valid tag must make the install fail and must leave no binary behind.
#
# Run from any directory:  bash scripts/test-install.sh

set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

identity_for() {
    printf 'https://github.com/officialunofficial/kit/.github/workflows/release.yml@refs/tags/%s' "$1"
}

case "$(uname -s)" in
    Darwin) os_part=apple-darwin ;;
    Linux) os_part=unknown-linux-gnu ;;
    *) echo "skip: unsupported host" >&2; exit 0 ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arch_part=x86_64 ;;
    arm64 | aarch64) arch_part=aarch64 ;;
    *) echo "skip: unsupported host" >&2; exit 0 ;;
esac
target="${arch_part}-${os_part}"

# Build a release fixture for one tag. The bundle holds the identity of
# the tag that "signed" it, which the caller chooses.
make_release() {
    local tag=$1 signed_tag=$2 bare=${1#v}
    local dir="$work/releases/$tag" stage="$work/stage/$tag/kit-${bare}-${target}"
    mkdir -p "$dir" "$stage"
    printf '#!/bin/sh\necho "kit %s"\n' "$bare" >"$stage/kit"
    chmod 0755 "$stage/kit"
    local archive="kit-${bare}-${target}.tar.gz"
    tar -czf "$dir/$archive" -C "$work/stage/$tag" "kit-${bare}-${target}"
    (cd "$dir" && shasum -a 256 "$archive" >"$archive.sha256")
    identity_for "$signed_tag" >"$dir/$archive.cosign.bundle"
}

mkdir -p "$work/bin"
cat >"$work/bin/curl" <<'SH'
#!/bin/sh
# Fake curl: map a release URL to a fixture file.
url=""; out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out=$2; shift 2 ;;
        -*) shift ;;
        *) url=$1; shift ;;
    esac
done
rel=${url#https://github.com/officialunofficial/kit/releases/download/}
[ "$rel" != "$url" ] || exit 22
src="$FAKE_RELEASES/$rel"
[ -f "$src" ] || exit 22
if [ -n "$out" ]; then cp "$src" "$out"; else cat "$src"; fi
SH
cat >"$work/bin/cosign" <<'SH'
#!/bin/sh
# Fake cosign: accept only an exact identity that matches the bundle.
identity=""; bundle=""
while [ $# -gt 0 ]; do
    case "$1" in
        verify-blob) shift ;;
        --certificate-identity) identity=$2; shift 2 ;;
        --bundle) bundle=$2; shift 2 ;;
        --certificate-identity-regexp) echo "regexp identity is not allowed" >&2; exit 2 ;;
        --certificate-oidc-issuer) shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$identity" ] && [ -n "$bundle" ] || exit 2
[ "$(cat "$bundle")" = "$identity" ]
SH
chmod 0755 "$work/bin/curl" "$work/bin/cosign"

fails=0
run_install() {
    local name=$1 tag=$2 expect=$3
    local prefix="$work/prefix-$name" state="$work/state-$name"
    mkdir -p "$prefix"
    chmod 0755 "$prefix"
    local status=0
    PATH="$work/bin:$PATH" FAKE_RELEASES="$work/releases" \
        KIT_INSTALL_DIR="$prefix" KIT_STATE_DIR="$state" \
        sh "$repo_root/install.sh" --version "$tag" >"$work/$name.out" 2>&1 || status=$?
    if [ "$expect" = pass ] && [ "$status" -eq 0 ] && [ -x "$prefix/kit" ]; then
        echo "ok: $name"
    elif [ "$expect" = fail ] && [ "$status" -ne 0 ] && [ ! -e "$prefix/kit" ]; then
        echo "ok: $name"
    else
        echo "FAIL: $name (status $status, expected $expect)" >&2
        cat "$work/$name.out" >&2
        fails=1
    fi
}

make_release v0.5.1 v0.5.1
run_install same-tag v0.5.1 pass

# A signature that is valid for an older tag must not install a newer tag.
make_release v0.5.2 v0.4.0
run_install replayed-tag v0.5.2 fail

# A signature for a later tag must not install an earlier tag either.
make_release v0.3.0 v0.9.0
run_install later-tag v0.3.0 fail

# A tag with regex or path characters never reaches cosign.
run_install bad-tag 'v0.5.1/../v0.4.0' fail

# A tag with an embedded newline never reaches cosign. A line-based
# check would accept it, because its first line is a valid tag.
run_install newline-tag "$(printf 'v0.5.1\nv0.4.0')" fail
run_install newline-tag-leading "$(printf 'x\nv0.5.1')" fail
for name in newline-tag newline-tag-leading; do
    if ! grep -q 'invalid release tag' "$work/$name.out"; then
        echo "FAIL: $name (the tag check did not reject the tag)" >&2
        fails=1
    fi
done

# Version order follows semver. A pre-release is below its release, so
# installing the release over a recorded pre-release is no downgrade,
# and installing a pre-release over a recorded release is one.
check_downgrade() {
    local name=$1 recorded=$2 tag=$3 expect=$4
    local state="$work/state-$name" prefix="$work/prefix-$name" status=0
    mkdir -p "$state" "$prefix"
    chmod 0755 "$prefix"
    printf '%s\n' "$recorded" >"$state/installed-tag"
    PATH="$work/bin:$PATH" FAKE_RELEASES="$work/releases" \
        KIT_INSTALL_DIR="$prefix" KIT_STATE_DIR="$state" \
        sh "$repo_root/install.sh" --version "$tag" >"$work/$name.out" 2>&1 || status=$?
    local warned=no
    grep -q 'DOWNGRADE' "$work/$name.out" && warned=yes
    if [ "$warned" = "$expect" ] && [ "$status" -eq 0 ]; then
        echo "ok: $name"
    else
        echo "FAIL: $name (status $status, downgrade warning $warned, expected $expect)" >&2
        cat "$work/$name.out" >&2
        fails=1
    fi
}

make_release v1.0.0 v1.0.0
make_release v1.0.0-rc.1 v1.0.0-rc.1
make_release v1.0.0-rc.2 v1.0.0-rc.2
make_release v1.0.0-rc.10 v1.0.0-rc.10
make_release v0.10.0 v0.10.0
check_downgrade release-over-prerelease v1.0.0-rc.1 v1.0.0 no
check_downgrade prerelease-over-release v1.0.0 v1.0.0-rc.1 yes
check_downgrade rc2-over-rc10 v1.0.0-rc.10 v1.0.0-rc.2 yes
check_downgrade rc10-over-rc2 v1.0.0-rc.2 v1.0.0-rc.10 no
check_downgrade minor-ten-over-nine v0.9.0 v0.10.0 no

# The install directory check fails closed. A stat that fails must stop
# the install and leave no binary behind.
mkdir -p "$work/badstat"
printf '#!/bin/sh\nexit 1\n' >"$work/badstat/stat"
chmod 0755 "$work/badstat/stat"
prefix="$work/prefix-stat-fails"
mkdir -p "$prefix"
chmod 0755 "$prefix"
status=0
PATH="$work/badstat:$work/bin:$PATH" FAKE_RELEASES="$work/releases" \
    KIT_INSTALL_DIR="$prefix" KIT_STATE_DIR="$work/state-stat-fails" \
    sh "$repo_root/install.sh" --version v0.5.1 >"$work/stat-fails.out" 2>&1 || status=$?
if [ "$status" -ne 0 ] && [ ! -e "$prefix/kit" ] && grep -q 'mode' "$work/stat-fails.out"; then
    echo "ok: stat-fails"
else
    echo "FAIL: stat-fails (status $status)" >&2
    cat "$work/stat-fails.out" >&2
    fails=1
fi

# A group-writable install directory is refused.
prefix="$work/prefix-group-writable"
mkdir -p "$prefix"
chmod 0775 "$prefix"
status=0
PATH="$work/bin:$PATH" FAKE_RELEASES="$work/releases" \
    KIT_INSTALL_DIR="$prefix" KIT_STATE_DIR="$work/state-group-writable" \
    sh "$repo_root/install.sh" --version v0.5.1 >"$work/group-writable.out" 2>&1 || status=$?
if [ "$status" -ne 0 ] && [ ! -e "$prefix/kit" ]; then
    echo "ok: group-writable"
else
    echo "FAIL: group-writable (status $status)" >&2
    cat "$work/group-writable.out" >&2
    fails=1
fi

# The member that holds the binary must be a regular file. A symlink
# there must fail the install.
make_release v0.6.0 v0.6.0
(
    cd "$work/stage/v0.6.0/kit-0.6.0-${target}"
    rm kit
    ln -s /bin/sh kit
)
tar -czf "$work/releases/v0.6.0/kit-0.6.0-${target}.tar.gz" \
    -C "$work/stage/v0.6.0" "kit-0.6.0-${target}"
(cd "$work/releases/v0.6.0" && shasum -a 256 "kit-0.6.0-${target}.tar.gz" >"kit-0.6.0-${target}.tar.gz.sha256")
run_install symlink-member v0.6.0 fail

# An archive with too many entries is refused.
make_release v0.7.0 v0.7.0
(
    cd "$work/stage/v0.7.0/kit-0.7.0-${target}"
    for i in $(seq 1 100); do : >"extra-$i"; done
)
tar -czf "$work/releases/v0.7.0/kit-0.7.0-${target}.tar.gz" \
    -C "$work/stage/v0.7.0" "kit-0.7.0-${target}"
(cd "$work/releases/v0.7.0" && shasum -a 256 "kit-0.7.0-${target}.tar.gz" >"kit-0.7.0-${target}.tar.gz.sha256")
run_install many-entries v0.7.0 fail
grep -q 'more than 64 entries' "$work/many-entries.out" || {
    echo "FAIL: many-entries (the entry cap did not reject the archive)" >&2
    fails=1
}

# A tar bomb is refused. The stage holds a file of zero bytes that expands
# past the decompressed cap but compresses to a few hundred kilobytes.
make_release v0.8.0 v0.8.0
(
    cd "$work/stage/v0.8.0/kit-0.8.0-${target}"
    dd if=/dev/zero of=bomb bs=1048576 count=600 2>/dev/null
)
tar -czf "$work/releases/v0.8.0/kit-0.8.0-${target}.tar.gz" \
    -C "$work/stage/v0.8.0" "kit-0.8.0-${target}"
rm "$work/stage/v0.8.0/kit-0.8.0-${target}/bomb"
(cd "$work/releases/v0.8.0" && shasum -a 256 "kit-0.8.0-${target}.tar.gz" >"kit-0.8.0-${target}.tar.gz.sha256")
run_install tar-bomb v0.8.0 fail
grep -q 'expands to more than' "$work/tar-bomb.out" || {
    echo "FAIL: tar-bomb (the size cap did not reject the archive)" >&2
    fails=1
}

# The entry count is bounded. A tar that lists without end must not make
# the installer work without end: the count stops one entry past the cap.
mkdir -p "$work/endless"
real_tar=$(command -v tar)
cat >"$work/endless/tar" <<SH
#!/bin/sh
if [ "\$1" = "-tf" ] && [ "\$2" = "-" ]; then exec yes entry; fi
exec "$real_tar" "\$@"
SH
chmod 0755 "$work/endless/tar"
prefix="$work/prefix-endless-listing"
mkdir -p "$prefix"
chmod 0755 "$prefix"
status=0
PATH="$work/endless:$work/bin:$PATH" FAKE_RELEASES="$work/releases" \
    KIT_INSTALL_DIR="$prefix" KIT_STATE_DIR="$work/state-endless-listing" \
    sh "$repo_root/install.sh" --version v0.5.1 >"$work/endless-listing.out" 2>&1 &
pid=$!
( sleep 30; kill "$pid" 2>/dev/null ) &
watchdog=$!
wait "$pid" || status=$?
kill "$watchdog" 2>/dev/null || true
if [ "$status" -ne 0 ] && [ ! -e "$prefix/kit" ] \
    && grep -q 'more than 64 entries' "$work/endless-listing.out"; then
    echo "ok: endless-listing"
else
    echo "FAIL: endless-listing (status $status)" >&2
    cat "$work/endless-listing.out" >&2
    fails=1
fi

exit "$fails"

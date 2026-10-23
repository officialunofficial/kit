#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail when an `unsafe` block, `unsafe impl`, `unsafe fn`, `unsafe trait` or
# `unsafe extern` block has no `// SAFETY:` comment. AGENTS.md requires the
# comment to state the invariant and why it holds.
#
# A site counts as documented when one of these holds:
#   - the comment block directly above it (attributes may sit between the
#     comment and the site) contains `SAFETY:`;
#   - the same line contains `SAFETY:`;
#   - the first line inside its braces is a comment that contains `SAFETY:`.
#
# The check reads the source text, so it also covers code that clippy skips
# for the current target or feature set. Clippy's
# `undocumented_unsafe_blocks` lint (denied in rust/Cargo.toml) covers
# the compiled code. Run from any directory:
#   bash scripts/check-unsafe-safety.sh [file.rs ...]

set -euo pipefail

cd "$(dirname "$0")/.."

# Generated code holds no `unsafe` today. The check still reads it, so a new
# generator version cannot add undocumented `unsafe` unseen. Pass file names
# to check only those files.
if [ "$#" -gt 0 ]; then
    files="$*"
else
    files=$(git ls-files -- '*.rs')
fi

status=0
total=0
for f in $files; do
    [ -L "$f" ] && continue
    out=$(perl -e '
        use strict; use warnings;
        my ($file) = @ARGV;
        open(my $fh, "<", $file) or die "$file: $!";
        my @l = <$fh>;
        my ($bad, $n) = (0, 0);
        my $block = 0;                       # inside a /* ... */ comment
        for my $i (0 .. $#l) {
            my $line = $l[$i];
            # Drop block comments, line comments and string literals before
            # looking for the keyword. A `SAFETY:` marker is read from the
            # original line below.
            my $code = $line;
            if ($block) {
                if ($code =~ s{^.*?\*/}{}) { $block = 0 } else { next }
            }
            while ($code =~ s{/\*.*?\*/}{ }) {}
            if ($code =~ s{/\*.*$}{}) { $block = 1 }
            $code =~ s{//.*$}{};
            $code =~ s{"(?:[^"\\]|\\.)*"}{""}g;
            chomp $code;
            next unless $code =~ /(?<![-\w])unsafe\s*(?:\{|impl\b|fn\b|trait\b|extern\b|\z)/;
            # `unsafe_code` / `unsafe_op_in_unsafe_fn` lint names and
            # `forbid(unsafe_code)` are not unsafe sites.
            next if $code =~ /^\s*#!?\[/;
            $n++;
            my $ok = ($line =~ m{//.*SAFETY:});
            # Walk up through the comment block (and attributes) above.
            if (!$ok) {
                my $j = $i - 1;
                while ($j >= 0 && $l[$j] =~ m{^\s*(?://|#\[|#!\[|\*|/\*)}) {
                    if ($l[$j] =~ /SAFETY:/) { $ok = 1; last }
                    $j--;
                }
            }
            # First comment line inside the braces.
            if (!$ok && $line =~ /\{\s*$/ && $i < $#l && $l[$i + 1] =~ m{^\s*//.*SAFETY:}) {
                $ok = 1;
            }
            if (!$ok) {
                printf "%s:%d: unsafe site without a SAFETY comment: %s", $file, $i + 1, $line;
                $bad++;
            }
        }
        print "COUNT $n\n";
        exit($bad ? 1 : 0);
    ' "$f") || status=1
    count=$(printf '%s\n' "$out" | sed -n 's/^COUNT //p')
    total=$((total + ${count:-0}))
    printf '%s\n' "$out" | grep -v '^COUNT ' >&2 || true
done

if [ "$status" -eq 0 ]; then
    echo "unsafe SAFETY check: ok ($total sites, all documented)"
fi
exit "$status"

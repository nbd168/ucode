#!/bin/sh
set -e

# CMake only reads presets from the source root; point a local, uncommitted
# CMakeUserPresets.json at the devcontainer presets.
if [ ! -e CMakeUserPresets.json ]; then
	cat > CMakeUserPresets.json <<-EOF
	{ "version": 4, "include": [ ".devcontainer/CMakePresets.json" ] }
	EOF
fi
exclude="$(git rev-parse --git-path info/exclude)"
grep -qxF '/CMakeUserPresets.json' "$exclude" 2>/dev/null \
	|| echo '/CMakeUserPresets.json' >> "$exclude"

npm install

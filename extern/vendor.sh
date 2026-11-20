#!/usr/bin/env bash
# Re-creates the vendored dependencies in this directory from upstream. To upgrade one, change its commit below,
# run this script, build, and review the diff. Each entry lists the paths removed after extraction.
set -euo pipefail
shopt -s extglob nullglob
cd "$(dirname "$0")"

vendor() {
  local dir=$1 repo=$2 commit=$3
  shift 3
  local tmp
  tmp=$(mktemp -d)
  curl -fsSL "https://github.com/${repo}/archive/${commit}.tar.gz" | tar -xz -C "$tmp" --strip-components=1
  for pattern in "$@"; do
    for path in "$tmp"/$pattern; do
      rm -rf "$path"
    done
  done
  rm -rf "$dir"
  mv "$tmp" "$dir"
  chmod 755 "$dir"
}

vendor cmake-modules bilke/cmake-modules d6d1a778e41cb114e5cdf279b8a659fa0ce9a0d4
vendor GSL microsoft/GSL ef0ffefe525a6219ff245d19a832ce06f3fd3504
vendor rapidjson Tencent/rapidjson fcb23c2dbf561ec0798529be4f66394d3e4996d8
vendor tinyxml2 leethomason/tinyxml2 e05956094c27117f989d22f25b75633123d72a83
vendor uriparser uriparser/uriparser 24df44b74753017acfaec4b3a30097a8a2ae1ae1

vendor glm g-truc/glm bf71a834948186f4097caa076cd2663c69a10e1e \
  doc

vendor draco google/draco 9f856abaafb4b39f1f013763ff061522e0261c6f \
  docs javascript maya testdata third_party unity

vendor KTX-Software CesiumGS/KTX-Software 6a231bd34fc782f961ff2c30752d71a655312c01 \
  '.github' ci_scripts icons other_projects pkgdoc tools \
  'tests/!(CMakeLists.txt)' \
  lib/astc-encoder/Docs lib/astc-encoder/Test \
  lib/basisu/contrib lib/basisu/test_files lib/basisu/webgl lib/basisu/webgl_videotest

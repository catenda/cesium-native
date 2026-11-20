# Cesium Native fork

This is a minimalized fork of [Cesium Native](https://github.com/CesiumGS/cesium-native/).

To simplify compliation, many parts of the original library have been left out.
3rd party dependencies have also been bundles, instead of added ad git submodules.

## Updating 3rdparty dependencies.

1. Update relevant commit hashes in extern/vendor.sh
2. Execute `extern/vendor.sh`

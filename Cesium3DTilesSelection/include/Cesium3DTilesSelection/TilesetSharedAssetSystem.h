#pragma once

#include <CesiumGltfReader/GltfSharedAssetSystem.h>

namespace Cesium3DTilesSelection {

/**
 * @brief Contains assets that are potentially shared across multiple Tilesets.
 */
class TilesetSharedAssetSystem
    : public CesiumGltfReader::GltfSharedAssetSystem {
public:
  static CesiumUtility::IntrusivePointer<TilesetSharedAssetSystem> getDefault();

  virtual ~TilesetSharedAssetSystem() = default;
};

} // namespace Cesium3DTilesSelection
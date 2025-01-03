// This file was generated by generate-classes.
// DO NOT EDIT THIS FILE!
#pragma once

#include "CesiumGltf/ExtensionCatendaMetadataObjectMetadataAttribute.h"
#include "CesiumGltf/Library.h"

#include <CesiumUtility/ExtensibleObject.h>

#include <optional>
#include <string>
#include <unordered_map>

namespace CesiumGltf {
/**
 * @brief Metadata for an object.
 */
struct CESIUMGLTF_API ExtensionCatendaMetadataObjectMetadata final
    : public CesiumUtility::ExtensibleObject {
  static inline constexpr const char* TypeName =
      "ExtensionCatendaMetadataObjectMetadata";

  /**
   * @brief ID of the parent object, if any.
   */
  std::optional<std::string> parentId;

  /**
   * @brief Name of the object type.
   */
  std::optional<std::string> objectType;

  /**
   * @brief A dictionary of all attributes for the current object, where the key
   * is the id of the attribute.
   */
  std::unordered_map<
      std::string,
      CesiumGltf::ExtensionCatendaMetadataObjectMetadataAttribute>
      attributes;
};
} // namespace CesiumGltf

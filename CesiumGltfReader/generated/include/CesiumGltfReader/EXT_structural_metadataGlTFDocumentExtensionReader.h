// This file was generated by generate-classes.
// DO NOT EDIT THIS FILE!
#pragma once

#include <CesiumGltfReader/Library.h>
#include <CesiumJsonReader/JsonReader.h>
#include <CesiumJsonReader/JsonReaderOptions.h>
#include <CesiumGltf/EXT_structural_metadataGlTFDocumentExtension.h>
#include <span>
#include <rapidjson/fwd.h>
#include <vector>

namespace CesiumGltf {
  struct EXT_structural_metadataGlTFDocumentExtension;
} // namespace CesiumGltf

namespace CesiumGltfReader {

/**
 * @brief Reads {@link EXT_structural_metadataGlTFDocumentExtension} instances from JSON.
 */
class CESIUMGLTFREADER_API EXT_structural_metadataGlTFDocumentExtensionReader {
public:
  /**
   * @brief Constructs a new instance.
   */
  EXT_structural_metadataGlTFDocumentExtensionReader();

  /**
   * @brief Gets the options controlling how the JSON is read.
   */
  CesiumJsonReader::JsonReaderOptions& getOptions();

  /**
   * @brief Gets the options controlling how the JSON is read.
   */
  const CesiumJsonReader::JsonReaderOptions& getOptions() const;

  /**
   * @brief Reads an instance of EXT_structural_metadataGlTFDocumentExtension from a byte buffer.
   *
   * @param data The buffer from which to read the instance.
   * @return The result of reading the instance.
   */
  CesiumJsonReader::ReadJsonResult<CesiumGltf::EXT_structural_metadataGlTFDocumentExtension> readFromJson(const std::span<const std::byte>& data) const;

  /**
   * @brief Reads an instance of EXT_structural_metadataGlTFDocumentExtension from a rapidJson::Value.
   *
   * @param data The buffer from which to read the instance.
   * @return The result of reading the instance.
   */
  CesiumJsonReader::ReadJsonResult<CesiumGltf::EXT_structural_metadataGlTFDocumentExtension> readFromJson(const rapidjson::Value& value) const;

  /**
   * @brief Reads an array of instances of EXT_structural_metadataGlTFDocumentExtension from a rapidJson::Value.
   *
   * @param data The buffer from which to read the array of instances.
   * @return The result of reading the array of instances.
   */
  CesiumJsonReader::ReadJsonResult<std::vector<CesiumGltf::EXT_structural_metadataGlTFDocumentExtension>> readArrayFromJson(const rapidjson::Value& value) const;

private:
  CesiumJsonReader::JsonReaderOptions _options;
};

} // namespace CesiumGltfReader
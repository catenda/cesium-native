// This file was generated by generate-classes.
// DO NOT EDIT THIS FILE!
#pragma once

#include <CesiumGltf/ExtensionCatendaMetadataObjectMetadataAttribute.h>
#include <CesiumJsonReader/ExtensibleObjectJsonHandler.h>
#include <CesiumJsonReader/JsonObjectJsonHandler.h>
#include <CesiumJsonReader/StringJsonHandler.h>

namespace CesiumJsonReader {
class ExtensionReaderContext;
}

namespace CesiumGltfReader {
class ExtensionCatendaMetadataObjectMetadataAttributeJsonHandler
    : public CesiumJsonReader::ExtensibleObjectJsonHandler {
public:
  using ValueType = CesiumGltf::ExtensionCatendaMetadataObjectMetadataAttribute;

  ExtensionCatendaMetadataObjectMetadataAttributeJsonHandler(
      const CesiumJsonReader::ExtensionReaderContext& context) noexcept;
  void reset(
      IJsonHandler* pParentHandler,
      CesiumGltf::ExtensionCatendaMetadataObjectMetadataAttribute* pObject);

  virtual IJsonHandler* readObjectKey(const std::string_view& str) override;

protected:
  IJsonHandler* readObjectKeyExtensionCatendaMetadataObjectMetadataAttribute(
      const std::string& objectType,
      const std::string_view& str,
      CesiumGltf::ExtensionCatendaMetadataObjectMetadataAttribute& o);

private:
  CesiumGltf::ExtensionCatendaMetadataObjectMetadataAttribute* _pObject =
      nullptr;
  CesiumJsonReader::StringJsonHandler _type;
  CesiumJsonReader::JsonObjectJsonHandler _value;
};
} // namespace CesiumGltfReader

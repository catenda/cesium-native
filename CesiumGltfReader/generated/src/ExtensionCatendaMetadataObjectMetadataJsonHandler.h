// This file was generated by generate-classes.
// DO NOT EDIT THIS FILE!
#pragma once

#include "ExtensionCatendaMetadataObjectMetadataAttributeJsonHandler.h"
#include <CesiumGltf/ExtensionCatendaMetadataObjectMetadata.h>
#include <CesiumJsonReader/DictionaryJsonHandler.h>
#include <CesiumJsonReader/ExtensibleObjectJsonHandler.h>
#include <CesiumJsonReader/StringJsonHandler.h>

namespace CesiumJsonReader {
  class JsonReaderOptions;
} // namespace CesiumJsonReader

namespace CesiumGltfReader {
  class ExtensionCatendaMetadataObjectMetadataJsonHandler : public CesiumJsonReader::ExtensibleObjectJsonHandler {
  public:
    using ValueType = CesiumGltf::ExtensionCatendaMetadataObjectMetadata;

    explicit ExtensionCatendaMetadataObjectMetadataJsonHandler(const CesiumJsonReader::JsonReaderOptions& options) noexcept;
    void reset(IJsonHandler* pParentHandler, CesiumGltf::ExtensionCatendaMetadataObjectMetadata* pObject);

    IJsonHandler* readObjectKey(const std::string_view& str) override;

  protected:
    IJsonHandler* readObjectKeyExtensionCatendaMetadataObjectMetadata(const std::string& objectType, const std::string_view& str, CesiumGltf::ExtensionCatendaMetadataObjectMetadata& o);

  private:

    CesiumGltf::ExtensionCatendaMetadataObjectMetadata* _pObject = nullptr;
    CesiumJsonReader::StringJsonHandler _parentId;
    CesiumJsonReader::StringJsonHandler _objectType;
    CesiumJsonReader::DictionaryJsonHandler<CesiumGltf::ExtensionCatendaMetadataObjectMetadataAttribute, ExtensionCatendaMetadataObjectMetadataAttributeJsonHandler> _attributes;
  };
}  // namespace CesiumGltfReader
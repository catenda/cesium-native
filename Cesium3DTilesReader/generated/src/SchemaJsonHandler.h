// This file was generated by generate-classes.
// DO NOT EDIT THIS FILE!
#pragma once

#include "ClassJsonHandler.h"
#include "EnumJsonHandler.h"

#include <Cesium3DTiles/Schema.h>
#include <CesiumJsonReader/DictionaryJsonHandler.h>
#include <CesiumJsonReader/ExtensibleObjectJsonHandler.h>
#include <CesiumJsonReader/StringJsonHandler.h>

namespace CesiumJsonReader {
class ExtensionReaderContext;
}

namespace Cesium3DTilesReader {
class SchemaJsonHandler : public CesiumJsonReader::ExtensibleObjectJsonHandler {
public:
  using ValueType = Cesium3DTiles::Schema;

  SchemaJsonHandler(
      const CesiumJsonReader::ExtensionReaderContext& context) noexcept;
  void reset(IJsonHandler* pParentHandler, Cesium3DTiles::Schema* pObject);

  virtual IJsonHandler* readObjectKey(const std::string_view& str) override;

protected:
  IJsonHandler* readObjectKeySchema(
      const std::string& objectType,
      const std::string_view& str,
      Cesium3DTiles::Schema& o);

private:
  Cesium3DTiles::Schema* _pObject = nullptr;
  CesiumJsonReader::StringJsonHandler _id;
  CesiumJsonReader::StringJsonHandler _name;
  CesiumJsonReader::StringJsonHandler _description;
  CesiumJsonReader::StringJsonHandler _version;
  CesiumJsonReader::
      DictionaryJsonHandler<Cesium3DTiles::Class, ClassJsonHandler>
          _classes;
  CesiumJsonReader::DictionaryJsonHandler<Cesium3DTiles::Enum, EnumJsonHandler>
      _enums;
};
} // namespace Cesium3DTilesReader
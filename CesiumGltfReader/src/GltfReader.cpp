#include "CesiumGltfReader/GltfReader.h"

#include "ModelJsonHandler.h"
#include "decodeDraco.h"
#include "registerExtensions.h"

#include <CesiumGltf/ExtensionKhrTextureBasisu.h>
#include <CesiumGltf/ExtensionTextureWebp.h>
#include <CesiumJsonReader/ExtensionReaderContext.h>
#include <CesiumJsonReader/JsonHandler.h>
#include <CesiumJsonReader/JsonReader.h>
#include <CesiumUtility/Tracing.h>
#include <CesiumUtility/Uri.h>

#include <ktx.h>
#include <rapidjson/reader.h>

#include <algorithm>
#include <cstddef>
#include <iomanip>
#include <sstream>
#include <string>
#include <cassert>

using namespace CesiumGltf;
using namespace CesiumGltfReader;
using namespace CesiumJsonReader;
using namespace CesiumUtility;

namespace {
#pragma pack(push, 1)
struct GlbHeader {
  uint32_t magic;
  uint32_t version;
  uint32_t length;
};

struct ChunkHeader {
  uint32_t chunkLength;
  uint32_t chunkType;
};
#pragma pack(pop)

bool isBinaryGltf(const gsl::span<const std::byte>& data) noexcept {
  if (data.size() < sizeof(GlbHeader)) {
    return false;
  }

  return reinterpret_cast<const GlbHeader*>(data.data())->magic == 0x46546C67;
}

GltfReaderResult readJsonGltf(
    const CesiumJsonReader::ExtensionReaderContext& context,
    const gsl::span<const std::byte>& data) {

  CESIUM_TRACE("CesiumGltfReader::GltfReader::readJsonGltf");

  ModelJsonHandler modelHandler(context);
  CesiumJsonReader::ReadJsonResult<Model> jsonResult =
      CesiumJsonReader::JsonReader::readJson(data, modelHandler);

  return GltfReaderResult{
      std::move(jsonResult.value),
      std::move(jsonResult.errors),
      std::move(jsonResult.warnings)};
}

/**
 * @brief Creates a string representation for the given magic value.
 *
 * The details are not specified, but the output will include a
 * hex representation of the given value, as well as the result
 * of interpreting the value as 4 unsigned characters.
 *
 * @param i The value
 * @return The string
 */
std::string toMagicString(uint32_t i) {
  const unsigned char c0 = static_cast<unsigned char>(i & 0xFF);
  const unsigned char c1 = static_cast<unsigned char>((i >> 8) & 0xFF);
  const unsigned char c2 = static_cast<unsigned char>((i >> 16) & 0xFF);
  const unsigned char c3 = static_cast<unsigned char>((i >> 24) & 0xFF);
  std::stringstream stream;
  stream << c0 << c1 << c2 << c3 << " (0x" << std::hex << i << ")";
  return stream.str();
}

GltfReaderResult readBinaryGltf(
    const CesiumJsonReader::ExtensionReaderContext& context,
    const gsl::span<const std::byte>& data) {
  CESIUM_TRACE("CesiumGltfReader::GltfReader::readBinaryGltf");

  if (data.size() < sizeof(GlbHeader) + sizeof(ChunkHeader)) {
    return {std::nullopt, {"Too short to be a valid GLB."}, {}};
  }

  const GlbHeader* pHeader = reinterpret_cast<const GlbHeader*>(data.data());
  if (pHeader->magic != 0x46546C67) {
    return {
        std::nullopt,
        {"GLB does not start with the expected magic value 'glTF', but " +
         toMagicString(pHeader->magic)},
        {}};
  }

  if (pHeader->version != 2) {
    return {
        std::nullopt,
        {"Only binary glTF version 2 is supported, found version " +
         std::to_string(pHeader->version)},
        {}};
  }

  if (pHeader->length > data.size()) {
    return {
        std::nullopt,
        {"GLB extends past the end of the buffer, header size " +
         std::to_string(pHeader->length) + ", data size " +
         std::to_string(data.size())},
        {}};
  }

  const gsl::span<const std::byte> glbData = data.subspan(0, pHeader->length);

  const ChunkHeader* pJsonChunkHeader =
      reinterpret_cast<const ChunkHeader*>(glbData.data() + sizeof(GlbHeader));
  if (pJsonChunkHeader->chunkType != 0x4E4F534A) {
    return {
        std::nullopt,
        {"GLB JSON chunk does not have the expected chunkType 'JSON', but " +
         toMagicString(pJsonChunkHeader->chunkType)},
        {}};
  }

  const size_t jsonStart = sizeof(GlbHeader) + sizeof(ChunkHeader);
  const size_t jsonEnd = jsonStart + pJsonChunkHeader->chunkLength;

  if (jsonEnd > glbData.size()) {
    return {
        std::nullopt,
        {"GLB JSON chunk extends past the end of the buffer, JSON end at " +
         std::to_string(jsonEnd) + ", data size " +
         std::to_string(glbData.size())},
        {}};
  }

  const gsl::span<const std::byte> jsonChunk =
      glbData.subspan(jsonStart, pJsonChunkHeader->chunkLength);
  gsl::span<const std::byte> binaryChunk;

  if (jsonEnd + sizeof(ChunkHeader) <= data.size()) {
    const ChunkHeader* pBinaryChunkHeader =
        reinterpret_cast<const ChunkHeader*>(glbData.data() + jsonEnd);
    if (pBinaryChunkHeader->chunkType != 0x004E4942) {
      return {
          std::nullopt,
          {"GLB binary chunk does not have the expected chunkType 'BIN', but " +
           toMagicString(pBinaryChunkHeader->chunkType)},
          {}};
    }

    const size_t binaryStart = jsonEnd + sizeof(ChunkHeader);
    const size_t binaryEnd = binaryStart + pBinaryChunkHeader->chunkLength;

    if (binaryEnd > glbData.size()) {
      return {
          std::nullopt,
          {"GLB binary chunk extends past the end of the buffer, binary end "
           "at " +
           std::to_string(binaryEnd) + ", data size " +
           std::to_string(glbData.size())},
          {}};
    }

    binaryChunk = glbData.subspan(binaryStart, pBinaryChunkHeader->chunkLength);
  }

  GltfReaderResult result = readJsonGltf(context, jsonChunk);

  if (result.model && !binaryChunk.empty()) {
    Model& model = result.model.value();

    if (model.buffers.empty()) {
      result.errors.emplace_back(
          "GLB has a binary chunk but the JSON does not define any buffers.");
      return result;
    }

    Buffer& buffer = model.buffers[0];
    if (buffer.uri) {
      result.errors.emplace_back("GLB has a binary chunk but the first buffer "
                                 "in the JSON chunk also has a 'uri'.");
      return result;
    }

    const int64_t binaryChunkSize = static_cast<int64_t>(binaryChunk.size());
    if (buffer.byteLength > binaryChunkSize ||
        buffer.byteLength + 3 < binaryChunkSize) {
      result.errors.emplace_back("GLB binary chunk size does not match the "
                                 "size of the first buffer in the JSON chunk.");
      return result;
    }

    buffer.cesium.data = std::vector<std::byte>(
        binaryChunk.begin(),
        binaryChunk.begin() + buffer.byteLength);
  }

  return result;
}

void postprocess(
    GltfReaderResult& readGltf,
    const GltfReaderOptions& options) {

  if (options.decodeDataUrls) {
    assert(false); // Removed implementation for this
  }

  if (options.decodeEmbeddedImages) {
    assert(false); // Removed implementation for this
  }

  if (options.decodeDraco) {
    decodeDraco(readGltf);
  }
}

} // namespace

GltfReader::GltfReader() : _context() { registerExtensions(this->_context); }

CesiumJsonReader::ExtensionReaderContext& GltfReader::getExtensions() {
  return this->_context;
}

const CesiumJsonReader::ExtensionReaderContext&
GltfReader::getExtensions() const {
  return this->_context;
}

GltfReaderResult GltfReader::readGltf(
    const gsl::span<const std::byte>& data,
    const GltfReaderOptions& options) const {

  const CesiumJsonReader::ExtensionReaderContext& context =
      this->getExtensions();
  GltfReaderResult result = isBinaryGltf(data) ? readBinaryGltf(context, data)
                                               : readJsonGltf(context, data);

  if (result.model) {
    postprocess(result, options);
  }

  return result;
}

bool isKtx(const gsl::span<const std::byte>& data) {
  const size_t ktxMagicByteLength = 12;
  if (data.size() < ktxMagicByteLength) {
    return false;
  }

  const uint8_t ktxMagic[ktxMagicByteLength] =
      {0xAB, 0x4B, 0x54, 0x58, 0x20, 0x32, 0x30, 0xBB, 0x0D, 0x0A, 0x1A, 0x0A};

  return memcmp(data.data(), ktxMagic, ktxMagicByteLength) == 0;
}

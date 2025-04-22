set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_LIST_DIR}/Catch2/contrib")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} PARENT_SCOPE)

add_subdirectory(GSL)

option(KTX_FEATURE_STATIC_LIBRARY "" on)
option(KTX_FEATURE_TESTS "" off)

# cesium-native uses std::variant features that require iOS 12+. Don't let KTX force
# our build to use iOS 11, because it won't work.
if(IOS)
  set(CMAKE_XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "12.0" CACHE STRING "iOS Deployment Target")
endif()

add_subdirectory(KTX-Software)

option(URIPARSER_BUILD_TESTS "" off)
option(URIPARSER_BUILD_DOCS "" off)
option(URIPARSER_ENABLE_INSTALL "" on)
option(URIPARSER_BUILD_TOOLS "" off)
add_subdirectory(uriparser)

if ((NOT TARGET draco) AND (NOT TARGET draco_static))
    add_subdirectory(draco)
    if (MSVC)
      set(CESIUM_NATIVE_DRACO_LIBRARY draco)
    else()
      set(CESIUM_NATIVE_DRACO_LIBRARY draco_static)
    endif()
endif()

set(CESIUM_NATIVE_DRACO_LIBRARY ${CESIUM_NATIVE_DRACO_LIBRARY} PARENT_SCOPE)

if (NOT TARGET glm)
    add_subdirectory(glm GLM)
endif()

# tinyxml2's CMake build tries to generate a pkg-config file in a way that's incompatible with multi-config generators
# (e.g., Visual Studio). And anyway it's trivial to build manually, so we do that here.
add_library(tinyxml2 tinyxml2/tinyxml2.cpp)
target_include_directories(
    tinyxml2
    PUBLIC
        tinyxml2
)

if (NOT TARGET sqlite3)
  add_subdirectory(sqlite3)
endif()

add_subdirectory(modp_b64)

set(CESIUM_NATIVE_RAPIDJSON_INCLUDE_DIR "${CMAKE_CURRENT_LIST_DIR}/rapidjson/include" CACHE INTERNAL
    "Include directory for rapidjson"
)

set(CESIUM_NATIVE_RAPIDJSON_DEFINES
    RAPIDJSON_HAS_CXX11_RVALUE_REFS
    CACHE INTERNAL
    "Compiler definitions for rapidjson"
)

set(CESIUM_NATIVE_DRACO_INCLUDE_DIR "${CMAKE_CURRENT_LIST_DIR}/draco/src/" CACHE INTERNAL
    "Include directory for Draco"
)

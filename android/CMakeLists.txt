project(rncryptopp)
cmake_minimum_required(VERSION 3.9.0)

message("-------------------- CryptoPP --------------------")
message("CMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}")
message("ANDROID_PLATFORM=${ANDROID_PLATFORM}")
message("SDK_ROOT_PATH=${SDK_ROOT_PATH}")
message("NDK_ROOT_PATH=${NDK_ROOT_PATH}")


set (CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 17)
set (PACKAGE_NAME "rncryptopp")
set (BUILD_DIR build)



# Compile Crypto++
# Must have full paths
set(COMPILE "${PROJECT_SOURCE_DIR}/../scripts/compile_cryptopp_android.sh")
message("COMPILE=${COMPILE}")

execute_process(
        COMMAND ${COMPILE} ${ANDROID_PLATFORM} "${PROJECT_SOURCE_DIR}/.." ${SDK_ROOT_PATH} ${NDK_ROOT_PATH}
        # use these two outputs for ease of debugging & in case of build dir gets cleaned
        # OUTPUT_FILE /home/ubuntu/cryptopp_build.txt
        # ERROR_FILE /home/ubuntu/cryptopp_error.txt
        OUTPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/build/cryptopp_build.txt
        ERROR_FILE ${CMAKE_CURRENT_SOURCE_DIR}/build/cryptopp_error.txt
)

message("CryptoPP build done")
message("--------------------------------------")


# Add headers
include_directories(
        ${PACKAGE_NAME}
        "${NODE_MODULES_DIR}/react-native/React"
        "${NODE_MODULES_DIR}/react-native/React/Base"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi/"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi/jsi"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/callinvoker"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/callinvoker/ReactCommon"
        "${NODE_MODULES_DIR}/react-native/ReactAndroid/src/main/java/com/facebook/react/turbomodule/core/jni"
        "${NODE_MODULES_DIR}/hermes-engine/android/include/"
        "${NODE_MODULES_DIR}/react-native/ReactAndroid/src/main/jni/react/turbomodule" # <-- CallInvokerHolder JNI wrapper
        "../cpp"
        "../cryptopp"
        ".."
)

# Find JSI on React Native 0.66.x and above
# else manually add JSI on React Native 0.65.x and below
# and add all project source files
file(GLOB RN_CRYPTOPP_CPP_FILES "../cpp/*.cpp")
file(GLOB RN_CRYPTOPP_C_FILES "../cpp/*.c")
file(GLOB RN_CRYPTOPP_H_FILES "../cpp/*.h")
file(GLOB RN_CRYPTOPP_HO_FILES "../cpp/host_objects/*.cpp")
file(GLOB RN_CRYPTOPP_HPP_FILES "../cpp/*.hpp")

add_library(
        ${PACKAGE_NAME}
        SHARED
        ${RN_CRYPTOPP_CPP_FILES}
        ${RN_CRYPTOPP_C_FILES}
        ${RN_CRYPTOPP_H_FILES}
        ${RN_CRYPTOPP_HPP_FILES}
        ${RN_CRYPTOPP_HO_FILES}
        ${NODE_MODULES_DIR}/react-native/ReactCommon/jsi/jsi/jsi.cpp
        ./cpp-adapter.cpp
)

find_package(ReactAndroid REQUIRED CONFIG)
find_package(fbjni REQUIRED CONFIG)
find_library(LOG_LIB log)


target_include_directories(
        ${PACKAGE_NAME}
        PRIVATE
        # --- fbjni ---
        "${LIBFBJNI_INCLUDE_DIR}"
        # --- React Native ---
        "${NODE_MODULES_DIR}/react-native/React"
        "${NODE_MODULES_DIR}/react-native/React/Base"
        "${NODE_MODULES_DIR}/react-native/ReactAndroid/src/main/jni"
        "${NODE_MODULES_DIR}/react-native/ReactAndroid/src/main/java/com/facebook/react/turbomodule/core/jni"
        "${NODE_MODULES_DIR}/react-native/ReactCommon"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/callinvoker"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi"
        "${NODE_MODULES_DIR}/hermes-engine/android/include/"
        "../cpp"
)



# Add cryptopp
add_library(cryptopp STATIC IMPORTED)
set_target_properties(
        # Target library
        cryptopp
        # Define property location
        PROPERTIES IMPORTED_LOCATION
        # Path to the library. Must be full path.
        ${PROJECT_SOURCE_DIR}/../cpp/android/libcryptopp_${ANDROID_ABI}.a
)

# Link JNI, JSI, LOG_LIB, and cryptopp
target_link_libraries(
        ${PACKAGE_NAME}
        cryptopp
        fbjni::fbjni
        ReactAndroid::jsi
        ReactAndroid::reactnative
        ${LOG_LIB}
        android
)

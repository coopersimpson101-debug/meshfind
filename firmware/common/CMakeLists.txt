# ESP-IDF component "common": the portable meshfind core.
# (The same sources are built on the host by tools/host_test.py / test/Makefile.)
set(srcs src/mf_crypto_common.c src/mf_proto.c src/mf_mesh.c)
if(CONFIG_MESHFIND_CRYPTO_MBEDTLS)
    list(APPEND srcs src/mf_crypto_mbedtls.c)
else()
    list(APPEND srcs src/mf_crypto_ref.c)
endif()

idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS include
                       REQUIRES mbedtls esp_hw_support)

if(CONFIG_MESHFIND_CRYPTO_MBEDTLS)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC MF_CRYPTO_BACKEND_MBEDTLS)
endif()

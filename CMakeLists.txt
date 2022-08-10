cmake_minimum_required(VERSION 3.20)
project(ecies_demo C)

set(CMAKE_C_STANDARD 99)

set(mbed_crypto
        ./lib/mbedtls/library/aes.c
        ./lib/mbedtls/library/aesni.c
        ./lib/mbedtls/library/aria.c
        ./lib/mbedtls/library/asn1parse.c
        ./lib/mbedtls/library/asn1write.c
        ./lib/mbedtls/library/base64.c
        ./lib/mbedtls/library/bignum.c
        ./lib/mbedtls/library/camellia.c
        ./lib/mbedtls/library/ccm.c
        ./lib/mbedtls/library/chacha20.c
        ./lib/mbedtls/library/chachapoly.c
        ./lib/mbedtls/library/cipher.c
        ./lib/mbedtls/library/cipher_wrap.c
        ./lib/mbedtls/library/constant_time.c
        ./lib/mbedtls/library/cmac.c
        ./lib/mbedtls/library/ctr_drbg.c
        ./lib/mbedtls/library/des.c
        ./lib/mbedtls/library/dhm.c
        ./lib/mbedtls/library/ecdh.c
        ./lib/mbedtls/library/ecdsa.c
        ./lib/mbedtls/library/ecjpake.c
        ./lib/mbedtls/library/ecp.c
        ./lib/mbedtls/library/ecp_curves.c
        ./lib/mbedtls/library/entropy.c
        ./lib/mbedtls/library/entropy_poll.c
        ./lib/mbedtls/library/error.c
        ./lib/mbedtls/library/gcm.c
        ./lib/mbedtls/library/hkdf.c
        ./lib/mbedtls/library/hmac_drbg.c
        ./lib/mbedtls/library/md.c
        ./lib/mbedtls/library/md5.c
        ./lib/mbedtls/library/memory_buffer_alloc.c
        ./lib/mbedtls/library/mps_reader.c
        ./lib/mbedtls/library/mps_trace.c
        ./lib/mbedtls/library/nist_kw.c
        ./lib/mbedtls/library/oid.c
        ./lib/mbedtls/library/padlock.c
        ./lib/mbedtls/library/pem.c
        ./lib/mbedtls/library/pk.c
        ./lib/mbedtls/library/pk_wrap.c
        ./lib/mbedtls/library/pkcs12.c
        ./lib/mbedtls/library/pkcs5.c
        ./lib/mbedtls/library/pkparse.c
        ./lib/mbedtls/library/pkwrite.c
        ./lib/mbedtls/library/platform.c
        ./lib/mbedtls/library/platform_util.c
        ./lib/mbedtls/library/poly1305.c
        ./lib/mbedtls/library/psa_crypto.c
        ./lib/mbedtls/library/psa_crypto_aead.c
        ./lib/mbedtls/library/psa_crypto_cipher.c
        ./lib/mbedtls/library/psa_crypto_client.c
        ./lib/mbedtls/library/psa_crypto_driver_wrappers.c
        ./lib/mbedtls/library/psa_crypto_ecp.c
        ./lib/mbedtls/library/psa_crypto_hash.c
        ./lib/mbedtls/library/psa_crypto_mac.c
        ./lib/mbedtls/library/psa_crypto_rsa.c
        ./lib/mbedtls/library/psa_crypto_se.c
        ./lib/mbedtls/library/psa_crypto_slot_management.c
        ./lib/mbedtls/library/psa_crypto_storage.c
        ./lib/mbedtls/library/psa_its_file.c
        ./lib/mbedtls/library/ripemd160.c
        ./lib/mbedtls/library/rsa.c
        ./lib/mbedtls/library/rsa_alt_helpers.c
        ./lib/mbedtls/library/sha1.c
        ./lib/mbedtls/library/sha256.c
        ./lib/mbedtls/library/sha512.c
        ./lib/mbedtls/library/ssl_debug_helpers_generated.c
        ./lib/mbedtls/library/threading.c
        ./lib/mbedtls/library/timing.c
        ./lib/mbedtls/library/version.c
        ./lib/mbedtls/library/version_features.c
        )

set(mbed_x509
        ./lib/mbedtls/library/x509.c
        ./lib/mbedtls/library/x509_create.c
        ./lib/mbedtls/library/x509_crl.c
        ./lib/mbedtls/library/x509_crt.c
        ./lib/mbedtls/library/x509_csr.c
        ./lib/mbedtls/library/x509write_crt.c
        ./lib/mbedtls/library/x509write_csr.c
        )

include_directories(./lib/mbedtls/include
        ./lib/mbedtls/library)

file (GLOB demo_src ./*.c)

add_executable(ecies_demo
        ${mbed_x509}
        ${mbed_crypto}
        ${demo_src})

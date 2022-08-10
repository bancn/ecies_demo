#include <assert.h>
#include <string.h>
#include <malloc.h>
#include "ecies.h"

char *plain = "test for ecies demo";

int main() {
    ECKEYPAIR keyPair = {0};
    int ret = GenEcKeyPair(MBEDTLS_ECP_DP_SECP256R1, &keyPair);
    assert(ret != 0);

    dump_buf("priv", keyPair.privKey, keyPair.privKeySize);
    dump_buf("pub", keyPair.pubKey, keyPair.pubKeySize);


    BYTEOBJECT in = {.buf = (uint8_t *)plain,
                     .size = strlen(plain) + 1};
    size_t encryptOlen = 16 + 32 + 65 + 16 + in.size;
    uint8_t *cipher = (uint8_t *)calloc(encryptOlen, 1);
    BYTEOBJECT cipherObj = {.buf = cipher, .size = encryptOlen};
    BYTEOBJECT pubKeyA = {.buf = keyPair.pubKey,
                          .size = keyPair.pubKeySize};

    ret = Encrypt(MBEDTLS_ECP_DP_SECP256R1, &pubKeyA, &in, &cipherObj);


    const size_t decryptOlen = encryptOlen - 16 - 32 - 65 - 16;
    uint8_t *plainText = (uint8_t *)calloc(encryptOlen, 1);
    BYTEOBJECT plainObj = {.buf = plainText, .size = decryptOlen};
    BYTEOBJECT privA = {.buf = keyPair.privKey, keyPair.privKeySize};
    ret = Decrypt(MBEDTLS_ECP_DP_SECP256R1, &privA, &cipherObj, &plainObj);

    printf("plaintext = %s\r\n", (char *)plainObj.buf);

    return ret;
}

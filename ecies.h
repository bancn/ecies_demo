//
// Created by Bancn on 2022/8/10.
//

#ifndef ECIES_DEMO_ECIES_H
#define ECIES_DEMO_ECIES_H
#include <mbedtls/ecp.h>
#include "utils.h"

typedef struct {
    size_t privKeySize;
    uint8_t privKey[4096];

    size_t pubKeySize;
    uint8_t pubKey[4096];
}ECKEYPAIR, *P_ECKEYPAIR;

int GenEcKeyPair(mbedtls_ecp_group_id id, P_ECKEYPAIR eckeypair);
int Encrypt(mbedtls_ecp_group_id id, P_BYTEOBJECT pubKeyA, P_BYTEOBJECT in, P_BYTEOBJECT out);
int Decrypt(mbedtls_ecp_group_id id, P_BYTEOBJECT privKeyA, P_BYTEOBJECT in, P_BYTEOBJECT out);
#endif //ECIES_DEMO_ECIES_H

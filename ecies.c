//
// Created by Bancn on 2022/8/10.
//

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <string.h>
#include <stdbool.h>
#include <mbedtls/pk.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/gcm.h>
#include "ecies.h"
#include "utils.h"

int GenRandom(void * p_rng, uint8_t *out, size_t olen)
{
    (void) p_rng;
    const char *peers = "ecies";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int ret;

    do {
        ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, peers, strlen(peers));
        ERROR_BREAK("GenRandom mbedtls_ctr_drbg_seed failed 0x%X\r\n", ret)

        ret = mbedtls_ctr_drbg_random(&ctr_drbg, out, olen);
        ERROR_BREAK("GenRandom mbedtls_ctr_drbg_random failed 0x%X\r\n", ret)
    } while (false);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

int GenEcKeyPair(mbedtls_ecp_group_id id, P_ECKEYPAIR eckeypair)
{
    mbedtls_pk_context key;

    mbedtls_pk_init(&key);

    int ret;
    do {
        ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        ERROR_BREAK("mbedtls_pk_setup failed 0x%X\r\n", ret)

        ret = mbedtls_ecp_gen_key(id, mbedtls_pk_ec(key), GenRandom, NULL);
        ERROR_BREAK("mbedtls_ecp_gen_key failed 0x%08X\r\n", ret )

        uint8_t tmp[4096] = {0};

        ret = mbedtls_pk_write_key_der(&key, tmp, sizeof(tmp));
        if (ret < 0) {
            printf("mbedtls_pk_write_key_der failed 0x%X\r\n", ret);
            break;
        }

        errno_t rc = memcpy_s(eckeypair->privKey, sizeof(eckeypair->privKey), tmp + sizeof(tmp) - ret, ret);
        if (rc != 0) {
            printf("copy privkey failed 0x%08X\r\n", rc);
            break;
        }
        eckeypair->privKeySize = ret;

        ret = mbedtls_pk_write_pubkey_der(&key, tmp, sizeof(tmp));
        if (ret < 0) {
            printf("mbedtls_pk_write_key_der failed 0x%X\r\n", ret);
            break;
        }
        rc = memcpy_s(eckeypair->pubKey, sizeof(eckeypair->pubKey), tmp + sizeof(tmp) - ret, ret);
        if (rc != 0) {
            printf("copy pubKey failed 0x%08X\r\n", rc);
            break;
        }
        eckeypair->pubKeySize = ret;

    } while (false);


    mbedtls_pk_free(&key);
    return ret;
}

int Encrypt(mbedtls_ecp_group_id id, P_BYTEOBJECT pubKeyA, P_BYTEOBJECT in, P_BYTEOBJECT out)
{
    mbedtls_pk_context pkContextB;
    mbedtls_pk_context pkContextA;
    mbedtls_ecp_point S;
    mbedtls_md_context_t mdCtx;
    mbedtls_gcm_context aesCtx;

    mbedtls_pk_init(&pkContextB);
    mbedtls_pk_init(&pkContextA);
    mbedtls_ecp_point_init(&S);
    mbedtls_md_init(&mdCtx);
    mbedtls_gcm_init(&aesCtx);

    int ret;
    do {
        ret = mbedtls_pk_setup(&pkContextB, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        ERROR_BREAK("mbedtls_pk_setup failed 0x%X\r\n", ret)

        ret = mbedtls_pk_parse_public_key(&pkContextA, pubKeyA->buf, pubKeyA->size);
        ERROR_BREAK("mbedtls_pk_parse_public_key failed 0x%X\r\n", ret)

        mbedtls_ecp_keypair *ecpKeypairA = mbedtls_pk_ec(pkContextA);
        mbedtls_ecp_keypair *ecpKeypairB = mbedtls_pk_ec(pkContextB);

        ret = mbedtls_ecp_gen_key(id, ecpKeypairB, GenRandom, NULL);
        ERROR_BREAK("mbedtls_ecp_gen_key failed 0x%08X\r\n", ret )

        ret = mbedtls_ecp_check_pubkey(&ecpKeypairB->private_grp, &ecpKeypairA->private_Q);
        ERROR_BREAK("mbedtls_ecp_check_pubkey failed 0x%08X\r\n", ret )

        ret = mbedtls_ecp_mul(&ecpKeypairB->private_grp, &S, &ecpKeypairB->private_d, &ecpKeypairA->private_Q, GenRandom, NULL);
        ERROR_BREAK("mbedtls_ecp_mul failed 0x%08X\r\n", ret )

        size_t SBytesLen = 0;
        uint8_t SBytes[4096] = {0};
        ret = mbedtls_ecp_point_write_binary(&ecpKeypairB->private_grp, &S, MBEDTLS_ECP_PF_UNCOMPRESSED, &SBytesLen, SBytes, sizeof(SBytes));
        ERROR_BREAK("mbedtls_ecp_point_write_binary failed 0x%08X\r\n", ret )

        size_t RBytesLen = 0;
        uint8_t RBytes[4096] = {0};
        ret = mbedtls_ecp_point_write_binary(&ecpKeypairB->private_grp, &ecpKeypairB->private_Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &RBytesLen, RBytes, sizeof(RBytes));
        ERROR_BREAK("mbedtls_ecp_point_write_binary failed 0x%08X\r\n", ret )

        uint8_t salt[32] = {0};
        uint8_t iv[16] = {0};
        uint8_t aesKey[32] = {0};
        GenRandom(NULL, salt, sizeof(salt));
        GenRandom(NULL, iv, sizeof(iv));

        ret = mbedtls_md_setup(&mdCtx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1);
        ERROR_BREAK("mbedtls_md_setup failed 0x%X", ret)

        ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), salt, 32, SBytes, SBytesLen, NULL, 0, aesKey, sizeof(aesKey));
        ERROR_BREAK("mbedtls_hkdf failed 0x%X", ret)

        ret = mbedtls_gcm_setkey(&aesCtx, MBEDTLS_CIPHER_ID_AES, aesKey, 256);
        ERROR_BREAK("mbedtls_gcm_setkey failed 0x%X", ret)


        uint8_t *o = out->buf;
        memcpy(o, iv, sizeof(iv));
        o += sizeof(iv);

        memcpy(o, salt, sizeof(salt));
        o += sizeof(salt);

        memcpy(o, RBytes, RBytesLen);
        o+= RBytesLen;
        size_t tagLen = 16;
        ret = mbedtls_gcm_crypt_and_tag(&aesCtx, MBEDTLS_GCM_ENCRYPT, in->size,
                    iv, sizeof(iv), NULL, 0, in->buf, o + tagLen, tagLen, o);
        ERROR_BREAK("mbedtls_gcm_crypt_and_tag failed 0x%X", ret)

    } while (false);

    mbedtls_gcm_free(&aesCtx);
    mbedtls_md_free(&mdCtx);

    mbedtls_ecp_point_free(&S);

    mbedtls_pk_free(&pkContextA);
    mbedtls_pk_free(&pkContextB);
    return ret;
}


int Decrypt(mbedtls_ecp_group_id id, P_BYTEOBJECT privKeyA, P_BYTEOBJECT in, P_BYTEOBJECT out)
{
    mbedtls_pk_context pkContextA;
    mbedtls_ecp_point R;
    mbedtls_ecp_point S;

    mbedtls_md_context_t mdCtx;
    mbedtls_gcm_context aesCtx;

    mbedtls_pk_init(&pkContextA);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&S);

    mbedtls_md_init(&mdCtx);
    mbedtls_gcm_init(&aesCtx);

    int ret;
    do {
        uint8_t iv[16] = {0};
        uint8_t salt[32] = {0};
        uint8_t tag[16] = {0};
        uint8_t pubKeyB[65] = {0};
        uint8_t aesKey[32] = {0};

        uint8_t *inputBuf = in->buf;
        memcpy(iv, inputBuf, sizeof(iv));
        inputBuf += sizeof(iv);

        memcpy(salt, inputBuf, sizeof(salt));
        inputBuf += sizeof(salt);

        memcpy(pubKeyB, inputBuf, sizeof(pubKeyB));
        inputBuf += sizeof(pubKeyB);

        memcpy(tag, inputBuf, sizeof(tag));
        inputBuf += sizeof(tag);

        const uint8_t *cipherText = inputBuf;

        ret = mbedtls_pk_parse_key(&pkContextA, privKeyA->buf, privKeyA->size, NULL, 0, GenRandom, NULL);
        ERROR_BREAK("mbedtls_pk_parse_key failed 0x%X\r\n", ret)

        mbedtls_ecp_keypair *ecpKeypairA = mbedtls_pk_ec(pkContextA);

        ret = mbedtls_ecp_point_read_binary(&ecpKeypairA->private_grp, &R, pubKeyB, sizeof(pubKeyB));
        ERROR_BREAK("mbedtls_ecp_point_read_binary failed 0x%X\r\n", ret)
        ret = mbedtls_ecp_check_pubkey(&ecpKeypairA->private_grp, &R);
        ERROR_BREAK("mbedtls_ecp_check_pubkey failed 0x%X\r\n", ret)

        ret = mbedtls_ecp_mul(&ecpKeypairA->private_grp, &S, &ecpKeypairA->private_d, &R, GenRandom, NULL);
        ERROR_BREAK("mbedtls_ecp_mul failed 0x%X\r\n", ret)

        size_t SBytesLen = 0;
        uint8_t SBytes[4096] = {0};
        ret = mbedtls_ecp_point_write_binary(&ecpKeypairA->private_grp, &S, MBEDTLS_ECP_PF_UNCOMPRESSED, &SBytesLen, SBytes, sizeof(SBytes));
        ERROR_BREAK("mbedtls_ecp_point_write_binary failed 0x%X\r\n", ret)

        ret = mbedtls_md_setup(&mdCtx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1);
        ERROR_BREAK("mbedtls_md_setup failed 0x%X\r\n", ret)

        ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), salt, sizeof(salt), SBytes, SBytesLen, NULL, 0, aesKey, sizeof(aesKey));
        ERROR_BREAK("mbedtls_hkdf failed 0x%X\r\n", ret)

        ret = mbedtls_gcm_setkey(&aesCtx, MBEDTLS_CIPHER_ID_AES, aesKey, 256);
        ERROR_BREAK("mbedtls_hkdf failed 0x%X\r\n", ret)

        ret = mbedtls_gcm_auth_decrypt(&aesCtx, out->size, iv, sizeof(iv), NULL, 0, tag, sizeof(tag), cipherText, out->buf);
        ERROR_BREAK("mbedtls_gcm_auth_decrypt failed 0x%X\r\n", ret)
    } while (false);

    mbedtls_gcm_free(&aesCtx);
    mbedtls_md_free(&mdCtx);

    mbedtls_ecp_point_free(&S);
    mbedtls_ecp_point_free(&R);
    mbedtls_pk_free(&pkContextA);
    return ret;
}
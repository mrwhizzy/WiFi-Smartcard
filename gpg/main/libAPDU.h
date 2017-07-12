/**
 *
 * Contains functions and more
 * C implementation of OpenPGPApplet.java
 *
 */

#ifndef __LIBAPDU_H__
#define __LIBAPDU_H__

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/config.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"

#define _0 (uint16_t) 0

#define FORCE_SM_GET_CHALLENGE 1

static const uint8_t HISTORICAL[15] = { 0x00, 0x73, 0x00, 0x00, \
                    (uint8_t) 0x80, 0x00, 0x00, 0x00, \
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const uint8_t AID[16] = { (uint8_t) 0xD2, 0x76, 0x00, 0x01, \
                    0x24, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,  \
                    0x00, 0x00, 0x01, 0x00, 0x00 };

// returned by vendor specific command f1
static const uint8_t VERSION[3] = { 0x01, 0x00, 0x12 };

#define SW_NO_ERROR 0x9000
#define SW_BYTES_REMAINING_00 0x6100
#define SW_WARNING_STATE_UNCHANGED 0x6200
#define SW_WRONG_LENGTH 0x6700
#define SW_SECURITY_STATUS_NOT_SATISFIED 0x6982
//#define SW_FILE_INVALID 0x6983    Openpgp defines 6983 as AUTHENTICATION BLOCKED
#define SW_AUTHENTICATION_BLOCKED 0x6983
#define SW_DATA_INVALID 0x6984
#define SW_CONDITIONS_NOT_SATISFIED 0x6985
#define SW_WRONG_DATA 0x6A80
#define SW_RECORD_NOT_FOUND 0x6A83
#define SW_INCORRECT_P1P2 0x6A86
#define SW_REFERENCED_DATA_NOT_FOUND 0x6A88
#define SW_WRONG_P1P2 0x6B00
#define SW_INS_NOT_SUPPORTED 0x6D00
#define SW_UNKNOWN 0x6F00

/**
 *  0xF8, // Support for GET CHALLENGE
 *               // Support for Key Import
 *               // PW1 Status byte changeable
 *               // Support for private use data objects
 *  0x00,       // Secure messaging using 3DES
 *  0x00, 0xFF, // Maximum length of challenges
 *  0x04, 0xC0, // Maximum length Cardholder Certificate
 *  0x00, 0xFF, // Maximum length command data
 *  0x00, 0xFF  // Maximum length response data
 */
static const uint8_t EXTENDED_CAP[10] = { (uint8_t) 0xF8, 0x00, \
                    0x00, (uint8_t) 0xFF, 0x04, (uint8_t) 0xC0, \
                    0x00, (uint8_t) 0xFF, 0x00, (uint8_t) 0xFF };

#define RESPONSE_MAX_LENGTH 255
#define CHALLENGES_MAX_LENGTH 255

#define BUFFER_MAX_LENGTH 1221

#define LOGINDATA_MAX_LENGTH 254
#define URL_MAX_LENGTH 254
#define NAME_MAX_LENGTH 39
#define LANG_MAX_LENGTH 8
#define CERT_MAX_LENGTH 1216
#define PRIVATE_DO_MAX_LENGTH 254

#define FP_LENGTH 20
#define PIN_LIMIT 3

#define PW1_MIN_LENGTH 6
#define PW1_MAX_LENGTH 127
// Default PW1 '123456'
static uint8_t PW1_DEFAULT[6] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
#define PW1_MODE_NO81 0
#define PW1_MODE_NO82 1

#define RC_MIN_LENGTH 8
#define RC_MAX_LENGTH 127

#define PW3_MIN_LENGTH 8
#define PW3_MAX_LENGTH 127
// Default PW3 '12345678'
static uint8_t PW3_DEFAULT[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };

#define KEY_SIZE 2048
#define KEY_SIZE_BYTES 256
#define EXPONENT_SIZE 17
#define EXPONENT_SIZE_BYTES 3
#define EXPONENT 65537
#define FP_SIZE 20

uint8_t loginData[LOGINDATA_MAX_LENGTH];
short int loginData_length;

uint8_t url[URL_MAX_LENGTH];
short int url_length;

uint8_t name[NAME_MAX_LENGTH];
short int name_length;

uint8_t lang[LANG_MAX_LENGTH];
short int lang_length;

uint8_t cert[CERT_MAX_LENGTH];
short int cert_length;

uint8_t sex;

uint8_t private_use_do_1[PRIVATE_DO_MAX_LENGTH];
short int private_use_do_1_length;

uint8_t private_use_do_2[PRIVATE_DO_MAX_LENGTH];
short int private_use_do_2_length;

uint8_t private_use_do_3[PRIVATE_DO_MAX_LENGTH];
short int private_use_do_3_length;

uint8_t private_use_do_4[PRIVATE_DO_MAX_LENGTH];
short int private_use_do_4_length;

typedef struct apdu_t {
    uint8_t CLA;
    uint8_t INS;
    uint8_t P1;
    uint8_t P2;
    uint16_t P1P2;
    uint16_t Le;        // Check for correct parsing
    uint16_t Lc;        // Check for correct parsing
    uint8_t data[256];     // maybe 128 is enough
} apdu_t;

typedef struct outData {
    uint16_t length;
    uint8_t data[RESPONSE_MAX_LENGTH+2];
} outData;

typedef struct ownerPIN {
    uint8_t remaining;
    uint8_t limit;
    uint8_t value[PW1_MAX_LENGTH+1];    // PW1_MAX_LENGTH == PW3_MAX_LENGTH == RC_MAX_LENGTH
    uint8_t validated;
} ownerPIN;

ownerPIN pw1;
uint8_t pw1_length;
uint8_t pw1_status;
uint16_t pw1_modes[2];

ownerPIN rc;
uint8_t rc_length;

ownerPIN pw3;
uint8_t pw3_length;

uint8_t ds_counter[3];

mbedtls_rsa_context sigKey, decKey, authKey;
uint8_t isSigEmpty, isDecEmpty, isAuthEmpty;
uint8_t sigAttributes[6] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x03 };
uint8_t sigFP[FP_SIZE];
uint8_t sigTime[4] = { 0x00, 0x00, 0x00, 0x00 };
uint8_t decAttributes[6] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x03 };
uint8_t decFP[FP_SIZE];
uint8_t decTime[4] = { 0x00, 0x00, 0x00, 0x00 };
uint8_t authAttributes[6] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x03 };
uint8_t authFP[FP_SIZE];
uint8_t authTime[4] = { 0x00, 0x00, 0x00, 0x00 };

uint8_t ca1_fp[FP_LENGTH];
uint8_t ca2_fp[FP_LENGTH];
uint8_t ca3_fp[FP_LENGTH];

//mbedtls_rsa_context cipher;

uint8_t buffer[BUFFER_MAX_LENGTH];
uint16_t out_left = 0;
uint16_t out_sent = 0;
uint16_t in_received = 0;

uint8_t chain = 0;      // false
uint8_t chain_ins = 0;
uint16_t chain_p1p2 = 0;

uint8_t terminated = 0; // false


/**
 * Parse the receive buffer to an APDU struct.
 * 
 * @param recvBuf The receive buffer
 * @param n The length of the buffer
 */
apdu_t parseAPDU(char* recvBuf, int n){
    apdu_t newAPDU;

    newAPDU.Lc = 0;
    newAPDU.Le = 0;
    bzero(newAPDU.data, sizeof(newAPDU.data));

    newAPDU.CLA = recvBuf[0];
    newAPDU.INS = recvBuf[1];
    newAPDU.P1 = recvBuf[2];
    newAPDU.P2 = recvBuf[3];
    newAPDU.P1P2 = newAPDU.P1 << 8 | newAPDU.P2;
    if (n == 5) {           // Le
        newAPDU.Le = (uint16_t) (0xFF & recvBuf[4]);
    } else if (n > 5) {
        newAPDU.Lc = (uint16_t) (0xFF & recvBuf[4]);
        if (n > 5 + newAPDU.Lc) {   // Lc | Data | Le
            newAPDU.Le = (uint16_t) (0xFF & recvBuf[5+newAPDU.Lc]);
            memcpy(newAPDU.data, (recvBuf+5), n-6);
        } else {                // Lc | Data
            memcpy(newAPDU.data, (recvBuf+5), n-5);
        }
    }
    return newAPDU;
}

/**
 * Return the key of the type requested:
 * - B6: Digital signatures
 * - B8: Confidentiality
 * - A4: Authentication
 *
 * @param type
 *            Type of key to be returned
 * @return Key of requested type
 */
mbedtls_rsa_context getKey(uint8_t type) {
    static const char *TAG = "getKey";
    mbedtls_rsa_context key = sigKey;

    if (type == (uint8_t) 0xB6) {
        key = sigKey;
    } else if (type == (uint8_t) 0xB8) {
        key = decKey;
    } else if (type == (uint8_t) 0xA4) {
        key = authKey;
    } else {
        ESP_LOGE(TAG, "SW_UNKNOWN");
    }

    return key;
}

int keyGen(uint8_t type) {
    static const char* TAG = "keyGen";

    int ret;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context* key;
    FILE* fpriv = NULL;
    const char* pers = "keyGen";
    
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers, strlen(pers))) != 0) {
        ESP_LOGE(TAG, "\nError:\tmbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exitKG;
    }

    if (type == (uint8_t) 0xB6) {
        key = &sigKey;
        if ((fpriv = fopen("/spiflash/sigKey.txt", "wb")) == NULL) {
            ESP_LOGE(TAG, "\nError:\tCould not open sigKey.txt for writing\n");
            goto exitKG;
        }
    } else if (type == (uint8_t) 0xB8) {
        key = &decKey;
        if ((fpriv = fopen("/spiflash/decKey.txt", "wb")) == NULL) {
            ESP_LOGE(TAG, "\nError:\tCould not open decKey.txt for writing\n");
            goto exitKG;
        }
    } else if (type == (uint8_t) 0xA4) {
        key = &authKey;
        if ((fpriv = fopen("/spiflash/authKey.txt", "wb")) == NULL) {
            ESP_LOGE(TAG, "\nError:\tCould not open authKey.txt for writing\n");
            goto exitKG;
        }
    } else {
        ESP_LOGE(TAG, "SW_UNKNOWN");
        goto exitKG;
    }

    if ((ret = mbedtls_rsa_gen_key(key, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, EXPONENT)) != 0){
        ESP_LOGE(TAG, "\nError:\tmbedtls_rsa_gen_key returned %d\n\n", ret);
        goto exitKG;
    }

    if ((ret = mbedtls_mpi_write_file("N = " , &key->N , 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("E = " , &key->E , 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("D = " , &key->D , 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("P = " , &key->P , 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("Q = " , &key->Q , 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("DP = ", &key->DP, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("DQ = ", &key->DQ, 16, fpriv)) != 0 ||
        (ret = mbedtls_mpi_write_file("QP = ", &key->QP, 16, fpriv)) != 0) {
        ESP_LOGE(TAG, "\nError:\tmbedtls_mpi_write_file returned %d\n\n", ret);
        fclose(fpriv);
        goto exitKG;
    }
    fclose(fpriv);
    ret = 0;
    ESP_LOGI(TAG, "\nSuccess\n");

exitKG:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

// Function just to read and print the keys from the flash storage
uint8_t readKeys(uint8_t type) {
    static const char *TAG = "readKeys";
    mbedtls_rsa_context* key;
    uint16_t ret = 0;
    FILE *f;

    if (type == (uint8_t) 0xB6) {
        key = &sigKey;
        if ((f = fopen("/spiflash/sigKey.txt", "rb")) == NULL) {
            ESP_LOGE(TAG, "\nError:\tCould not open sigKey.txt for reading\n");
            goto exitRK;
        }
    } else if (type == (uint8_t) 0xB8) {
        key = &decKey;
        if ((f = fopen("/spiflash/decKey.txt", "rb")) == NULL) {
            ESP_LOGE(TAG, "\nError:\tCould not open decKey.txt for reading\n");
            goto exitRK;
        }
    } else if (type == (uint8_t) 0xA4) {
        key = &authKey;
        if ((f = fopen("/spiflash/authKey.txt", "rb")) == NULL) {
            ESP_LOGE(TAG, "\nError:\tCould not open authKey.txt for reading\n");
            goto exitRK;
        }
    } else {
        ESP_LOGE(TAG, "Some error must have happened");
        goto exitRK;
    }

    if ((ret = mbedtls_mpi_read_file(&key->N , 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&key->E , 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&key->D , 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&key->P , 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&key->Q , 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&key->DP, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&key->DQ, 16, f)) != 0 ||
        (ret = mbedtls_mpi_read_file(&key->QP, 16, f)) != 0) {
        ESP_LOGE(TAG, "\nError:\tmbedtls_mpi_read_file returned %d\n\n", ret);
        fclose(f);
        goto exitRK;
    }

    ret = (mbedtls_mpi_bitlen(&key->N) + 7) >> 3;
    key->len = ret;

    // for testing purposes
    rewind(f);
    char line[2048];
    size_t newLen = fread(line, sizeof(char), 2048, f);
    if (newLen != 0) {
        line[++newLen] = '\0';
    }
    fclose(f);
    ESP_LOGI(TAG, "Read from key file:\n%s\n", line);
    // testing purposes end here

exitRK:
    return ret;
}

/**
 * Check the password of a given PIN against the input.
 * 
 * @param pw The PIN struct
 * @param pin The tested PIN password
 * @param length Length of the tested password
 */
uint8_t checkPIN(ownerPIN* pw, uint8_t* pin, uint8_t length) {
    if (pw->remaining == 0) {
        return 0;
    }
    pw->remaining = (uint8_t) (pw->remaining - 1);
    pw->validated = 0;

    if (pw->value[0] != length) {   // * OOPS, timing attack vulnerability spotted! :D
        return 0;                   // At least you can infer the length of the PIN
    }

    if (memcmp(pin, &pw->value[1], length) == 0) {
        pw->validated = 1;
        pw->remaining = (uint8_t) (pw->remaining + 1); // Restore
        return 1;
    }
    return 0;
}

/**
 * Update the password of a given PIN.
 * 
 * @param pw The PIN struct
 * @param pin The new PIN password
 * @param length Length of the new password
 */
uint8_t updatePIN(ownerPIN* pw, uint8_t* pin, uint16_t offset, uint8_t length) {
    if (length > (sizeof(pw->value)/sizeof(pw->value[0]) + 1)) {
        return 1;
    }
    bzero(pw->value, sizeof(pw->value));
    pw->value[0] = length;
    uint8_t* pinOffset = pin + offset;
    memcpy(&(pw->value[1]), pinOffset, length);
    pw->validated = (uint8_t) 0;
    pw->remaining = pw->limit;
    return 0;
}

/**
 * Reset the chaining variables.
 */
void resetChaining() {
    chain = 0;
    in_received = 0;
}

/**
 * Provide support for command chaining by storing the received data in
 * buffer
 * 
 * @param apdu
 */
uint16_t commandChaining(apdu_t apdu){
    static const char* TAG = "commandChaining";
    uint16_t len = apdu.Lc;

    if (chain != 0) {
        resetChaining();
    }

    if ((uint8_t) (apdu.CLA & (uint8_t) 0x10) == (uint8_t) 0x10) {
        // If chaining was already initiated, INS and P1P2 should match
        if ((chain == 1) && (apdu.INS != chain_ins && apdu.P1P2 != chain_p1p2)) {
            resetChaining();
            ESP_LOGE(TAG, "SW_CONDITIONS_NOT_SATISFIED");
            return SW_CONDITIONS_NOT_SATISFIED;
        }

        // Check whether data to be received is larger than size of the buffer
        if ((uint16_t) (in_received + len) > BUFFER_MAX_LENGTH) {
            resetChaining();
            ESP_LOGE(TAG, "SW_WRONG_DATA");
            return SW_WRONG_DATA;
        }

        // Store received data in buffer
        uint8_t* bufOffset = buffer + in_received;
        memcpy(bufOffset, apdu.data, len);
        in_received += len;

        chain = 1;
        chain_ins = apdu.INS;
        chain_p1p2 = apdu.P1P2;
        ESP_LOGE(TAG, "SW_NO_ERROR");
        return SW_NO_ERROR;
    }

    if ((chain == 1) && (apdu.INS == chain_ins) && (apdu.P1P2 == chain_p1p2)) {
        chain = 0;

        // Check whether data to be received is larger than size of the buffer
        if ((uint16_t) (in_received + len) > BUFFER_MAX_LENGTH) {
            resetChaining();
            ESP_LOGE(TAG, "SW_WRONG_DATA");
            return SW_WRONG_DATA;
        }

        // Add received data to the buffer
        uint8_t* bufOffset = buffer + in_received;
        memcpy(bufOffset, apdu.data, len);
        in_received += len;
        return SW_NO_ERROR;
    } else if (chain == 1) {
        // Chained command expected
        resetChaining();
        ESP_LOGE(TAG, "SW_UNKNOWN");
        return SW_UNKNOWN;
    } else {
        // No chaining was used, so copy data to buffer
        memcpy(buffer, apdu.data, len);
        in_received = len;
        return SW_NO_ERROR;
    }
}

/**
 * Provide the VERIFY command (INS 20)
 * 
 * Verify one of the passwords depending on mode: - 81: PW1 for a PSO:CDS
 * command - 82: PW1 for other commands - 83: PW3
 * 
 * @param mode
 */
uint16_t verify(uint8_t mode) {
    if (mode == (uint8_t) 0x81 || mode == (uint8_t) 0x82) {
        // Check length of input
        if (in_received < PW1_MIN_LENGTH || in_received > PW1_MAX_LENGTH) {
            return SW_WRONG_DATA;
        }

        // Check given PW1 and set requested mode if verified succesfully
        if (pw1.remaining == 0) {
            return SW_AUTHENTICATION_BLOCKED;
        } else if (checkPIN(&pw1, buffer, (uint8_t) in_received) != 0) {
            if (mode == (uint8_t) 0x81) {
                pw1_modes[PW1_MODE_NO81] = true;
            } else {
                pw1_modes[PW1_MODE_NO82] = true;
            }
        } else {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
    } else if (mode == (uint8_t) 0x83) {
        // Check length of input
        if (in_received < PW3_MIN_LENGTH || in_received > PW3_MAX_LENGTH) {
            return SW_WRONG_DATA;
        }

        // Check PW3
        if (pw3.remaining == 0) {
            return SW_AUTHENTICATION_BLOCKED;
        } else if (checkPIN(&pw3, buffer, (uint8_t) in_received) != 0) {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
    } else {
        return SW_INCORRECT_P1P2;
    }
    return SW_NO_ERROR;
}

/**
 * Provide the CHANGE REFERENCE DATA command (INS 24)
 * 
 * Change the password specified using mode: - 81: PW1 - 82: PW3
 * 
 * @param apdu
 * @param mode
 *            Password to be changed
 */
uint16_t changeReferenceData(uint8_t mode) {
    if (mode == (uint8_t) 0x81) {
        // Check length of the new password
        uint16_t new_length = (uint16_t) (in_received - pw1_length);
        if (new_length < PW1_MIN_LENGTH || new_length > PW1_MAX_LENGTH) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }

        if (checkPIN(&pw1, buffer, (uint8_t) pw1_length) != 0) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }

        // Change PW1
        //JCSystem.beginTransaction();  FIND SOMETHING EQUIVALENT
        updatePIN(&pw1, buffer, pw1_length, (uint8_t) new_length);
        pw1_length = (uint8_t) new_length;
        pw1_modes[PW1_MODE_NO81] = false;
        pw1_modes[PW1_MODE_NO82] = false;
        //JCSystem.commitTransaction(); FIND SOMETHING EQUIVALENT
    } else if (mode == (uint8_t) 0x83) {
        // Check length of the new password
        uint16_t new_length = (uint16_t) (in_received - pw3_length);
        if (new_length < PW3_MIN_LENGTH || new_length > PW3_MAX_LENGTH) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }

        if (checkPIN(&pw3, buffer, (uint8_t) pw3_length) != 0) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }

        // Change PW3
        //JCSystem.beginTransaction();  FIND SOMETHING EQUIVALENT
        updatePIN(&pw3, buffer, pw3_length, (uint8_t) new_length);
        pw3_length = (uint8_t) new_length;
        //JCSystem.commitTransaction(); FIND SOMETHING EQUIVALENT
    }
    return SW_NO_ERROR;
}

/**
 * Provide the RESET RETRY COUNTER command (INS 2C)
 * 
 * Reset PW1 either using the Resetting Code (mode = 00) or PW3 (mode = 02)
 * 
 * @param mode
 *            Mode used to reset PW1
 */
uint16_t resetRetryCounter(uint8_t mode) {
    short int new_length = 0;
    uint16_t offs = 0;
    if (mode == (uint8_t) 0x00) {
        // Authentication using RC
        if (rc_length == 0) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }

        new_length = (short int) (in_received - rc_length);
        offs = rc_length;
        if (checkPIN(&rc, buffer, rc_length) != 0) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
    } else if (mode == (uint8_t) 0x02) {
        // Authentication using PW3
        if (pw3.validated != 1) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        new_length = in_received;
    } else {
        return SW_WRONG_P1P2;
    }

    if (new_length < PW1_MIN_LENGTH || new_length > PW1_MAX_LENGTH) {
        return SW_WRONG_DATA;
    }

    // Change PW1
    //JCSystem.beginTransaction();  FIND SOMETHING EQUIVALENT
    updatePIN(&pw1, buffer, offs, (uint8_t) new_length);
    pw1_length = (uint8_t) new_length;
    pw1.validated = 0;
    pw1.remaining = pw1.limit;
    //JCSystem.commitTransaction(); FIND SOMETHING EQUIVALENT
    return SW_NO_ERROR;
}

/**
 * Increase the digital signature counter by one. In case of overflow
 * SW_WARNING_STATE_UNCHANGED will be thrown and nothing will
 * change.
 */
uint16_t increaseDSCounter() {
    for (short int i = (short int) ((sizeof(ds_counter)/sizeof(ds_counter[0])) - 1); i >= 0; i--) {
        if ((uint16_t) (ds_counter[i] & 0xFF) >= 0xFF) {
            if (i == 0) {
                // Overflow
                return SW_WARNING_STATE_UNCHANGED;
            } else {
                ds_counter[i] = 0;
            }
        } else {
            ds_counter[i]++;
            break;
        }
    }
    return SW_NO_ERROR;
}

/**
 * Provide the PSO: COMPUTE DIGITAL SIGNATURE command (INS 2A, P1P2 9E9A)
 * 
 * Sign the data provided using the key for digital signatures.
 * 
 * Before using this method PW1 has to be verified with mode No. 81. If the
 * first status byte of PW1 is 00, access condition PW1 with No. 81 is
 * reset.
 * 
 * @param length Length of data written in buffer
 */
uint16_t computeDigitalSignature(uint16_t* length) {
    size_t len;
    if (!((pw1.validated == 1) && (pw1_modes[PW1_MODE_NO81] == 1))){
        return SW_SECURITY_STATUS_NOT_SATISFIED;
    }

    if (pw1_status == (uint8_t) 0x00) {
        pw1_modes[PW1_MODE_NO81] = 0;
    }

    if (isSigEmpty) {
        return SW_REFERENCED_DATA_NOT_FOUND;
    }

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    const char *pers = "computeDigitalSignature";

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char *) pers, strlen(pers)) != 0) {
        return SW_UNKNOWN;  // It is not unknown though, there is a return value
    }

    if (increaseDSCounter() != SW_NO_ERROR) {
        return SW_WARNING_STATE_UNCHANGED;
    }

    uint8_t* outOffset = buffer + in_received;
    if(mbedtls_rsa_pkcs1_encrypt(&sigKey, mbedtls_ctr_drbg_random, &ctr_drbg, 
            MBEDTLS_RSA_PRIVATE, in_received, buffer, outOffset) != 0) {
        return SW_UNKNOWN;  // Again, not really unknown...
    }

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    len = (mbedtls_mpi_bitlen(&sigKey.N) + 7) >> 3;
    memcpy(buffer, outOffset, len);  // * Rest of buffer is non-empty
    (*length) = len;
    return SW_NO_ERROR;
}

/**
 * Provide the PSO: DECIPHER command (INS 2A, P1P2 8086)
 * 
 * Decrypt the data provided using the key for confidentiality.
 * 
 * Before using this method PW1 has to be verified with mode No. 82.
 * 
 * @param length Length of data written in buffer
 */
uint16_t decipher(uint16_t* length) {
    // DECIPHER
    if (!((pw1.validated == 1) && pw1_modes[PW1_MODE_NO82])) {
        return SW_SECURITY_STATUS_NOT_SATISFIED;
    }

    if (isDecEmpty) {
        return SW_REFERENCED_DATA_NOT_FOUND;
    }

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    const char *pers = "decipher";

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char *) pers, strlen(pers)) != 0) {
        return SW_UNKNOWN;  // Same as above
    }

    // Start at offset 1 to omit padding indicator byte
    uint8_t* inOffset = buffer + 1;
    uint8_t* outOffset = buffer + in_received;
    size_t len;

    // in_received - 1 or in_received??
    if ((in_received - 1) != ((mbedtls_mpi_bitlen(&decKey.N) + 7) >> 3)) {
        return SW_DATA_INVALID;
    }

    if(mbedtls_rsa_pkcs1_decrypt(&decKey, mbedtls_ctr_drbg_random, &ctr_drbg,
            MBEDTLS_RSA_PRIVATE, &len, inOffset, outOffset, (BUFFER_MAX_LENGTH - in_received)) != 0) {
        return SW_UNKNOWN;  // Again, not really unknown...
    }

    memcpy(buffer, outOffset, len);  // * Rest of buffer is non-empty, again
    (*length) = len;
    return SW_NO_ERROR;
}

/**
 * Provide the INTERNAL AUTHENTICATE command (INS 88)
 * 
 * Sign the data provided using the key for authentication. Before using
 * this method PW1 has to be verified with mode No. 82.
 * 
 * @param length Length of data written in buffer
 */
uint16_t internalAuthenticate(uint16_t* length) {
    size_t len;
    if (!((pw1.validated == 1) && pw1_modes[PW1_MODE_NO82])) {
        return SW_SECURITY_STATUS_NOT_SATISFIED;
    }

    if (isAuthEmpty) {
        return SW_REFERENCED_DATA_NOT_FOUND;
    }

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    const char *pers = "internalAuthenticate";

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        (const unsigned char *) pers, strlen(pers)) != 0) {
        return SW_UNKNOWN;  // Same as above
    }

    uint8_t* outOffset = buffer + in_received;
    if(mbedtls_rsa_pkcs1_encrypt(&authKey, mbedtls_ctr_drbg_random, &ctr_drbg, 
            MBEDTLS_RSA_PRIVATE, in_received, buffer, outOffset) != 0) {
        return SW_UNKNOWN;  // Again, not really unknown...
    }

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    len = (mbedtls_mpi_bitlen(&authKey.N) + 7) >> 3;
    memcpy(buffer, outOffset, len);  // * Rest of buffer is non-empty
    (*length) = len;
    return SW_NO_ERROR;
}

/**
 * Output the public key of the given key pair.
 * 
 * @param key
 *            Key pair containing public key to be output
 */
uint16_t sendPublicKey(mbedtls_rsa_context key) {
    // Build message in buffer
    short int offset = 0;

    buffer[offset++] = 0x7F;
    buffer[offset++] = 0x49;
    buffer[offset++] = (uint8_t) 0x82;
    short int offsetForLength = offset;
    offset += 2;

    // 81 - Modulus
    buffer[offset++] = (uint8_t) 0x81;

    // Length of modulus is always greater than 128 bytes
    if (KEY_SIZE_BYTES < 256) {
        buffer[offset++] = (uint8_t) 0x81;
        buffer[offset++] = (uint8_t) KEY_SIZE_BYTES;
    } else {
        buffer[offset++] = (uint8_t) 0x82;
        buffer[offset++] = (uint8_t) (KEY_SIZE_BYTES >> 8);
        buffer[offset++] = (uint8_t) (KEY_SIZE_BYTES & 0x00FF);
    }

    uint8_t* bufOffset = buffer + offset;
    mbedtls_mpi_write_binary(&key.N, bufOffset, KEY_SIZE_BYTES);
    offset += KEY_SIZE_BYTES;

    // 82 - Exponent
    buffer[offset++] = (uint8_t) 0x82;
    buffer[offset++] = (uint8_t) EXPONENT_SIZE_BYTES;
    bufOffset = buffer + offset;
    mbedtls_mpi_write_binary(&key.E, bufOffset, EXPONENT_SIZE_BYTES);
    offset += EXPONENT_SIZE_BYTES;

    buffer[offsetForLength] = (uint8_t) ((offset - offsetForLength - 2) >> 8);
    buffer[offsetForLength+1] = (uint8_t) ((offset - offsetForLength - 2) & 0x00FF);

    return offset;
}


/**
 * Provide the GENERATE ASYMMETRIC KEY PAIR command (INS 47)
 * 
 * For mode 80, generate a new key pair, specified in the first element of
 * buffer, and output the public key.
 * 
 * For mode 81, output the public key specified in the first element of
 * buffer.
 * 
 * Before using this method PW3 has to be verified.
 * 
 * @param mode
 *            Generate key pair (80) or read public key (81)
 * @return Length of data written in buffer
 */
uint16_t genAsymKey(uint8_t mode) {
    static const char* TAG = "genAsymKey";

    if (mode == (uint8_t) 0x80) {
        if (pw3.validated == 0) {
            ESP_LOGE(TAG, "SW_SECURITY_STATUS_NOT_SATISFIED");
            return 0;
        }

        keyGen(buffer[0]);

        if (buffer[0] == (uint8_t) 0xB6) {
            bzero(ds_counter, sizeof(ds_counter));
        }
    }

    // Output requested key
    return sendPublicKey(getKey(buffer[0]));
}


/**
 * Provide the GET CHALLENGE command (INS 84)
 * 
 * Generate a random number of the length given in len.
 * 
 * @param len Length of the requested challenge
 * @param length Length of data written in buffer
 */
uint16_t getChallenge(uint16_t len, uint16_t* length) {
    if (len > CHALLENGES_MAX_LENGTH)
        return SW_WRONG_DATA;

    srand((unsigned int) time(NULL));
    for (int i = 0; i < len; i++) {
        buffer[i] = (uint8_t) rand() & 0xFF;
    }

    (*length) = len;
    return SW_NO_ERROR;
}

/**
 * Provide the GET DATA command (INS CA)
 * 
 * Output the data specified with tag.
 * 
 * @param tag Tag of the requested data
 * @param ret Length of data written in buffer
 */
uint16_t getData(short tag, uint16_t* ret) {
    uint16_t offset = 0;
    uint8_t* bufOffset;
        
    switch (tag) {
    // 4F - Application identifier (AID)
    case (uint16_t) 0x004F:
        memcpy(buffer, AID, sizeof(AID));
        (*ret) = sizeof(AID);
        return SW_NO_ERROR;

    // 5E - Login data
    case (uint16_t) 0x005E:
        memcpy(buffer, loginData, loginData_length);
        (*ret) = loginData_length;
        return SW_NO_ERROR;

    // 5F50 - URL
    case (uint16_t) 0x5F50:
        memcpy(buffer, url, url_length);
        (*ret) = url_length;
        return SW_NO_ERROR;

    // 5F52 - Historical bytes
    case (uint16_t) 0x5F52:
        memcpy(buffer, HISTORICAL, sizeof(HISTORICAL));
        (*ret) = sizeof(HISTORICAL);
        return SW_NO_ERROR;

    // 65 - Cardholder Related Data
    case (uint16_t) 0x0065:

        // 5B - Name
        buffer[offset++] = 0x5B;
        buffer[offset++] = (uint8_t) name_length;
        bufOffset = buffer + offset;
        memcpy(bufOffset, name, name_length);
        offset += name_length;

        // 5F2D - Language
        buffer[offset++] = 0x5F;
        buffer[offset++] = 0x2D;
        buffer[offset++] = (uint8_t) lang_length;
        bufOffset = buffer + offset;
        memcpy(bufOffset, lang, lang_length);
        offset += lang_length;

        // 5F35 - Sex
        buffer[offset++] = 0x5F;
        buffer[offset++] = 0x35;
        buffer[offset++] = 0x01;
        buffer[offset++] = sex;

        (*ret) = offset;
        return SW_NO_ERROR;

    // 6E - Application Related Data
    case (uint16_t) 0x006E:

        // 4F - AID
        buffer[offset++] = 0x4F;
        buffer[offset++] = sizeof(AID);
        bufOffset = buffer + offset;
        memcpy(bufOffset, AID, sizeof(AID));
        offset += sizeof(AID);

        // 5F52 - Historical bytes
        buffer[offset++] = 0x5F;
        buffer[offset++] = 0x52;
        buffer[offset++] = (uint8_t) sizeof(HISTORICAL);
        bufOffset = buffer + offset;
        memcpy(bufOffset, HISTORICAL, sizeof(HISTORICAL));
        offset += sizeof(HISTORICAL);

        // 73 - Discretionary data objects
        buffer[offset++] = 0x73;
        buffer[offset++] = (uint8_t) 0x81; // This field's length will exceed 127 bytes
        uint16_t ddoLengthOffset = offset;
        buffer[offset++] = 0x00; // Placeholder for length byte

        // C0 - Extended capabilities
        buffer[offset++] = (uint8_t) 0xC0;
        buffer[offset++] = (uint8_t) sizeof(EXTENDED_CAP);
        bufOffset = buffer + offset;
        memcpy(bufOffset, EXTENDED_CAP, sizeof(EXTENDED_CAP));
        offset += sizeof(EXTENDED_CAP);

        // C1 - Algorithm attributes signature
        buffer[offset++] = (uint8_t) 0xC1;
        buffer[offset++] = (uint8_t) 0x06;
        bufOffset = buffer + offset;
        memcpy(bufOffset, sigAttributes, sizeof(sigAttributes));
        offset += sizeof(sigAttributes);

        // C2 - Algorithm attributes decryption
        buffer[offset++] = (uint8_t) 0xC2;
        buffer[offset++] = (uint8_t) 0x06;
        bufOffset = buffer + offset;
        memcpy(bufOffset, decAttributes, sizeof(decAttributes));
        offset += sizeof(decAttributes);

        // C3 - Algorithm attributes authentication
        buffer[offset++] = (uint8_t) 0xC3;
        buffer[offset++] = (uint8_t) 0x06;
        bufOffset = buffer + offset;
        memcpy(bufOffset, authAttributes, sizeof(authAttributes));
        offset += sizeof(authAttributes);

        // C4 - PW1 Status bytes
        buffer[offset++] = (uint8_t) 0xC4;
        buffer[offset++] = 0x07;
        buffer[offset++] = pw1_status;
        buffer[offset++] = PW1_MAX_LENGTH;
        buffer[offset++] = RC_MAX_LENGTH;
        buffer[offset++] = PW3_MAX_LENGTH;
        buffer[offset++] = pw1.remaining;
        buffer[offset++] = rc.remaining;
        buffer[offset++] = pw3.remaining;

        // C5 - Fingerprints sign, dec and auth keys
        buffer[offset++] = (uint8_t) 0xC5;
        buffer[offset++] = (uint16_t) 60;   // * Doesn't really make sense to cast to 16-bit
        bufOffset = buffer + offset;
        memcpy(bufOffset, sigFP, FP_SIZE);
        offset += FP_SIZE;
        bufOffset = buffer + offset;
        memcpy(bufOffset, decFP, FP_SIZE);
        offset += FP_SIZE;
        bufOffset = buffer + offset;
        memcpy(bufOffset, authFP, FP_SIZE);
        offset += FP_SIZE;

        // C6 - Fingerprints CA 1, 2 and 3
        buffer[offset++] = (uint8_t) 0xC6;
        buffer[offset++] = (uint16_t) 60;   // * Again, 16-bit casting to an 8-bit variable...
        bufOffset = buffer + offset;
        memcpy(bufOffset, ca1_fp, FP_LENGTH);
        offset += FP_LENGTH;
        bufOffset = buffer + offset;
        memcpy(bufOffset, ca2_fp, FP_LENGTH);
        offset += FP_LENGTH;
        bufOffset = buffer + offset;
        memcpy(bufOffset, ca3_fp, FP_LENGTH);
        offset += FP_LENGTH;

        // CD - Generation times of public key pair
        buffer[offset++] = (uint8_t) 0xCD;
        buffer[offset++] = (uint16_t) 12;   // * Hope this is the last time of this casting
        bufOffset = buffer + offset;
        memcpy(bufOffset, sigTime, sizeof(sigTime));
        offset += sizeof(sigTime);
        bufOffset = buffer + offset;
        memcpy(bufOffset, decTime, sizeof(decTime));
        offset += sizeof(decTime);
        bufOffset = buffer + offset;
        memcpy(bufOffset, authTime, sizeof(authTime));
        offset += sizeof(authTime);

        // Set length of combined discretionary data objects
        buffer[ddoLengthOffset] = (uint8_t) (offset - ddoLengthOffset - 1);

        (*ret) = offset;
        return SW_NO_ERROR;

    // 7A - Security support template
    case (uint16_t) 0x007A:

        // 93 - Digital signature counter
        buffer[offset++] = (uint8_t) 0x93;
        buffer[offset++] = 0x03;
        bufOffset = buffer + offset;
        memcpy(bufOffset, ds_counter, sizeof(ds_counter));
        offset += sizeof(ds_counter);

        (*ret) = offset;
        return SW_NO_ERROR;

    // 7F21 - Cardholder Certificate
    case (uint16_t) 0x7F21:
        if (cert_length > 0) {
            bufOffset = buffer + offset;
            memcpy(bufOffset, cert, sizeof(cert));
            offset += sizeof(cert);
        }

        (*ret) = offset;
        return SW_NO_ERROR;

    // C4 - PW Status Bytes
    case (uint16_t) 0x00C4:
        buffer[offset++] = pw1_status;
        buffer[offset++] = PW1_MAX_LENGTH;
        buffer[offset++] = RC_MAX_LENGTH;
        buffer[offset++] = PW3_MAX_LENGTH;
        buffer[offset++] = pw1.remaining;
        buffer[offset++] = rc.remaining;
        buffer[offset++] = pw3.remaining;

        (*ret) = offset;
        return SW_NO_ERROR;

    // 0101 - Private Use DO 1
    case (uint16_t) 0x0101:
        memcpy(buffer, private_use_do_1, private_use_do_1_length);
        offset += private_use_do_1_length;
        (*ret) = offset;
        return SW_NO_ERROR;

    // 0102 - Private Use DO 2
    case (uint16_t) 0x0102:
        memcpy(buffer, private_use_do_2, private_use_do_2_length);
        offset += private_use_do_2_length;
        (*ret) = offset;
        return SW_NO_ERROR;

    // 0103 - Private Use DO 3
    case (uint16_t) 0x0103:
        // For private use DO 3, PW1 must be verified with mode 82 to read
        if (!((pw3.validated != 1) && pw1_modes[PW1_MODE_NO82])) {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        memcpy(buffer, private_use_do_3, private_use_do_3_length);
        offset += private_use_do_3_length;
        (*ret) = offset;
        return SW_NO_ERROR;

    // 0104 - Private Use DO 4
    case (uint16_t) 0x0104:
        // For private use DO 4, PW3 must be verified to read
        if (pw3.validated != 1) {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        memcpy(buffer, private_use_do_4, private_use_do_4_length);
        offset += private_use_do_4_length;
        (*ret) = offset;
        return SW_NO_ERROR;

    default:
        return SW_RECORD_NOT_FOUND;
    }

    (*ret) = offset;
    return SW_NO_ERROR;
}

/**
 * Provide the PUT DATA command (INS DA)
 * 
 * Write the data specified using tag.
 * 
 * Before using this method PW3 has to be verified.
 * 
 * @param apdu
 * @param tag
 *            Tag of the requested data
 */
uint16_t putData(uint16_t tag) {
    if((tag == (uint16_t) 0x0101) || (tag == (uint16_t) 0x0103)) {
        // Special case for private use DO's 1 and 3: these can be written if
        // PW1 is verified with mode 82. All others require PW3 verification.
        if (!((pw1.validated == 1) && pw1_modes[PW1_MODE_NO82])) {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }

        if (in_received > PRIVATE_DO_MAX_LENGTH) {
            return SW_WRONG_LENGTH;
        }

        switch (tag) {
        // 0101 - Private Use DO 1
        case (uint16_t) 0x0101:
            //JCSystem.beginTransaction();
            private_use_do_1_length = in_received;
            memcpy(private_use_do_1, buffer, in_received);
            return SW_NO_ERROR;
            //JCSystem.commitTransaction();

        // 0103 - Private Use DO 3
        case (uint16_t) 0x0103:
            //JCSystem.beginTransaction();
            private_use_do_3_length = in_received;
            memcpy(private_use_do_3, buffer, in_received);
            return SW_NO_ERROR;
            //JCSystem.commitTransaction();
        }
    }

    if (pw3.validated == 0) {
        return SW_SECURITY_STATUS_NOT_SATISFIED;
    }

    switch (tag) {
    // 5B - Name
    case (uint16_t) 0x005B:
        if (in_received > NAME_MAX_LENGTH) {
            return SW_WRONG_DATA;
        }
        //JCSystem.beginTransaction();
        memcpy(name, buffer, in_received);
        name_length = in_received;
        return SW_NO_ERROR;
        //JCSystem.commitTransaction();

    // 5E - Login data
    case (uint16_t) 0x005E:
        if (in_received > LOGINDATA_MAX_LENGTH) {
            return SW_WRONG_DATA;
        }
        //JCSystem.beginTransaction();
        memcpy(loginData, buffer, in_received);
        loginData_length = in_received;
        return SW_NO_ERROR;
        //JCSystem.commitTransaction();

    // 5F2D - Language preferences
    case (uint16_t) 0x5F2D:
        if (in_received > LANG_MAX_LENGTH) {
            return SW_WRONG_DATA;
        }
        //JCSystem.beginTransaction();
        memcpy(lang, buffer, in_received);
        lang_length = in_received;
        return SW_NO_ERROR;
        //JCSystem.commitTransaction();

    // 5F35 - Sex
    case (uint16_t) 0x5F35:
        if (in_received != 1) {
            return SW_WRONG_DATA;
        }

        // Check for valid values
        if (buffer[0] != (uint8_t) 0x31 && buffer[0] != (uint8_t) 0x32
                && buffer[0] != (uint8_t) 0x39) {
            return SW_WRONG_DATA;
        }
        sex = buffer[0];
        return SW_NO_ERROR;

    // 5F50 - URL
    case (uint16_t) 0x5F50:
        if (in_received > URL_MAX_LENGTH) {
            return SW_WRONG_DATA;
        }
        //JCSystem.beginTransaction();
        memcpy(url, buffer, in_received);
        url_length = in_received;
        return SW_NO_ERROR;
        //JCSystem.commitTransaction();

    // 7F21 - Cardholder certificate
    case (uint16_t) 0x7F21:
        if (in_received > CERT_MAX_LENGTH) {
            return SW_WRONG_DATA;
        }
        memcpy(cert, buffer, in_received);
        cert_length = in_received;
        return SW_NO_ERROR;

    // C4 - PW Status Bytes
    case (uint16_t) 0x00C4:
        if (in_received != 1) {
            return SW_WRONG_DATA;
        }
        // Check for valid values
        if (buffer[0] != (uint8_t) 0x00 && buffer[0] != (uint8_t) 0x01) {
            return SW_WRONG_DATA;
        }
        pw1_status = buffer[0];
        return SW_NO_ERROR;

    // C7 - Fingerprint signature key
    case (uint16_t) 0x00C7:
        if (in_received != FP_SIZE) {   // * Redundant check in the Java implementation
            return SW_WRONG_DATA;       // Method setFingerprint performs limit checking
        }
        memcpy(sigFP, buffer, in_received);
        return SW_NO_ERROR;

    // C8 - Fingerprint decryption key
    case (uint16_t) 0x00C8:
        if (in_received != FP_SIZE) {   // * Redundant check in the Java implementation
            return SW_WRONG_DATA;       // Method setFingerprint performs limit checking
        }
        memcpy(decFP, buffer, in_received);
        return SW_NO_ERROR;

    // C9 - Fingerprint authentication key
    case (uint16_t) 0x00C9:
        if (in_received != FP_SIZE) {   // * Redundant check in the Java implementation
            return SW_WRONG_DATA;       // Method setFingerprint performs limit checking
        }
        memcpy(authFP, buffer, in_received);
        return SW_NO_ERROR;

    // CA - Fingerprint Certification Authority 1
    case (uint16_t) 0x00CA:
        if (in_received != FP_LENGTH) {
            return SW_WRONG_DATA;
        }
        memcpy(ca1_fp, buffer, in_received);
        return SW_NO_ERROR;

    // CB - Fingerprint Certification Authority 2
    case (uint16_t) 0x00CB:
        if (in_received != FP_LENGTH) {
            return SW_WRONG_DATA;
        }
        memcpy(ca2_fp, buffer, in_received);
        return SW_NO_ERROR;

    // CC - Fingerprint Certification Authority 3
    case (uint16_t) 0x00CC:
        if (in_received != FP_LENGTH) {
            return SW_WRONG_DATA;
        }
        memcpy(ca3_fp, buffer, in_received);
        return SW_NO_ERROR;

    // CE - Signature key generation date/time
    case (uint16_t) 0x00CE:
        if (in_received != 4) {     // * Redundant check in the Java implementation
            return SW_WRONG_DATA;   // Method setTime performs limit checking
        }
        memcpy(sigTime, buffer, in_received);
        return SW_NO_ERROR;

    // CF - Decryption key generation date/time
    case (uint16_t) 0x00CF:
        if (in_received != 4) {     // * Redundant check in the Java implementation
            return SW_WRONG_DATA;   // Method setTime performs limit checking
        }
        memcpy(decTime, buffer, in_received);
        return SW_NO_ERROR;

    // D0 - Authentication key generation date/time
    case (short) 0x00D0:
        if (in_received != 4) {     // * Redundant check in the Java implementation
            return SW_WRONG_DATA;   // Method setTime performs limit checking
        }
        memcpy(authTime, buffer, in_received);
        return SW_NO_ERROR;

    // D3 - Resetting Code
    case (uint16_t) 0x00D3:
        if (in_received == 0) {
            rc_length = 0;
        } else if (in_received >= RC_MIN_LENGTH
                && in_received <= RC_MAX_LENGTH) {
            //JCSystem.beginTransaction();
            updatePIN(&rc, buffer, 0, (uint8_t) in_received);
            rc_length = (uint8_t) in_received;
            rc.validated = 0;
            rc.remaining = rc.limit;
            //JCSystem.commitTransaction();
        } else {
            return SW_WRONG_DATA;
        }
        return SW_NO_ERROR;

    // 0102 - Private Use DO 2
    case 0x0102:
        if (in_received > PRIVATE_DO_MAX_LENGTH) {
            return SW_WRONG_LENGTH;
        }
        //JCSystem.beginTransaction();
        memcpy(private_use_do_2, buffer, in_received);
        private_use_do_2_length = in_received;
        //JCSystem.commitTransaction();
        return SW_NO_ERROR;

    // 0104 - Private Use DO 4
    case 0x0104:
        if (in_received > PRIVATE_DO_MAX_LENGTH) {
            return SW_WRONG_LENGTH;
        }
        //JCSystem.beginTransaction();
        memcpy(private_use_do_4, buffer, in_received);
        private_use_do_4_length = in_received;
        //JCSystem.commitTransaction();
        return SW_NO_ERROR;

    default:
        return SW_RECORD_NOT_FOUND;
    }
}

/**
 * Send next block of data in buffer. Used for sending data in <buffer>
 * 
 * @param apdu
 * @param status Status to send
 */
uint16_t sendNext(apdu_t apdu, uint16_t status, outData* output) {
    uint8_t* bufOffset;

    // Determine maximum size of the messages
    uint16_t max_length;
    max_length = RESPONSE_MAX_LENGTH;
    
    if (max_length > out_left) {
        max_length = out_left;
    }

    bufOffset = buffer + out_sent;
    memcpy(output->data, bufOffset, max_length);

    uint16_t statusNew = status;
    if (out_left > max_length) {
        output->length = max_length;
        
        // Compute byte left and sent
        out_left -= max_length;
        out_sent += max_length;
        
        // Determine new status word
        if (out_left > max_length) {
            statusNew = (uint16_t) (SW_BYTES_REMAINING_00 | max_length);
        } else {
            statusNew = (uint16_t) (SW_BYTES_REMAINING_00 | out_left);
        }
    } else {
        output->length = out_left;

        // Reset buffer
        out_sent = 0;
        out_left = 0;
    }

    output->data[max_length] = (uint8_t) (statusNew >> 8);
    output->data[max_length+1] = (uint8_t) (statusNew & 0xFF);
    output->length += 2;
    return statusNew;
}

/**
 * Send len bytes from buffer. If len is greater than RESPONSE_MAX_LENGTH,
 * remaining data can be retrieved using GET RESPONSE.
 * 
 * @param apdu
 * @param len
 *            The byte length of the data to send
 */
void sendBuffer(apdu_t apdu, uint16_t len, outData* output) {
    out_sent = 0;
    out_left = len;
    sendNext(apdu, SW_NO_ERROR, output);
}

uint8_t initialize() {
    static const char* TAG = "initialize";
    bzero(buffer, sizeof(buffer));
    bzero(pw1_modes, sizeof(pw1_modes));

    pw1.limit = PIN_LIMIT;
    pw1.remaining = pw1.limit;
    pw1.validated = (uint8_t) 0;
    if (updatePIN(&pw1, PW1_DEFAULT, 0, (uint8_t) sizeof(PW1_DEFAULT)/sizeof(PW1_DEFAULT[0])) != 0) {
        ESP_LOGE(TAG, "Error updating pw1");
        return 1;
    }
    pw1_length = (uint8_t) sizeof(PW1_DEFAULT)/sizeof(PW1_DEFAULT[0]);
    pw1_status = 0x00;

    rc.limit = PIN_LIMIT;
    rc.remaining = rc.limit;
    rc.validated = (uint8_t) 0;
    rc_length = 0;

    pw3.limit = PIN_LIMIT;
    pw3.remaining = pw3.limit;
    pw3.validated = (uint8_t) 0;
    if (updatePIN(&pw3, PW3_DEFAULT, 0, (uint8_t) sizeof(PW3_DEFAULT)/sizeof(PW3_DEFAULT[0])) != 0) {
        ESP_LOGE(TAG, "Error updating pw3");
        return 1;
    }
    pw3_length = (uint8_t) sizeof(PW3_DEFAULT)/sizeof(PW3_DEFAULT[0]);

    mbedtls_rsa_init(&sigKey, MBEDTLS_RSA_PKCS_V15, 0);
    isSigEmpty = 1;
    sigAttributes[1] = (uint8_t) (KEY_SIZE >> 8);
    sigAttributes[2] = (uint8_t) (KEY_SIZE & 0x00FF);
    sigAttributes[3] = (uint8_t) (EXPONENT_SIZE >> 8);
    sigAttributes[4] = (uint8_t) (EXPONENT_SIZE & 0x00FF);
    bzero(sigFP, sizeof(sigFP));

    mbedtls_rsa_init(&decKey, MBEDTLS_RSA_PKCS_V15, 0);
    isDecEmpty = 1;
    decAttributes[1] = (uint8_t) (KEY_SIZE >> 8);
    decAttributes[2] = (uint8_t) (KEY_SIZE & 0x00FF);
    decAttributes[3] = (uint8_t) (EXPONENT_SIZE >> 8);
    decAttributes[4] = (uint8_t) (EXPONENT_SIZE & 0x00FF);
    bzero(decFP, sizeof(decFP));

    mbedtls_rsa_init(&authKey, MBEDTLS_RSA_PKCS_V15, 0);
    isAuthEmpty = 1;
    authAttributes[1] = (uint8_t) (KEY_SIZE >> 8);
    authAttributes[2] = (uint8_t) (KEY_SIZE & 0x00FF);
    authAttributes[3] = (uint8_t) (EXPONENT_SIZE >> 8);
    authAttributes[4] = (uint8_t) (EXPONENT_SIZE & 0x00FF);
    bzero(authFP, sizeof(authFP));

    bzero(loginData, sizeof(loginData));
    loginData_length = 0;
    bzero(url, sizeof(loginData));
    url_length = 0;
    bzero(name, sizeof(loginData));
    name_length = 0;
    bzero(lang, sizeof(lang));
    lang_length = 0;
    bzero(cert, sizeof(cert));
    cert_length = 0;
    sex = 0x39;

    bzero(private_use_do_1, sizeof(private_use_do_1));
    private_use_do_1_length = 0;
    bzero(private_use_do_2, sizeof(private_use_do_2));
    private_use_do_2_length = 0;
    bzero(private_use_do_3, sizeof(private_use_do_3));
    private_use_do_3_length = 0;
    bzero(private_use_do_4, sizeof(private_use_do_4));
    private_use_do_4_length = 0;

    return 0;
}

// NOT OK
void process(apdu_t apdu, outData* output) {
    static const char* TAG = "process";
    uint16_t status = SW_NO_ERROR;
    uint16_t len = 0;
    uint8_t ret;

    if (apdu.INS == 0xA4) {
            // Reset PW1 modes
            pw1_modes[PW1_MODE_NO81] = 0;
            pw1_modes[PW1_MODE_NO82] = 0;

            return;
    }

    // Support for command chaining
    if ((status = commandChaining(apdu)) != 0x9000){
        goto exit;
    }

    // Reset buffer for GET RESPONSE
    if (apdu.INS != (uint8_t) 0xC0) {
        out_sent = 0;
        out_left = 0;
    }

    if (terminated == 1 && apdu.INS != 0x44) {
        ESP_LOGE(TAG, "SW_CONDITIONS_NOT_SATISFIED, terminated == 1");
        status = SW_CONDITIONS_NOT_SATISFIED;
        goto exit;
    }

    switch(apdu.INS) {
        // GET RESPONSE
        case (uint8_t) 0xC0:
            // Will be handled at the exit
            break;

        // VERIFY
        case (uint8_t) 0x20:
            status = verify(apdu.P2);
            break;

        // CHANGE REFERENCE DATA
        case (uint8_t) 0x24:
            status = changeReferenceData(apdu.P2);
            break;

        // RESET RETRY COUNTER
        case (uint8_t) 0x2C:
            // Reset only available for PW1
            if (apdu.P2 != (uint8_t) 0x81) {
                ESP_LOGE(TAG, "SW_INCORRECT_P1P2");
                status = SW_INCORRECT_P1P2;
                goto exit;
            }

            status = resetRetryCounter(apdu.P1);
            break;

        // PERFORM SECURITY OPERATION
        case (uint8_t) 0x2A:
            // COMPUTE DIGITAL SIGNATURE
            if (apdu.P1P2 == (uint16_t) 0x9E9A) {
                status = computeDigitalSignature(&len);
            }
            // DECIPHER
            else if (apdu.P1P2 == (uint16_t) 0x8086) {
                status = decipher(&apdu.Le);
            } else {
                ESP_LOGE(TAG, "SW_WRONG_P1P2");
                status = SW_WRONG_P1P2;
                goto exit;
            }
            break;

        // INTERNAL AUTHENTICATE
        case (uint8_t) 0x88:
            status = internalAuthenticate(&len);
            break;

        // GENERATE ASYMMETRIC KEY PAIR
        case (uint8_t) 0x47:
            if ((ret = genAsymKey(apdu.P1)) != 0) {
                apdu.Le = ret;
            }
            break;

        // GET CHALLENGE
        case (uint8_t) 0x84:
            status = getChallenge(apdu.Lc, &len);
            break;

        // GET DATA
        case (uint8_t) 0xCA:
            status = getData(apdu.P1P2, &len);
            break;

        // PUT DATA
        case (uint8_t) 0xDA:
            /*
            putData(p1p2);
            */
            break;

        // DB - PUT DATA (Odd)
        case (uint8_t) 0xDB:
            // Odd PUT DATA only supported for importing keys
            // 4D - Extended Header list
            /*
            if (p1p2 == (short) 0x3FFF) {
                importKey(apdu);
            } else {
                ESP_LOGE(TAG, "SW_RECORD_NOT_FOUND");
            }
            break;
            */

        // E6 - TERMINATE DF
        case (uint8_t) 0xE6:
            /*
            if (pw1.getTriesRemaining() == 0 && pw3.getTriesRemaining() == 0) {
                terminated = true;
            } else {
                ESP_LOGE(TAG, "SW_CONDITIONS_NOT_SATISFIED");
            }
            */
            break;

        // 44 - ACTIVATE FILE
        case (uint8_t) 0x44:
            /*
            if (terminated == true) {
                initialize();
                terminated = false;
                JCSystem.requestObjectDeletion();
            } else {
                ESP_LOGE(TAG, "SW_CONDITIONS_NOT_SATISFIED");
            }
            */
            break;

        // GET VERSION (vendor specific)
        case (uint8_t) 0xF1:
            /*
            le = Util.arrayCopy(VERSION, _0, buffer, _0, (short) VERSION.length);
            */
            break;

        // SET RETRIES (vendor specific)
        case (uint8_t) 0xF2:
            /*
            if (lc != 3) {
                ESP_LOGE(TAG, "SW_WRONG_DATA");
            }
            short offs = ISO7816.OFFSET_CDATA;
            setPinRetries(buf[offs++], buf[offs++], buf[offs++]);
            */
            break;

        default :
            ESP_LOGE(TAG, "Failed to process APDU");
    }
exit:
    if (status != (uint16_t) 0x9000) {
        // Send the exception that was thrown 
        //sendError(apdu, ret);
        //sendException(apdu, status);
    } else {
        // GET RESPONSE
        if (apdu.INS == (uint8_t) 0xC0) {
            //sendNext(apdu, SW_NO_ERROR, &output);
        } else {
            sendBuffer(apdu, len, output);  // TODO: Check return value
        }
    }
}

#endif
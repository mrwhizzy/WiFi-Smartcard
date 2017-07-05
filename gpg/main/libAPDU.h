/* 
 *
 * Contains functions and more
 * C implementation of OpenPGPApplet.java
 *
 */

#ifndef __LIBAPDU_H__
#define __LIBAPDU_H__

//import javacard.framework.*;  ha
//import javacard.security.*;   HA
//import javacardx.crypto.*;    HA!

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

// returned by vendor specific command f1
static const uint8_t VERSION[3] = { 0x01, 0x00, 0x12 };

// Openpgp defines 6983 as AUTHENTICATION BLOCKED
#define SW_AUTHENTICATION_BLOCKED 0x6983

/*  0xF8, // Support for GET CHALLENGE
                 // Support for Key Import
                 // PW1 Status byte changeable
                 // Support for private use data objects
    0x00, // Secure messaging using 3DES
    0x00, 0xFF, // Maximum length of challenges
    0x04, 0xC0, // Maximum length Cardholder Certificate
    0x00, 0xFF, // Maximum length command data
    0x00, 0xFF  // Maximum length response data             */
static const uint8_t EXTENDED_CAP[10] = { (uint8_t) 0xF8, 0x00, \
                    0x00, (uint8_t) 0xFF, 0x04, (uint8_t) 0xC0, \
                    0x00, (uint8_t) 0xFF, 0x00, (uint8_t) 0xFF };

#define RESPONSE_MAX_LENGTH 255
#define RESPONSE_SM_MAX_LENGTH 231
#define CHALLENGES_MAX_LENGTH 255

#define BUFFER_MAX_LENGTH 1221

#define LOGINDATA_MAX_LENGTH 254
#define URL_MAX_LENGTH 254
#define NAME_MAX_LENGTH 39
#define LANG_MAX_LENGTH 8
#define CERT_MAX_LENGTH 1216
#define PRIVATE_DO_MAX_LENGTH 254

#define FP_LENGTH 20

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

#define SW_REFERENCED_DATA_NOT_FOUND 0x6A88

#define KEY_SIZE 2048
#define KEY_SIZE_BYTES 256
#define EXPONENT_SIZE_BYTES 3
#define EXPONENT 65537

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
    char data[256];     // maybe 128 is enough
} apdu_t;

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
            strncpy(newAPDU.data, (recvBuf+5), strlen(recvBuf-6));
        } else {                // Lc | Data
            strcpy(newAPDU.data, (recvBuf+5));
        }
    }
    return newAPDU;
}

// SHOULD BE FINE
uint8_t updatePIN(ownerPIN* pw, uint8_t* pin, uint16_t offset, uint8_t length) {
    if (length > (sizeof(pw->value)/sizeof(pw->value[0]) + 1)) {
        return 1;
    }
    bzero(pw->value, sizeof(pw->value));
    pw->value[0] = length;
    memcpy(&(pw->value[1]), pin, length);
    pw->validated = (uint8_t) 0;
    return 0;
}

// SHOULD BE FINE
uint8_t initialize() {
    static const char* TAG = "initialize";
    bzero(buffer, sizeof(buffer));
    bzero(pw1_modes, sizeof(pw1_modes));

    pw1.remaining = (uint8_t) 3;
    pw1.validated = (uint8_t) 0;
    if (updatePIN(&pw1, PW1_DEFAULT, _0, (uint8_t) sizeof(PW1_DEFAULT)/sizeof(PW1_DEFAULT[0])) != 0) {
        ESP_LOGE(TAG, "Error updating pw1");
        return 1;
    }
    pw1_length = (uint8_t) sizeof(PW1_DEFAULT)/sizeof(PW1_DEFAULT[0]);
    pw1_status = 0x00;

    rc.remaining = (uint8_t) 3;
    rc.validated = (uint8_t) 0;
    rc_length = 0;

    pw3.remaining = (uint8_t) 3;
    pw3.validated = (uint8_t) 0;
    if (updatePIN(&pw3, PW3_DEFAULT, _0, (uint8_t) sizeof(PW3_DEFAULT)/sizeof(PW3_DEFAULT[0])) != 0) {
        ESP_LOGE(TAG, "Error updating pw3");
        return 1;
    }
    pw3_length = (uint8_t) sizeof(PW3_DEFAULT)/sizeof(PW3_DEFAULT[0]);

    mbedtls_rsa_init(&sigKey, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_rsa_init(&decKey, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_rsa_init(&authKey, MBEDTLS_RSA_PKCS_V15, 0);

    loginData_length = 0;
    url_length = 0;
    name_length = 0;
    lang_length = 0;
    bzero(cert, sizeof(cert));
    cert_length = 0;
    sex = 0x39;

    private_use_do_1_length = 0;
    private_use_do_2_length = 0;
    private_use_do_3_length = 0;
    private_use_do_4_length = 0;
    return 0;
}

// SHOULD BE FINE
void resetChaining() {
    chain = 0;
    in_received = 0;
}

// SHOULD BE FINE
void commandChaining(apdu_t apdu){
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
        }

        // Check whether data to be received is larger than size of the buffer
        if ((uint16_t) (in_received + len) > BUFFER_MAX_LENGTH) {
            resetChaining();
            ESP_LOGE(TAG, "SW_WRONG_DATA");
        }

        // Store received data in buffer
        uint8_t* bufOffset = buffer;// + in_received;
        memcpy(bufOffset, apdu.data, len);
        in_received += len;

        chain = 1;
        chain_ins = apdu.INS;
        chain_p1p2 = apdu.P1P2;
        ESP_LOGE(TAG, "SW_NO_ERROR");
    }

    if ((chain == 1) && (apdu.INS == chain_ins) && (apdu.P1P2 == chain_p1p2)) {
        chain = 0;

        // Check whether data to be received is larger than size of the buffer
        if ((uint16_t) (in_received + len) > BUFFER_MAX_LENGTH) {
            resetChaining();
            ESP_LOGE(TAG, "SW_WRONG_DATA");
        }

        // Add received data to the buffer
        uint8_t* bufOffset = buffer;// + in_received;
        memcpy(bufOffset, apdu.data, len);
        in_received += len;
    } else if (chain == 1) {
        // Chained command expected
        resetChaining();
        ESP_LOGE(TAG, "SW_UNKNOWN");
    } else {
        // No chaining was used, so copy data to buffer
        memcpy(buffer, apdu.data, len);
        in_received = len;
    }
}


/**
 * Increase the digital signature counter by one. In case of overflow
 * SW_WARNING_STATE_UNCHANGED will be thrown and nothing will
 * change.
 */
// SHOULD BE FINE
void increaseDSCounter() {
    static const char* TAG = "increaseDSCounter";
    for (short int i = (short int) ((sizeof(ds_counter)/sizeof(ds_counter[0])) - 1); i >= 0; i--) {
        if ((uint16_t) (ds_counter[i] & 0xFF) >= 0xFF) {
            if (i == 0) {
                // Overflow
                ESP_LOGE(TAG, "SW_WARNING_STATE_UNCHANGED");
            } else {
                ds_counter[i] = 0;
            }
        } else {
            ds_counter[i]++;
            break;
        }
    }
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
 * @param apdu
 * @return Length of data written in buffer
 */
/* NOT OK
uint16_t computeDigitalSignature(apdu_t apdu) {
    static const char* TAG = "computeDigitalSignature";
    if (! ((pw1.validated == 1) && (pw1_modes[PW1_MODE_NO81] == 1)))
        ESP_LOGE(TAG, "SW_SECURITY_STATUS_NOT_SATISFIED");

    if (pw1_status == (uint8_t) 0x00)
        pw1_modes[PW1_MODE_NO81] = 0;

    if (!sig_key.getPrivate().isInitialized())
        ESP_LOGE(TAG, "SW_REFERENCED_DATA_NOT_FOUND");

    cipher.init(sig_key.getPrivate(), Cipher.MODE_ENCRYPT);
    increaseDSCounter();

    short length = cipher.doFinal(buffer, _0, in_received, buffer, in_received);
    Util.arrayCopyNonAtomic(buffer, in_received, buffer, _0, length);
    return length;
}
*/


/**
 * Output the public key of the given key pair.
 * 
 * @param apdu
 * @param key
 *            Key pair containing public key to be output
 */
// SHOULD BE FINE
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
        buffer[offset++] = (uint8_t) ((KEY_SIZE_BYTES & 0xFF00) << 8);
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

    buffer[offsetForLength] = (uint8_t) (((offset - offsetForLength - 2) & 0xFF00) << 8);
    buffer[offsetForLength+1] = (uint8_t) ((offset - offsetForLength - 2) & 0x00FF);

    return offset;
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
// SHOULD BE FINE
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
// SHOULD BE FINE
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

// Function just to read and print the keys from the flash storage
uint16_t readKeys(uint8_t type) {
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
        ESP_LOGE(TAG, "SW_UNKNOWN");    
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

// NOT OK
void process(apdu_t apdu) {
    static const char* TAG = "process";
    uint16_t ret;
    
    /*if (apdu.INS == 0xA4) {
            // Reset PW1 modes
            pw1_modes[PW1_MODE_NO81] = 0;
            pw1_modes[PW1_MODE_NO82] = 0;

            return;
    }*/
    
    uint16_t status = 0x9000;           // No error
    apdu.Le = 0;

    // Support for command chaining
    commandChaining(apdu);

    
    // Reset buffer for GET RESPONSE
    if (apdu.INS != (uint8_t) 0xC0) {
        out_sent = 0;
        out_left = 0;
    }

    if (terminated == 1 && apdu.INS != 0x44) {
        ESP_LOGE(TAG, "SW_CONDITIONS_NOT_SATISFIED");
    }

    switch(apdu.INS) {
        // GET RESPONSE
        case (uint8_t) 0xC0:
            // Will be handled in finally clause
            break;

        // VERIFY
        case (uint8_t) 0x20:
            /*
            verify(apdu, p2);
            */
            break;

        // CHANGE REFERENCE DATA
        case (uint8_t) 0x24:
            /*
            changeReferenceData(apdu, p2);
            */
            break;

        // RESET RETRY COUNTER
        case (uint8_t) 0x2C:
            /*
            // Reset only available for PW1
            if (p2 != (byte) 0x81)
                ESP_LOGE(TAG, "SW_INCORRECT_P1P2");

            resetRetryCounter(apdu, p1);
            */
            break;

        // PERFORM SECURITY OPERATION
        case (uint8_t) 0x2A:
            // The following lines are for testing ONLY
            ESP_LOGI(TAG, "%04X\n", apdu.P1P2);
            pw3.validated = 1;
            buffer[0] = 0xB6;
            ret = genAsymKey((uint8_t) 0x80);
            printf("GEN RETURNED: %d\n", ret);
            ret = readKeys((uint8_t) 0xB6);
            printf("READ RETURNED: %d\n", ret);
            // End of testing


            /*

            */

            /*
            // COMPUTE DIGITAL SIGNATURE
            if (p1p2 == (short) 0x9E9A) {
                le = computeDigitalSignature(apdu);
            }
            // DECIPHER
            else if (p1p2 == (short) 0x8086) {
                le = decipher(apdu);
            } else {
                ESP_LOGE(TAG, "SW_WRONG_P1P2");
            }
            */
            break;

        // INTERNAL AUTHENTICATE
        case (uint8_t) 0x88:
            /*
            le = internalAuthenticate(apdu);
            break;
            */

        // GENERATE ASYMMETRIC KEY PAIR
        case (uint8_t) 0x47:
            if ((ret = genAsymKey(apdu.P1)) != 0) {
                apdu.Le = ret;
            }
            break;

        // GET CHALLENGE
        case (uint8_t) 0x84:
            /*
            le = getChallenge(apdu, lc);
            */
            break;

        // GET DATA
        case (uint8_t) 0xCA:
            /*
            le = getData(p1p2);
            */
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
    if (status != (uint16_t) 0x9000) {
        // Send the exception that was thrown 
        //sendException(apdu, status);
    } else {
        // GET RESPONSE
        if (apdu.INS == (uint8_t) 0xC0) {
            //sendNext(apdu);
        } else {
            //sendBuffer(apdu, le);
        }
    }
}

#endif
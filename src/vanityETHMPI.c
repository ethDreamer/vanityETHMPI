#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include "sph_keccak.h"
#include "cmdline/vanityETHCmdline.h"
#ifdef USE_MPI
#include <mpi.h>
#endif

#define EC_CURVE_NAME       NID_secp256k1
#define PRIVATE_KEY_SIZE    32
#define PUBLIC_KEY_SIZE     65
#define ADDRESS_SIZE        20
#define PRIVATE_KEY_TAG     103277
#define PUBLIC_KEY_TAG      280323
#define DIE_TAG             666

typedef unsigned char uchar;
typedef unsigned int uint;

void keccak256(uchar *data, size_t length, uchar *hash) {
    /* calculate address hash */
    sph_keccak256_context cc;
    sph_keccak256_init(&cc);
    sph_keccak256((void *)&cc, (const void *)data, length);
    sph_keccak256_close((void *)&cc, (void *)hash);
}

void char2hex(uchar *in, char *hex, uint size) {
    uint i;
    for (i = 0; i < size; i++) {
        sprintf(hex, "%02x", *in);
        in++; hex += 2;
    }
    hex[0] = '\0';
}
void getPubHex(uchar *pub, char *hex) {
    char2hex(pub, hex, PUBLIC_KEY_SIZE);
}
void getPrivHex(uchar *priv, char *hex) {
    char2hex(priv, hex, PRIVATE_KEY_SIZE);
}
void getAddrHex(uchar *addr, char *hex) {
    char2hex(addr, hex, ADDRESS_SIZE);
}

void getAddressFromPubkey(uchar *publicKey, uchar *address) {
    unsigned char hash[32]; int i;
    // drop the first byte
    keccak256(&publicKey[1], PUBLIC_KEY_SIZE - 1, hash);
    for (i = 0; i < ADDRESS_SIZE; i++)
        address[i] = hash[i+12];
}

void error(const char *message) {
    printf("%s\n", message);
    exit(1);
}

void genKeyPair(uchar *privateKey, uchar *publicKey) {
    EC_KEY* pKey;
    /* generate new curve */
    pKey = EC_KEY_new_by_curve_name(EC_CURVE_NAME);
    if (!pKey)
        error("genPrivateKey(): EC_KEY_new_by_curve_name failed");
    if (!EC_KEY_generate_key(pKey))
        error("genPrivateKey(): EC_KEY_generate_key failed");
    /* generate new private key */
    const BIGNUM *bn = EC_KEY_get0_private_key(pKey);
    if (!bn)
        error("genPrivateKey(): EC_KEY_get0_private_key failed");
    int nBytes = BN_num_bytes(bn);
    /* copy private key to buffer */
    int n = BN_bn2bin(bn, &privateKey[PRIVATE_KEY_SIZE - nBytes]);
    if (n != nBytes)
        error("genPrivateKey(): BN_bn2bin failed");
    /* calculate uncompresseed public key */
    EC_KEY_set_conv_form(pKey, POINT_CONVERSION_UNCOMPRESSED); 
    int nSize = i2o_ECPublicKey(pKey, NULL);
    if (nSize == 0)
        error("getPublicKey() : i2o_ECPublicKey failed");
    /* copy pubic key to buffer */
    if (i2o_ECPublicKey(pKey, &publicKey) != nSize)
        error("getPublicKey() : i2o_ECPublicKey returned unexpected size");
    EC_KEY_free(pKey); 
}

void getFirstContractAddress(uchar *address, uchar *contract) {
    uchar RLP[ADDRESS_SIZE + 3]; uchar hash[32]; uint i;

    RLP[0] = 0xd6; RLP[1] = 0x94;
    for (i = 0; i < ADDRESS_SIZE; i++)
        RLP[i+2] = address[i];
    RLP[ADDRESS_SIZE + 2] = 0x80;

    keccak256(RLP, ADDRESS_SIZE+3, hash);
    for (i = 0; i < 20; i++)
        contract[i] = hash[i+12];
}

int checkMatch(uchar *address, char *compare) {
    if (compare[0] == '0' && compare[1] == 'x')
        compare += 2;

    char byte[3];
    uint size = strlen(compare);
    uint i = 0; int match = 1;
    while (match && 2*i < size) {
        sprintf(byte, "%02x", address[i]);
        match = (match && (compare[2*i] == byte[0]));
        if (match && (2*i+1 < size))
            match = (match && (compare[2*i+1] == byte[1]));
        i++;
    }
    return match;
}

void printAll(uchar *privateKey, uchar *publicKey, uchar *address, uchar *contract) {
    char privHex[2*PRIVATE_KEY_SIZE+1];
    char pubHex[2*PUBLIC_KEY_SIZE+1];
    char addrHex[2*ADDRESS_SIZE+1];
    char contHex[2*ADDRESS_SIZE+1];
    getPrivHex(privateKey, privHex);
    getPubHex(publicKey, pubHex);
    getAddrHex(address, addrHex);
    getAddrHex(contract, contHex);

    printf("Private Key:             0x%s\n", privHex);
//    printf("Uncompressed Public Key: 0x%s\n", pubHex);
    printf("Address:                 0x%s\n", addrHex);
    printf("First Contract:          0x%s\n", contHex);
    printf("\n");
}

void master(struct gengetopt_args_info args) {
    uchar privateKey[PRIVATE_KEY_SIZE+1]; privateKey[PRIVATE_KEY_SIZE] = '\0';
    uchar publicKey[PUBLIC_KEY_SIZE+1];   publicKey[PUBLIC_KEY_SIZE]   = '\0';
    uchar address[ADDRESS_SIZE+1];        address[ADDRESS_SIZE]        = '\0';
    uchar contract[ADDRESS_SIZE+1];       contract[ADDRESS_SIZE]       = '\0';

#ifdef USE_MPI
    int rank; int size;
    uchar recvPrivateKey[PRIVATE_KEY_SIZE+1]; recvPrivateKey[PRIVATE_KEY_SIZE] = '\0';
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    MPI_Request recvRequest; MPI_Status recvStatus;
    MPI_Irecv((void *)recvPrivateKey, PRIVATE_KEY_SIZE, MPI_UNSIGNED_CHAR, MPI_ANY_SOURCE,
        PRIVATE_KEY_TAG, MPI_COMM_WORLD, &recvRequest);
#endif

    uint nfound = 0; int found = 0;
    // collect the results
    while (nfound < args.count_arg) {
#ifdef USE_MPI
        if (recvResult(&recvRequest, &recvStatus)) {
            MPI_Recv((void *)publicKey, PUBLIC_KEY_SIZE, MPI_UNSIGNED_CHAR, recvStatus.MPI_SOURCE, PUBLIC_KEY_TAG,
                MPI_COMM_WORLD, &recvStatus);
            memcpy((void *)privateKey, (void *)recvPrivateKey, sizeof(privateKey));
            MPI_Irecv((void *)recvPrivateKey, PRIVATE_KEY_SIZE, MPI_UNSIGNED_CHAR, MPI_ANY_SOURCE,
                PRIVATE_KEY_TAG, MPI_COMM_WORLD, &recvRequest);
        }
        else
#endif
            genKeyPair(privateKey, publicKey);

        getAddressFromPubkey(publicKey, address);
        getFirstContractAddress(address, contract);
        found = checkMatch(((args.contract_flag) ? contract : address), args.input_arg);
        if (found) {
            printf("Key %i\n", (nfound+1));
            printAll(privateKey, publicKey, address, contract);
            nfound++;
        }
    }
#ifdef USE_MPI
    // send stop to everyone
    MPI_Request stopRequest; int buf[1]; uint i;
    for (i = 0; i < size; i++)
        MPI_Isend((const void *)buf, 0, MPI_INT, i, DIE_TAG, MPI_COMM_WORLD, &stopRequest);
#endif
}
#ifdef USE_MPI
int recvResult(MPI_Request *request, MPI_Status *status) {
    int flag = 0;
    MPI_Test(request, &flag, status);
    return flag;
}

void sendResult(uchar *privateKey, uchar *publicKey) {
    MPI_Request privRequest; MPI_Request pubRequest;
    MPI_Ibsend((const void *)privateKey, PRIVATE_KEY_SIZE, MPI_UNSIGNED_CHAR, 0, PRIVATE_KEY_TAG,
              MPI_COMM_WORLD, &privRequest);
    MPI_Ibsend((const void *)publicKey, PUBLIC_KEY_SIZE, MPI_UNSIGNED_CHAR, 0, PUBLIC_KEY_TAG,
              MPI_COMM_WORLD, &pubRequest);
}

int checkStop(MPI_Request *stopRequest) {
    int flag = 0; MPI_Status status;
    MPI_Test(stopRequest, &flag, &status);
    return flag;
}

void slave(struct gengetopt_args_info args) {
    uchar privateKey[PRIVATE_KEY_SIZE+1]; privateKey[PRIVATE_KEY_SIZE] = '\0';
    uchar publicKey[PUBLIC_KEY_SIZE+1]; publicKey[PUBLIC_KEY_SIZE] = '\0';
    uchar address[ADDRESS_SIZE+1]; address[ADDRESS_SIZE] = '\0';
    uchar contract[ADDRESS_SIZE+1]; contract[ADDRESS_SIZE] = '\0';

    MPI_Request stopRequest; int buf[1];
    MPI_Irecv((void *)buf, 0, MPI_INT, 0, DIE_TAG, MPI_COMM_WORLD, &stopRequest);

    int found = 0; int stop = 0;
    while (!stop) {
        genKeyPair(privateKey, publicKey);
        getAddressFromPubkey(publicKey, address);
        if (args.contract_flag)
            getFirstContractAddress(address, contract);
        found = checkMatch(((args.contract_flag) ? contract : address), args.input_arg);
        if (found)
            sendResult(privateKey, publicKey);
        stop = checkStop(&stopRequest);
    }
}
#endif

int main(int argc, char *argv[]) {
    int rank = 0;
#ifdef USE_MPI
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
#endif

    struct gengetopt_args_info args;
    if (cmdline_parser(argc, argv, &args) != 0)
        exit(1);

    if (rank == 0)
        master(args);
#ifdef USE_MPI
    else
        slave(args);
    MPI_Finalize();
#endif
    return 0;
}


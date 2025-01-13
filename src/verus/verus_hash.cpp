/**
* Verushash solver interface for ccminer (compatible with linux and windows)
* Solver taken from nheqminer, by djeZo (and NiceHash)
* tpruvot - 2017 (GPL v3)
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdexcept>
#include <array>
#include <vector>

#include "verus_clhash.h"
#include "../uint256.h"
#include "../main.h"
#include "../constants.h"

constexpr int VERUS_KEY_SIZE = 8832;
constexpr int VERUS_KEY_SIZE128 = 552;

enum
{
	// primary actions
	SER_NETWORK = (1 << 0),
	SER_DISK = (1 << 1),
	SER_GETHASH = (1 << 2),
};


// Change from direct definition to using the constant from constants.h
#include "../constants.h"
// constexpr int EQNONCE_OFFSET = 30;
constexpr int NONCE_OFT = EQNONCE_OFFSET;

static bool init[MAX_GPUS] = { 0 };
static __thread uint32_t throughput = 0;

#ifndef htobe32
#define htobe32(x) swab32(x)
#endif

// cleanup
void free_verushash(int thr_id) {
	if (!init[thr_id]) { return; }
	init[thr_id] = false;
}

/**
 * GenNewCLKey function.
 * 
 * This function generates a new key by chain hashing with Haraka256 from the last curbuf.
 * 
 * @param seedBytes32  The seed bytes for the key generation.
 * @param keyback      The key buffer to store the generated key.
 */
extern "C" inline void GenNewCLKey(
    unsigned char *seedBytes32, 
    u128 *keyback
) {
    // Calculate the number of 256-bit blocks in the key
    int n256blks = VERUS_KEY_SIZE >> 5;

    // Calculate the number of extra bytes in the key
    int nbytesExtra = VERUS_KEY_SIZE & 0x1f;

    // Initialize the key and source pointers
    unsigned char *pkey = (unsigned char*)keyback;
    unsigned char *psrc = seedBytes32;

    // Generate the key by chain hashing with Haraka256
    for (int i = 0; i < n256blks; i++) {
        // Hash the current block
        haraka256(pkey, psrc);

        // Update the source and key pointers
        psrc = pkey;
        pkey += 32;
    }

    // Handle any extra bytes in the key
    if (nbytesExtra) {
        // Hash the last block
        unsigned char buf[32];
        haraka256(buf, psrc);

        // Copy the extra bytes to the key buffer
        memcpy(pkey, buf, nbytesExtra);
    }
}

/**
 * FixKey function.
 * 
 * This function fixes the key by replacing certain elements with values from the g_prand and g_prandex arrays.
 * 
 * @param fixrand      The fixrand array.
 * @param fixrandex    The fixrandex array.
 * @param keyback      The key buffer to fix.
 * @param g_prand      The g_prand array.
 * @param g_prandex    The g_prandex array.
 */
extern "C" inline void FixKey(
    uint32_t *fixrand, 
    uint32_t *fixrandex, 
    u128 *keyback, 
    u128 *g_prand, 
    u128 *g_prandex
) {
    // Fix the key by replacing certain elements
    for (int i = 31; i > -1; i--) {
        // Replace the element at the fixrandex index with the value from g_prandex
        keyback[fixrandex[i]] = g_prandex[i];

        // Replace the element at the fixrand index with the value from g_prand
        keyback[fixrand[i]] = g_prand[i];
    }
}


/**
 * VerusHashIntermediate function.
 * 
 * This function generates an intermediate hash using the Verus algorithm.
 * 
 * @param result2      The output hash buffer.
 * @param data         The input data buffer.
 * @param len          The length of the input data.
 */
extern "C" inline void VerusHashIntermediate(
    void *result2, 
    unsigned char *data, 
    int len
) {
    // Define aligned buffers for hash calculation
    alignas(32) unsigned char buf1[64] = { 0 }, buf2[64];

    // Initialize buffer pointers and position
    unsigned char *curBuf = buf1, *result = buf2;
    int curPos = 0;

    // Load constants for hash calculation
    load_constants();

    // Digest input data in chunks of up to 32 bytes
    for (int pos = 0; pos < len; ) {
        // Calculate the available space in the current buffer
        int room = 32 - curPos;

        // Check if there's enough data to fill the current buffer
        if (len - pos >= room) {
            // Copy data into the current buffer and calculate the hash
            memcpy(curBuf + 32 + curPos, data + pos, room);
            haraka512(result, curBuf);

            // Swap the current buffer and result buffer
            unsigned char *tmp = curBuf;
            curBuf = result;
            result = tmp;

            // Update the position and reset the current buffer position
            pos += room;
            curPos = 0;
        } else {
            // Copy the remaining data into the current buffer
            memcpy(curBuf + 32 + curPos, data + pos, len - pos);
            curPos += len - pos;
            pos = len;
        }
    }

    // Finalize the hash calculation
    memcpy(curBuf + 47, curBuf, 16);
    memcpy(curBuf + 63, curBuf, 1);
    //	FillExtra((u128 *)curBuf);

    // Copy the final hash result to the output buffer
    memcpy(result2, curBuf, 64);
}
/**
 * Verus2hash function.
 * 
 * This function generates a hash using the Verus2 algorithm.
 * 
 * @param hash         The output hash buffer.
 * @param curBuf       The current buffer to process.
 * @param nonce        The nonce value.
 * @param data_key     The data key.
 * @param gpu_init     The GPU initialization value.
 * @param fixrand      The fixed random value.
 * @param fixrandex    The fixed random exponent value.
 * @param g_prand      The global pseudo-random value.
 * @param g_prandex    The global pseudo-random exponent value.
 * @param version      The version number.
 */
extern "C" inline void Verus2hash(
    unsigned char *hash, 
    unsigned char *curBuf, 
    unsigned char *nonce,
    u128  * __restrict data_key, 
    uint8_t *gpu_init, 
    uint32_t *fixrand, 
    uint32_t *fixrandex, 
    u128 *g_prand, 
    u128 *g_prandex, 
    int version
) {
    // Define shuffle masks for byte shuffling
    static const __m128i shuf1 = _mm_setr_epi8(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0);
    static const __m128i shuf2 = _mm_setr_epi8(1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0);

    // Load and shuffle the current buffer
    const __m128i fill1 = _mm_shuffle_epi8(_mm_load_si128((u128 *)curBuf), shuf1);
    _mm_store_si128((u128 *)(&curBuf[32 + 16]), fill1);

    // Store the first byte of the current buffer
    unsigned char ch = curBuf[0];
    curBuf[32 + 15] = ch;

    // Copy the nonce value into the current buffer
    memcpy(curBuf + 32, nonce, 15);

    // Calculate the intermediate hash value
    uint64_t intermediate = verusclhashv2_2(
        data_key, 
        curBuf, 
        511, 
        fixrand, 
        fixrandex, 
        g_prand, 
        g_prandex
    );

    // Shuffle the intermediate hash value
    __m128i fill2 = _mm_shuffle_epi8(_mm_loadl_epi64((u128 *)&intermediate), shuf2);
    _mm_store_si128((u128 *)(&curBuf[32 + 16]), fill2);

    // Store the last byte of the intermediate hash value
    curBuf[32 + 15] = *((unsigned char *)&intermediate);

    // Mask the intermediate hash value
    intermediate &= 511;

    // Generate the final hash value
    haraka512_keyed(hash, curBuf, data_key + intermediate);

    // Fix the key
    FixKey(fixrand, fixrandex, data_key, g_prand, g_prandex);
}
/**
 * scan_for_valid_hashes function.
 * 
 * This function scans for valid hashes using the Verus algorithm.
 * 
 * @param thr_id        The thread ID.
 * @param work          The work structure.
 * @param max_nonce     The maximum nonce value.
 * @param hashes_done   The number of hashes done.
 * 
 * @return The number of valid nonces found.
 */
extern "C" int scan_for_valid_hashes(
    int thr_id, 
    struct work *work, 
    uint32_t max_nonce, 
    unsigned long *hashes_done
) {
    // Define the data and target pointers
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;

    // Define the block hash half buffer
    uint8_t blockhash_half[64] = { 0 };

    // Define the GPU initialization value
    uint8_t gpuinit = 0;

    // Define the timing variables
    struct timeval tv_start, tv_end;

    // Define the aligned storage for the data key
    using aligned_u128 = std::aligned_storage<sizeof(u128), alignof(u128)>::type;
    std::array<aligned_u128, VERUS_KEY_SIZE + 1024> data_key;

    // Define the data key pointers
    u128 *data_key_prand = reinterpret_cast<u128*>(data_key.data()) + VERUS_KEY_SIZE128;
    u128 *data_key_prandex = reinterpret_cast<u128*>(data_key.data()) + VERUS_KEY_SIZE128 + 32;

    // Define the nonce buffer
    uint32_t nonce_buf = 0;

    // Define the fixrand and fixrandex arrays
    std::array<uint32_t, 32> fixrand;
    std::array<uint32_t, 32> fixrandex;

    // Define the block 41970 buffer
    unsigned char block_41970[3] = { 0xfd, 0x40, 0x05 };

    // Define the full data buffer
    uint8_t full_data[140 + 3 + 1344] = { 0 };

    // Define the solution data pointer
    uint8_t* sol_data = &full_data[140];

    // Copy the data into the full data buffer
    memcpy(full_data, pdata, 140);
    memcpy(sol_data, block_41970, 3);
    memcpy(sol_data + 3, work->solution, 1344);

    // Define the version and nonce space buffers
    uint8_t version = work->solution[0];
    uint8_t nonceSpace[15] = { 0 };

    // Check if the version is 7 or higher and the solution is non-canonical
    if (version >= 7 && work->solution[5] > 0) {
        // Clear non-canonical data from the header and solution
        memset(full_data + 4, 0, 96);
        memset(full_data + 4 + 32 + 32 + 32 + 4, 0, 4);
        memset(full_data + 4 + 32 + 32 + 32 + 4 + 4, 0, 32);
        memset(sol_data + 3 + 8, 0, 64);

        // Copy the nonce values from the header to the nonce space
        memcpy(nonceSpace, &pdata[EQNONCE_OFFSET - 3], 7);
        memcpy(nonceSpace + 7, &pdata[EQNONCE_OFFSET + 2], 4);
    }

    // Define the vhash buffer
    uint32_t vhash[8] = { 0 };

    // Calculate the block hash half
    VerusHashIntermediate(blockhash_half, (unsigned char*)full_data, 1487);

    // Generate the new CL key
    GenNewCLKey((unsigned char*)blockhash_half, reinterpret_cast<u128*>(data_key.data()));

    // Get the start time
    gettimeofday(&tv_start, NULL);

    // Initialize the throughput
    throughput = 1;

    // Define the hash target
    const uint32_t Htarg = ptarget[7];

    // Loop through the nonce values
    while (nonce_buf < max_nonce && !work_restart[thr_id].restart) {
        // Update the hashes done
        *hashes_done = nonce_buf + throughput;

        // Set the nonce value in the nonce space
        ((uint32_t*)(&nonceSpace[11]))[0] = nonce_buf;

        // Calculate the Verus2 hash
        Verus2hash((unsigned char*)vhash, (unsigned char*)blockhash_half, nonceSpace, reinterpret_cast<u128*>(data_key.data()),
            &gpuinit, fixrand.data(),fixrandex.data(), data_key_prand, data_key_prandex, version);

        // Check if the hash is valid
        if (vhash[7] <= Htarg) {
            // Increment the valid nonces count
            work->valid_nonces++;

            // Copy the data into the work structure
            memcpy(work->data, full_data, 140);

            // Get the nonce index
            int nonce = work->valid_nonces - 1;

            // Copy the solution into the work structure
            memcpy(work->extra, sol_data, 1347);

            // Copy the nonce space into the work structure
            memcpy(work->extra + 1332, nonceSpace, 15);

            // Store the hash target ratio
            bn_store_hash_target_ratio(vhash, work->target, work, nonce);

            // Store the nonce value
            work->nonces[work->valid_nonces - 1] = ((uint32_t*)full_data)[NONCE_OFT];

            // Break out of the loop
            break;
        }

        // Increment the nonce buffer
        nonce_buf += throughput;
    }

    // Get the end time
    gettimeofday(&tv_end, NULL);

    // Increment the nonce value in the data
    pdata[NONCE_OFT] = ((uint32_t*)full_data)[NONCE_OFT] + 1;

    // Free the Verus hash resources
    free_verushash(thr_id);

    // Return the number of valid nonces
    return work->valid_nonces;
}

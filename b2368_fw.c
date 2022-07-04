//
// Copyright (c) 2020-2022 Carlos Pizarro <kr105@kr105.com>
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

#include "sha2.h"

typedef enum { HELP, TEST, EXTRACT, CREATE } runmode;

struct mstc_trailer {
    uint8_t fill[128];
    uint32_t magic;     // 1B 05 CE 17
    uint8_t image_type; // 01
    uint8_t unk1;       // ?
    uint8_t fs_type;    // 01 -> Type: UBIFS=1, SquashFS=2, InitRAMFS(initrd)=3, SquashFS_NO_padding=4
    uint8_t unk2;       // ?
    uint32_t unk3;      // ?
    uint32_t unk4;      // ?
    uint32_t crc32;     // crc32(kern+rootfs)
    uint32_t unk5;      // ?
    uint32_t unk6;      // ?
    uint32_t fs_crc32;  // crc32(rootfs)
    uint32_t fs_len;    // len(rootfs)
    uint8_t sha256[32]; // sha256(sha256(kern+rootfs)+MSTC_SHA256_MIXER)
    uint32_t unk7;      // ?
    uint32_t unk8;      // ?
};

#define MSTC_TRAILER_MAGIC 0x1B05CE17
#define MSTC_TRAILER_SIZE sizeof(struct mstc_trailer)

#define KERNEL_SIZE (4 * 1024 * 1024) // 4MB

/* Copyright (C) 1986 Gary S. Brown.  You may use this program, or
   code or tables extracted from it, as desired without restriction. */

const uint32_t crc_32_tab[] = { /* CRC polynomial 0xedb88320 */
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

#define UPDC32(octet,crc) (crc_32_tab[((crc) ^ (octet)) & 0xff] ^ ((crc) >> 8))

uint32_t crc32buf(uint8_t* buf, size_t len)
{
    uint32_t oldcrc32;

    oldcrc32 = 0xFFFFFFFF;

    for (; len; --len, ++buf)
    {
        oldcrc32 = UPDC32(*buf, oldcrc32);
    }

    return ~oldcrc32;

}

unsigned char* bin_to_strhex(const uint8_t* bin, uint32_t binsz, uint8_t** result)
{
    uint8_t hex_str[] = "0123456789abcdef";
    uint32_t i;

    if (!(*result = (uint8_t*)malloc(binsz * 2 + 1)))
        return (NULL);

    (*result)[binsz * 2] = 0;

    if (!binsz)
        return (NULL);

    for (i = 0; i < binsz; i++)
    {
        (*result)[i * 2 + 0] = hex_str[(bin[i] >> 4) & 0x0F];
        (*result)[i * 2 + 1] = hex_str[(bin[i]) & 0x0F];
    }
    return (*result);
}

void calc_mixed_sha256(uint8_t *buf, uint32_t buflen, uint8_t* digest)
{
    const char apend[] = "MSTC_SHA256_MIXER";

    uint8_t* digeststr = NULL;
    uint8_t digestapnd[SHA256_DIGEST_SIZE * 2 + sizeof(apend)] = { 0 };

    sha256(buf, buflen, digest);

    bin_to_strhex(digest, SHA256_DIGEST_SIZE, &digeststr);

    strcpy((char*)digestapnd, (char*)digeststr);
    strcat((char*)digestapnd, apend);

    sha256(digestapnd, strlen((char*)digestapnd), digest);
}

int checkras(FILE* rasfile, struct mstc_trailer* trailerout)
{
    uint8_t* filebody = NULL;
    uint32_t filesize = 0;
    uint32_t bodysize = 0;
    uint32_t readsize = 0;
    uint32_t crc_test = 0;
    uint8_t sha256_test[SHA256_DIGEST_SIZE] = {0};
    struct mstc_trailer trailer;

    // Get file size
    fseek(rasfile, 0L, SEEK_END);
    filesize = ftell(rasfile);
    rewind(rasfile);

    if (filesize < MSTC_TRAILER_SIZE) {
        printf("File size too small.\n");
        return 0;
    }

    // Move the pointer just before the trailer
    fseek(rasfile, filesize - MSTC_TRAILER_SIZE, SEEK_CUR);

    // Read the trailer
    readsize = fread((void*)&trailer, 1, MSTC_TRAILER_SIZE, rasfile);

    if (readsize != MSTC_TRAILER_SIZE) {
        printf("Failed reading file trailer.\n");
        return 0;
    }

    bodysize = filesize - MSTC_TRAILER_SIZE;

    rewind(rasfile);

    // Read file body
    filebody = (uint8_t*)malloc(bodysize);
    fread(filebody, 1, filesize, rasfile);

    // Pointer must be rewind before return
    rewind(rasfile);

    // Check CRC32
    crc_test = crc32buf(filebody, bodysize);
    if (ntohl(crc_test) != trailer.crc32) {
        printf("Failed CRC32 check of file.\n");
        return 0;
    }

    uint32_t kernelsize = bodysize - trailer.fs_len;

    // Check rootfs CRC32
    crc_test = crc32buf(filebody + kernelsize, trailer.fs_len);
    if (ntohl(crc_test) != trailer.fs_crc32) {
        printf("Failed CRC32 check of rootfs in file.\n");
        return 0;
    }

    // Check mixed SHA256
    calc_mixed_sha256(filebody, bodysize, sha256_test);
    if (memcmp(sha256_test, trailer.sha256, SHA256_DIGEST_SIZE) != 0) {
        printf("Failed SHA256 check of file.\n");
        return 0;
    }

    memcpy(trailerout, &trailer, MSTC_TRAILER_SIZE);

    return 1;
}

int main(int argc, const char* argv[])
{
    FILE* fp;
    runmode mode = HELP;
    const char* openfile = NULL;
    const char* kernelfile = NULL;
    const char* rootfsfile = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            mode = HELP;
            break;
        }
        else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--test") == 0) {
            mode = TEST;
            openfile = argv[++i];
            break;
        }
        else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--extract") == 0) {
            mode = EXTRACT;
            openfile = argv[++i];
            kernelfile = argv[++i];
            rootfsfile = argv[++i];
            continue;
        }
        else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--create") == 0) {
            mode = CREATE;
            openfile = argv[++i];
            continue;
        }
        else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--kernel") == 0) {
            kernelfile = argv[++i];
            continue;
        }
        else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--rootfs") == 0) {
            rootfsfile = argv[++i];
            continue;
        }
    }

    if (mode == HELP) {
        printf("Usage: %s <args>\n"
            "-t (--test)     Test file integrity (-t input.bin)\n"
            "-e (--extract)  Extract kernel and rootfs (-e input.bin kernel.bin rootfs.bin)\n"
            "-c (--create)   Create RAS image with trailer (-c output.bin -k kernel.bin -r rootfs.bin)\n", argv[0]);
        return 2;
    }

    if (mode == TEST) {
        struct mstc_trailer trailer;

        fp = fopen(openfile, "rb");

        if (fp == NULL) {
            perror("Fail opening input file:");
            return 1;
        }

        int retcode = 0;
        if (checkras(fp, &trailer) == 1) {
            printf("All checks OK!\n");
            printf("trailer.magic: 0x%08X\n", ntohl(trailer.magic));
            printf("trailer.crc32: 0x%08X\n", ntohl(trailer.crc32));
            printf("trailer.fs_crc32: 0x%08X\n", ntohl(trailer.fs_crc32));
            printf("trailer.fs_len: %d\n", trailer.fs_len);
            printf("trailer.fs_type: 0x%02X\n", trailer.fs_type);
            printf("trailer.image_type: 0x%02X\n", trailer.image_type);
            printf("trailer.sha256: ");
            for (int x = 0; x < SHA256_DIGEST_SIZE; x++) {
                printf("%02x", trailer.sha256[x]);
            }
            printf("\n");
            printf("trailer.unk1: 0x%02X\n", trailer.unk1);
            printf("trailer.unk2: 0x%02X\n", trailer.unk2);
            printf("trailer.unk3: 0x%08X\n", trailer.unk3);
            printf("trailer.unk4: 0x%08X\n", trailer.unk4);
            printf("trailer.unk5: 0x%08X\n", trailer.unk5);
            printf("trailer.unk6: 0x%08X\n", trailer.unk6);
            printf("trailer.unk7: 0x%08X\n", trailer.unk7);
            printf("trailer.unk8: 0x%08X\n", trailer.unk8);

        }
        else {
            printf("Some checks FAIL!\n");
            retcode = 1;
        }

        fclose(fp);
        return retcode;
    }

    if (mode == EXTRACT) {
        int filesize = 0;
        int bodysize = 0;
        int bytesread = 0;
        int byteswritten = 0;
        char* filebody = NULL;
        struct mstc_trailer trailer;

        fp = fopen(openfile, "rb");

        if (fp == NULL) {
            printf("Fail opening file.\n");
            return 1;
        }

        if (checkras(fp, &trailer) == 0) {
            return 1;
        }

        // Get file size
        fseek(fp, 0L, SEEK_END);
        filesize = ftell(fp);
        rewind(fp);

        // Calculate body size
        bodysize = filesize - MSTC_TRAILER_SIZE;

        // Read body
        filebody = (char*)malloc(bodysize);
        bytesread = fread(filebody, 1, bodysize, fp);

        if (bytesread != bodysize) {
            printf("Fail reading file body.\n");
            free(filebody);
            return 1;
        }

        uint32_t kernelsize = bodysize - trailer.fs_len;

        FILE* kernelp = NULL;
        FILE* rootfsp = NULL;

        // Try opening kernel file
        kernelp = fopen(kernelfile, "wb");
        if (kernelp == NULL) {
            perror("Fail opening kernel file for writting:");
            free(filebody);
            return 1;
        }

        // Try opening rootfs file
        rootfsp = fopen(rootfsfile, "wb");
        if (rootfsp == NULL) {
            perror("Fail opening rootfs file for writting:");
            free(filebody);
            fclose(kernelp);
            return 1;
        }

        // Try writting kernel file
        byteswritten = fwrite(filebody, 1, kernelsize, kernelp);
        if (byteswritten != kernelsize) {
            printf("Fail writting kernel file '%s'.\n", kernelfile);
            free(filebody);
            fclose(kernelp);
            fclose(rootfsp);
            return 1;
        }

        // Try writting rootfs file
        byteswritten = fwrite(filebody + kernelsize, 1, trailer.fs_len, rootfsp);
        if (byteswritten != trailer.fs_len) {
            free(filebody);
            fclose(kernelp);
            fclose(rootfsp);
            printf("Fail writting rootfs file '%s'.\n", kernelfile);
            return 1;
        }

        // Cleanup
        free(filebody);
        fclose(fp);
        fclose(kernelp);
        fclose(rootfsp);

        printf("File '%s' extracted sucessfully.\n", openfile);
        return 0;
    }

    if (mode == CREATE) {
        uint32_t crc;
        uint32_t kernelsize = 0;
        uint32_t rootfssize = 0;
        uint32_t totalsize = 0;
        uint32_t bytesread = 0;
        uint8_t* filebody = NULL;
        uint8_t* kerneldata = NULL;
        uint8_t* rootfsdata = NULL;
        struct mstc_trailer trailer;

        FILE* kernelp = NULL;
        FILE* rootfsp = NULL;
        FILE* outfile = NULL;

        // Try opening kernel file
        kernelp = fopen(kernelfile, "rb");
        if (kernelp == NULL) {
            perror("Fail opening kernel file for reading.");
            return 1;
        }

        // Find kernel file size
        fseek(kernelp, 0L, SEEK_END);
        kernelsize = ftell(kernelp);
        rewind(kernelp);

        if (kernelsize > KERNEL_SIZE) {
            perror("Kernel file size is too large (Limit is 4MB)");
            fclose(kernelp);
            return 1;
        }

        // Try opening rootfs file
        rootfsp = fopen(rootfsfile, "rb");
        if (rootfsp == NULL) {
            perror("Fail opening rootfs file for reading.");
            fclose(kernelp);
            return 1;
        }

        // Find rootfs file size
        fseek(rootfsp, 0L, SEEK_END);
        rootfssize = ftell(rootfsp);
        rewind(rootfsp);

        // Total file size
        totalsize = KERNEL_SIZE + rootfssize;

        // Alloc buffers
        kerneldata = (uint8_t*)malloc(kernelsize);
        rootfsdata = (uint8_t*)malloc(rootfssize);
        filebody = (uint8_t*)malloc(totalsize);

        if (kerneldata == 0 || rootfsdata == 0 || filebody == 0) {
            perror("Error allocating memory");
            fclose(kernelp);
            fclose(rootfsp);
            free(filebody);
            free(kerneldata);
            free(rootfsdata);
            return 1;
        }

        // Try reading kernel file
        bytesread = fread(kerneldata, 1, kernelsize, kernelp);
        if (bytesread != kernelsize) {
            perror("Fail reading kernel file.\n");
            fclose(kernelp);
            fclose(rootfsp);
            free(filebody);
            free(kerneldata);
            free(rootfsdata);
            return 1;
        }

        // Try reading rootfs file
        bytesread = fread(rootfsdata, 1, rootfssize, rootfsp);
        if (bytesread != rootfssize) {
            printf("Fail reading rootfs file.\n");
            fclose(kernelp);
            fclose(rootfsp);
            free(filebody);
            free(kerneldata);
            free(rootfsdata);
            return 1;
        }

        // Original firmware has the remaining space for kernel part filled with 0xFF
        memset(filebody, 0xFF, totalsize);

        memcpy(filebody, kerneldata, kernelsize);
        memcpy(filebody + KERNEL_SIZE, rootfsdata, rootfssize);

        // Init the trailer
        memset(&trailer, 0x00, MSTC_TRAILER_SIZE);

        trailer.magic = htonl(MSTC_TRAILER_MAGIC);

        trailer.fs_len = rootfssize;

        // Calculate CRC32 of the file
        crc = crc32buf(filebody, totalsize);
        trailer.crc32 = htonl(crc);

        // Calculate CRC32 of the rootfs
        crc = crc32buf(rootfsdata, rootfssize);
        trailer.fs_crc32 = htonl(crc);

        // Calculate SHA256 of the file
        calc_mixed_sha256(filebody, totalsize, trailer.sha256);

        // Fill flags
        trailer.fs_type = 1;
        trailer.image_type = 1;

        // This flags are always set to this values on all original firmware samples I got
        trailer.unk1 = 2;
        trailer.unk2 = 0;

        outfile = fopen(openfile, "wb");

        // Write the final data to the file
        fwrite(filebody, 1, totalsize, outfile);
        fwrite(&trailer, 1, MSTC_TRAILER_SIZE, outfile);

        // Cleanup
        free(kerneldata);
        free(rootfsdata);
        free(filebody);
        fclose(outfile);
        fclose(kernelp);
        fclose(rootfsp);

        printf("File '%s' built succesfully.\n", openfile);
        return 0;
    }
}


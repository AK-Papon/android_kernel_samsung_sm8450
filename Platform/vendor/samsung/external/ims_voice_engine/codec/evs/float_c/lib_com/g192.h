/*====================================================================================
    EVS Codec 3GPP TS26.443 Oct 20, 2015. Version 12.4.0
  ====================================================================================*/

#ifndef G192_H
#define G192_H G192_H

#include <stdio.h>

/*
 * ENUMS
 */

/* error enums */

typedef enum _G192_ERROR
{
    G192_NO_ERROR          = 0x0000,
    G192_MEMORY_ERROR      = 0x0001,
    G192_WRONG_PARAMS      = 0x0002,
    G192_INIT_ERROR        = 0x0003,
    G192_WRITE_ERROR       = 0x0004,
    G192_READ_ERROR        = 0x0005,
    G192_FILE_NOT_FOUND    = 0x0006,
    G192_NOT_IMPLEMENTED   = 0x0010,
    G192_NOT_INITIALIZED   = 0x0100,
    G192_UNKNOWN_ERROR     = 0x1000
} G192_ERROR;

/*
 * Structures
 */

/* main handle */
struct __G192;
typedef struct __G192 * G192_HANDLE;
#define DS5_SIMU
/*
 * Functions
 */

G192_ERROR
G192_Reader_Open(G192_HANDLE* phG192, FILE * filename);

G192_ERROR
G192_ReadVoipFrame_compact(G192_HANDLE const hG192,
                           unsigned char * const serial,
                           short * const num_bits,
                           unsigned short * const rtpSequenceNumber,
                           unsigned int * const rtpTimeStamp,
                           unsigned int * const rcvTime_ms);

G192_ERROR
G192_ReadVoipFrame_short(G192_HANDLE const hG192,
                         short * const serial,
                         short * const num_bits,
                         unsigned short * const rtpSequenceNumber,
                         unsigned int * const rtpTimeStamp,
                         unsigned int * const rcvTime_ms);

G192_ERROR
G192_Reader_Close(G192_HANDLE* phG192);

#ifdef DS5_SIMU
#define BigLittleSwap16(A)  ((((unsigned short)(A) & 0xff00) >> 8) | \
                            (((unsigned short)(A) & 0x00ff) << 8))
#define BigLittleSwap32(A)  ((((unsigned int)(A) & 0xff000000) >> 24) | \
                            (((unsigned int)(A) & 0x00ff0000) >> 8) | \
                            (((unsigned int)(A) & 0x0000ff00) << 8) | \
                            (((unsigned int)(A) & 0x000000ff) << 24))
unsigned int t_htonl(unsigned int h);
unsigned int t_ntohl(unsigned int n);
unsigned short t_htons(unsigned short h);
unsigned short t_ntohs(unsigned short n);
#endif
#endif /* G192_H */

/*
 * base64 decoder implementation
 *
 * Licensed under a Creative Commons Attribution-ShareAlike 3.0 Unported
 * License
 *
 * This is a human-readable summary of (and not a substitute for) the license:
 * https://creativecommons.org/licenses/by-sa/3.0/legalcode.txt
 *
 * You are free to:
 *
 *    Share — copy and redistribute the material in any medium or format
 *    Adapt — remix, transform, and build upon the material
 *    for any purpose, even commercially.
 *
 *    The licensor cannot revoke these freedoms as long as you follow
 *    the license terms.
 *
 * Under the following terms:
 *
 *    Attribution — You must give appropriate credit, provide a link to
 *    the license, and indicate if changes were made. You may do so in any
 *    reasonable manner, but not in any way that suggests the licensor endorses
 *    you or your use.
 *
 *    ShareAlike — If you remix, transform, or build upon the material, you
 *    must distribute your contributions under the same license as the original.
 *
 *    No additional restrictions — You may not apply legal terms or
 *    technological measures that legally restrict others from doing anything
 *    the license permits.
 */

#include "base64_decode.h"

#define WHITESPACE 64
#define EQUALS     65
#define INVALID    66

static const unsigned char d[256] = {
  64, 66, 66, 66, 66, 66, 66, 66, 66, 66, 64, 66, 66, 64, 66, 66, /* 16 */
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, /* 32 */
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 62, 66, 66, 66, 63, /* 48 */
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 66, 66, 66, 65, 66, 66, /* 64 */
  66,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /* 80 */
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 66, 66, 66, 66, 66, /* 96 */
  66, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 112 */
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 66, 66, 66, 66, 66, /* 128 */
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, /* 144 */
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, /* 160 */
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, /* 176 */
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, /* 192 */
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, /* 208 */
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, /* 224 */
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, /* 240 */
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66  /* 256 */
};

int base64decode(const char *in, size_t inLen, unsigned char *out, size_t *outLen) {
  const char *end = in + inLen;
  char iter = 0;
  size_t buf = 0, len = 0;

  while (in < end) {
    unsigned char c = d[(unsigned)(*in++)];

    switch (c) {
      case WHITESPACE: {
        continue;   /* skip whitespace */
      }
      case INVALID: {
        return 1; /* invalid input, return error */
      }
      case EQUALS: { /* pad character, end of data */
        in = end;
        continue;
      }
      default: {
        buf = buf << 6 | c;
        iter++; // increment the number of iteration
        /* If the buffer is full, split it into bytes */
        if (iter == 4) {
          if ((len += 3) > *outLen) {
            return 1; /* buffer overflow */
          }
          *(out++) = (buf >> 16) & 255;
          *(out++) = (buf >> 8) & 255;
          *(out++) = buf & 255;
          buf = 0; iter = 0;
        }
      }
    }
  }

  if (iter == 3) {
    if ((len += 2) > *outLen) {
      return 1; /* buffer overflow */
    }
    *(out++) = (buf >> 10) & 255;
    *(out++) = (buf >> 2) & 255;
  } else if (iter == 2) {
    if (++len > *outLen) {
      return 1; /* buffer overflow */
    }
    *(out++) = (buf >> 4) & 255;
  }

  *outLen = len; /* modify to reflect the actual output size */
  return 0;
}

/*====================================================================================
    EVS Codec 3GPP TS26.443 Oct 20, 2015. Version 12.4.0
  ====================================================================================*/

#include <stdlib.h>
#include <math.h>
#include "options.h"
#include "cnst.h"
#include "rom_com.h"
#include "prot.h"

/*-------------------------------------------------------------------*
 * rc_get_bits2()
 *
 *  Get number of bits needed to finalize range coder
 *-------------------------------------------------------------------*/

short rc_get_bits2(                 /* o: Number of bits needed         */
    const short N,                  /* i: Number of bits currently used */
    const unsigned int range        /* i: Range of range coder          */
)
{
    return N + 32 - (log2_i(range) - 1);
}

/*-------------------------------------------------------------------*
 * rc_get_bits_f2()
 *
 *  Get fractional number of bits needed to finialize range coder
 *-------------------------------------------------------------------*/

short rc_get_bits_f2(               /* o: Number of bits needed in Q3   */
    const short N,                  /* i: Number of bits currently used */
    const unsigned int range        /* i: Range of range coder          */
)
{
    unsigned int r;
    short i, k, n;

    n = log2_i(range) - 1;
    r = range >> ((n+1) - 15);  /* Q15 */

    for (i = 0; i < 3; i++)
    {
        r = (r*r) >> 15;        /* Q15 */
        k = r >> 16;            /* 1 if r >= 2 */
        n = (n<<1) | k;
        r >>= k;
    }

    return (N << 3) + 256 - n;  /* Q3 */
}


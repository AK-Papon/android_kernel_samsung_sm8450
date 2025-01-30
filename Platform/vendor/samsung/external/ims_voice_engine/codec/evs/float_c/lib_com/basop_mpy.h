/*====================================================================================
    EVS Codec 3GPP TS26.443 Oct 20, 2015. Version 12.4.0
  ====================================================================================*/

#ifndef __BASOP_MPY_H
#define __BASOP_MPY_H

#include "stl.h"
#include "options.h"

#define  Mpy_32_16  Mpy_32_16_new
Word32 Mpy_32_16_new(Word32 x,Word16 y);


/**
 * \brief   32*16 Bit fractional Multiplication using 40 bit OPS
 *          Performs a multiplication of a 32-bit variable x by
 *          a 16-bit variable y, returning a 32-bit value.
 *
 * \param[i] x
 * \param[i] y
 *
 * \return x*y
 */
Word32 Mpy_32_16_1(Word32 x,
                   Word16 y);


/**
 * \brief 	32*16 Bit fractional Multiplication using 40 bit OPS
 *          Performs a multiplication of a 32-bit variable x by
 *          a 16-bit variable y, returning a 32-bit value.
 *
 * \param[i] x
 * \param[i] y
 *
 * \return x*y
 */
Word32 Mpy_32_16(Word32 x,
                 Word16 y);


/**
 * \brief 	32*16 Bit fractional Multiplication using 40 bit OPS
 *          Performs a multiplication of a 32-bit variable x by
 *          a 16-bit variable y including rounding, returning a 32-bit value.
 *
 * \param[i] x
 * \param[i] y
 *
 * \return x*y
 */
Word32 Mpy_32_16_r(Word32 x, Word16 y);


/**
 * \brief 	32*32 Bit fractional Multiplication using 40 bit OPS
 *
 *          Performs a multiplication of a 32-bit variable x by
 *          a 32-bit variable y, returning a 32-bit value.
 *
 * \param[i] x
 * \param[i] y
 *
 * \return x*y
 */

Word32 Mpy_32_32(Word32 x,
                 Word32 y);

#endif /* __BASOP_SETTINGS_H */

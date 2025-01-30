/*====================================================================================
    EVS Codec 3GPP TS26.443 Oct 20, 2015. Version 12.4.0
  ====================================================================================*/

#include <math.h>
#include "options.h"
#include "cnst.h"
#include "rom_com.h"
#include "prot.h"
#include "stl.h"

/*-------------------------------------------------------------------*
 * Local definitions
 *-------------------------------------------------------------------*/

#define OFFSET 21
#define STEP   9

typedef unsigned long long ui64_t;

/*-------------------------------------------------------------------*
 * own_cos()
 *
 *  Bit-exact cosine
 *-------------------------------------------------------------------*/

short own_cos(
    const short x
)
{
    short a[4] = {14967,   -25518,   3415,   32351};
    int b;

    b = a[0];
    b = (a[1] + ((b * x) >> 16)) << 1;
    b = a[2] + ((b * x) >> 15);
    b = a[3] + ((b * x) >> 15);

    return (short)b;
}

/*-------------------------------------------------------------------*
 * get_angle_res()
 *
 *
 *-------------------------------------------------------------------*/

short get_angle_res(short dim, short bits)
{
    short bits_min = 28;
    short bits_max = 96;

    short angle_res, angle_bits;

    angle_bits = min(bits-bits_max, (bits+(2*dim-1)*bits_min)/(2*dim-1));
    angle_bits = min(56, angle_bits);

    if (angle_bits<4)
    {
        angle_res = 1;
    }
    else
    {
        angle_res = pow2_angle_res[angle_bits&0x7]>>(14-(angle_bits>>3));
        angle_res = (angle_res+1)>>1<<1;
    }

    return angle_res;
}

/*-------------------------------------------------------------------*
 * get_pulse ()
 *
 *
 *-------------------------------------------------------------------*/

short get_pulse(
    const short q
)
{
    short s, m, k;

    if (q <= OFFSET)
    {
        return q;
    }
    else
    {
        s = (short)((q - OFFSET)*(1.0f/STEP));
        m = q - (OFFSET + s*STEP);
        k = (255 >> (8-s)) << 1;

        return min(KMAX, OFFSET + STEP*k + (1 << (s+1))*m);
    }
}

/*-------------------------------------------------------------------*
 * bits2pulses()
 *
 *
 *-------------------------------------------------------------------*/

short bits2pulses(
    const short N,
    const short bits,
    const short strict_bits
)
{
    const unsigned char *tab;
    short B, mid, low, high, q;
    short i;

    tab = hBitsN[N];
    low = 1;
    high = tab[0];
    B = bits - 1;

    if (tab[high] <= B)
    {
        q =  high;
    }
    else
    {
        for (i = 0; i < 6; i++)
        {
            mid = (low + high)>>1;

            if (tab[mid] >= B)
            {
                high = mid;
            }
            else
            {
                low = mid;
            }
        }

        if (strict_bits || B - tab[low] <= tab[high] - B)
        {
            q = low;
        }
        else
        {
            q = high;
        }
    }

    return q;
}

/*-------------------------------------------------------------------*
 * bits2pulses()
 *
 *
 *-------------------------------------------------------------------*/

short pulses2bits(
    const short N,
    const short P
)
{
    const unsigned char *tab;
    short bits;

    tab = hBitsN[N];

    if (P == 0)
    {
        bits = 0;
    }
    else
    {
        bits = tab[P] + 1;
    }

    return bits;
}


/*-------------------------------------------------------------------*
 * local_norm_s()
 *
 *
 *-------------------------------------------------------------------*/
static
short local_norm_s (       /* o : n shifts needed to normalize */
    short short_var      /* i : signed 16 bit variable */
)
{
    short short_res;

    if (short_var == -1 )
    {
        return (16-1);
    }
    else
    {
        if (short_var == 0)
        {
            return 0;
        }

        else
        {
            if (short_var < 0)
            {
                short_var = ~short_var;
            }

            for (short_res = 0; short_var < 0x4000; short_res++)
            {
                short_var <<= 1;
            }
        }
    }

    return (short_res);
}


/*--------------------------------------------------------------------------*
 * log2_div()
 *
 *  Logarithm of division
 *--------------------------------------------------------------------------*/

short  log2_div(        /* o : Log2 of division, Q11 */
    short input_s,      /* i : Numerator         Q15 */
    short input_c       /* i : Denominator       Q15 */
)
{
    Word16 mc, nc, ms, ns, d, z;
    Word16 result;
    Word32 acc;

    /* log2|sin(x)/cos(x)| = log2|sin(x)| - log2(cos(x)|
     *                     = log2|ms*2^-ns| - log2|mc*2^-nc|, where 0.5 <= ms < 1.0 and 0.5 <= mc < 1.0
     *                     = log2|ms| - ns - log2|mc| + nc
     *
     * Approximate log2(y) by a 2nd order least square fit polynomial. Then,
     *
     * log2|sin(x)/cos(x)| ~ (a0*ms^2 + a1*ms + a2) - ns - (a0*mc^2 + a1*mc + a2) + nc
     *                     = a0*(ms^2 - mc^2) + a1*(ms - mc) - ns + nc
     *                     = a0*(ms + mc)*(ms - mc) + a1*(ms - mc) - ns + nc
     *                     = (a0*(ms + mc) + a1)*(ms - mc) - ns + nc
     *                     = (a0*ms + a0*mc + a1)*(ms - mc) - ns + nc
     */
    ns = local_norm_s(input_s );    /* exponent*/
    nc = local_norm_s(input_c );    /* exponent */

    ms  = input_s << ns;   /* mantissa */
    mc  = input_c << nc;   /* mantissa */

    acc = L_mac(538500224L, mc, -2776);  /* a0*mc + a1, acc(Q27), a0(Q11), a1(Q27)*/
    z = mac_r(acc, ms, -2776);           /* z in Q11, a0 in Q11 */
    d = sub(ms, mc);                     /* d in Q15 */
    z = mult_r(z, d);                    /* z in Q11 */

    result = add(z, shl(sub(nc, ns), 11));

    return result;
}


/*--------------------------------------------------------------------------*
 * apply_gain()
 *
 * Apply gain
 *--------------------------------------------------------------------------*/

void apply_gain
(
    const short *ord,                       /* i  : Indices for energy order                     */
    const short *band_start,                /* i  : Sub band start indices                       */
    const short *band_end,                  /* i  : Sub band end indices                         */
    const short num_sfm,                    /* i  : Number of bands                              */
    const float *gains,                     /* i  : Band gain vector                             */
    float *xq                         /* i/o: Float synthesis / Gain adjusted synth        */
)
{
    short band,i;
    float g;

    for ( band = 0; band < num_sfm; band++)
    {
        g = gains[ord[band]];

        for( i = band_start[band]; i < band_end[band]; i++)
        {
            xq[i] *= g;
        }
    }

    return;
}


/*--------------------------------------------------------------------------*
 * fine_gain_quant()
 *
 * Fine gain quantization
 *--------------------------------------------------------------------------*/

void fine_gain_quant
(
    Encoder_State *st,
    const short *ord,                       /* i  : Indices for energy order                     */
    const short num_sfm,                    /* i  : Number of bands                              */
    const short *gain_bits,                 /* i  : Gain adjustment bits per sub band            */
    float *fg_pred,                   /* i/o: Predicted gains / Corrected gains            */
    const float *gopt                       /* i  : Optimal gains                                */
)
{
    short band;
    short gbits;
    short idx;
    float gain_db,gain_dbq;
    float err;

    for ( band = 0; band < num_sfm; band++)
    {
        gbits = gain_bits[ord[band]];
        if ( fg_pred[band] != 0 && gbits > 0 )
        {
            err = gopt[band] / fg_pred[band];
            gain_db = 20.0f*(float)log10(err);
            idx = (short) squant(gain_db, &gain_dbq, finegain[gbits-1], gain_cb_size[gbits-1]);
            push_indice( st, IND_PVQ_FINE_GAIN, idx, gbits );

            /* Update prediced gain with quantized correction */
            fg_pred[band] *= (float)pow(10, gain_dbq * 0.05f);
        }
    }

    return;
}

/*-------------------------------------------------------------------*
 * srt_vec_ind()
 *
 * sort vector and save sorting indices
 *-------------------------------------------------------------------*/

void srt_vec_ind (
    const short *linear,      /* i: linear input */
    short *srt,         /* o: sorted output*/
    short *I,           /* o: index for sorted output  */
    short length        /* i: length of vector */
)
{
    float linear_f[MAX_SRT_LEN];
    float srt_f[MAX_SRT_LEN];

    mvs2r(linear, linear_f, length);
    srt_vec_ind_f(linear_f, srt_f, I, length);
    mvr2s(srt_f, srt, length);

    return;
}

/*-------------------------------------------------------------------*
 * srt_vec_ind_f()
 *
 * sort vector and save sorting indices, using float input values
 *-------------------------------------------------------------------*/

void srt_vec_ind_f(
    const float *linear,      /* i: linear input */
    float *srt,         /* o: sorted output*/
    short *I,           /* o: index for sorted output  */
    short length        /* i: length of vector */
)
{
    short pos,npos;
    short idxMem;
    float valMem;

    /*initialize */
    for (pos = 0; pos < length; pos++)
    {
        I[pos] = pos;
    }

    mvr2r(linear, srt,length);

    /* now iterate */
    for (pos = 0; pos < (length - 1); pos++)
    {
        for (npos = (pos + 1); npos < length;  npos++)
        {
            if (srt[npos] < srt[pos])
            {
                idxMem    = I[pos];
                I[pos]    = I[npos];
                I[npos]   = idxMem;

                valMem    = srt[pos];
                srt[pos]  = srt[npos];
                srt[npos] = valMem;
            }
        }
    }

    return;
}


unsigned int UMult_32_32(unsigned int UL_var1, unsigned int UL_var2)
{
    ui64_t tmp;

    tmp = (ui64_t)UL_var1 * (ui64_t)UL_var2;
    return (unsigned int)(tmp >> 32);
}

/*-------------------------------------------------------------------*
 *  UL_div
 *
 *  Calculate UL_num/UL_den. UL_num assumed to be Q31, UL_den assumed
 *  to be Q32, then result is in Q32.
 *-------------------------------------------------------------------*/
static unsigned int UL_div(const unsigned int UL_num, const unsigned int UL_den)
{
    unsigned int UL_e, UL_Q;
    unsigned int UL_msb;
    short i;

    UL_e = 0xffffffff - UL_den;
    UL_Q = UL_num;

    for (i = 0; i < 5; i++)
    {
        UL_msb = UMult_32_32(UL_Q, UL_e);
        UL_Q = UL_Q + UL_msb;
        UL_e = UMult_32_32(UL_e, UL_e);
    }

    return UL_Q;
}
/*-------------------------------------------------------------------*
 *  UL_inverse
 *
 *  Calculate inverse of UL_val. Output in Q_exp.
 *-------------------------------------------------------------------*/
unsigned int UL_inverse(const unsigned int UL_val, short *exp)
{
    unsigned int UL_tmp;

    /* *exp = norm_ul(UL_val);*/
    *exp = 31 - log2_i(UL_val);
    UL_tmp = UL_val << (*exp);   /* Q32*/

    *exp = 32 + 31 - *exp;

    return UL_div(0x80000000, UL_tmp);
}

/*-----------------------------------------------------------------------------
 * ratio()
 *
 * Divide the numerator by the denominator.
 *----------------------------------------------------------------------------*/
Word16 ratio(const Word32 numer, const Word32 denom, Word16 *expo)
{
    Word16 expNumer, expDenom;
    Word16 manNumer, manDenom;
    Word16 quotient;

    expDenom = norm_l(denom);                     /* exponent */
    manDenom = extract_h(L_shl(denom, expDenom)); /* mantissa */
    expNumer = norm_l(numer);                     /* exponent */
    manNumer = extract_h(L_shl(numer, expNumer)); /* mantissa */
    manNumer = shr(manNumer, 1); /* Ensure the numerator < the denominator */
    quotient = div_s(manNumer, manDenom); /* in Q14 */

    *expo = sub(expNumer, expDenom);

    return quotient; /* Q14 */
}

/*-----------------------------------------------------------------------------
 * atan2_fx():
 *
 * Approximates arctan piecewise with various 4th to 5th order least square fit
 * polynomials for input in 5 segments:
 *   - 0.0 to 1.0
 *   - 1.0 to 2.0
 *   - 2.0 to 4.0
 *   - 4.0 to 8.0
 *   - 8.0 to infinity
 *---------------------------------------------------------------------------*/
Word16 atan2_fx(  /* o: Angle between 0 and EVS_PI/2 radian (Q14) */
    const Word32 y,  /* i: Argument must be positive (Q15) */
    const Word32 x   /* i: Q15 */
)
{
    Word32 acc, arg;
    Word16 man, expo, reciprocal;
    Word16 angle, w, z;

    IF (L_sub(x, 0) == 0)
    {
        return 25736; /* EVS_PI/2 in Q14 */
    }
    man = ratio(y, x, &expo); /*  man in Q14 */
    expo = sub(expo, (15 - 14)); /*  Now, man is considered in Q15 */
    arg = L_shr((Word32)man, expo);

    IF (L_shr(arg, 3+15) != 0)
    /*===============================*
     *      8.0 <= x < infinity      *
     *===============================*/
    {
        /* atan(x) = EVS_PI/2 - 1/x + 1/(3x^3) - 1/(5x^5) + ...
         *         ~ EVS_PI/2 - 1/x, for x >= 8.
         */
        expo = norm_l(arg);
        man = extract_h(L_shl(arg, expo));
        reciprocal = div_s(0x3fff, man);
        expo = sub(15 + 1, expo);
        reciprocal = shr(reciprocal, expo);   /*  Q14*/
        angle = sub(25736, reciprocal);       /* Q14   (EVS_PI/2 - 1/x) */

        /* For 8.0 <= x < 10.0, 1/(5x^5) is not completely negligible.
         * For more accurate result, add very small correction term.
         */
        IF (L_sub(L_shr(arg, 15), 10L) < 0)
        {
            angle = add(angle, 8); /* Add tiny correction term. */
        }
    }
    ELSE IF (L_shr(arg, 2+15) != 0)
    /*==========================*
     *      4.0 <= x < 8.0      *
     *==========================*/
    {
        /* interval: [3.999, 8.001]
         * atan(x) ~ (((a0*x     +   a1)*x   + a2)*x   + a3)*x   + a4
         *         = (((a0*8*y   +   a1)*8*y + a2)*8*y + a3)*8*y + a4   Substitute 8*y -> x
         *         = (((a0*8^3*y + a1*8^2)*y + a2*8)*y + a3)*8*y + a4
         *         = (((    c0*y +     c1)*y +   c2)*y + c3)*8*y + c4,
         *  where y = x/8
         *   and a0 = -1.28820869667651e-04, a1 = 3.88263533346295e-03,
         *       a2 = -4.64216306484597e-02, a3 = 2.75986060068931e-01,
         *       a4 = 7.49208077809799e-01.
         */
        w = extract_l(L_shr(arg, 3));              /* Q15  y = x/8 */
        acc = 533625337L;                          /* Q31  c1 = a1*8^2 */       move32();
        z = mac_r(acc, w, -2161);                  /* Q15  c0 = a0*8^3 */
        acc = -797517542L;                         /* Q31  c2 = a2*8 */         move32();
        z = mac_r(acc, w, z);                      /* Q15 */
        acc = 592675551L;                          /* Q31  c3 = a3 */           move32();
        z = mac_r(acc, w, z);                      /* z (in:Q15, out:Q12) */
        acc = 201114012L;                          /* Q28  c4 = a4 */           move32();
        acc = L_mac(acc, w, z);                    /* Q28 */
        angle = extract_l(L_shr(acc, (28 - 14)));  /* Q14 result of atan(x), where 4 <= x < 8 */
    }
    ELSE IF (L_shr(arg, 1+15) != 0)
    /*==========================*
     *      2.0 <= x < 4.0      *
     *==========================*/
    {
        /* interval: [1.999, 4.001]
         * atan(x) ~ (((a0*x    + a1)*x   +   a2)*x   + a3)*x   + a4
         *         = (((a0*4*y  + a1)*4*y +   a2)*4*y + a3)*4*y + a4   Substitute 4*y -> x
         *         = (((a0*16*y + a1*4)*y +   a2)*4*y + a3)*4*y + a4
         *         = (((a0*32*y + a1*8)*y + a2*2)*2*y + a3)*4*y + a4
         *         = (((   c0*y +   c1)*y +   c2)*2*y + c3)*4*y + c4,
         *  where y = x/4
         *   and a0 = -0.00262378195660943, a1 = 0.04089687039888652,
         *       a2 = -0.25631148958325911, a3 = 0.81685854627399479,
         *       a4 = 0.21358070563097167
         * */
        w = extract_l(L_shr(arg, 2));              /* Q15  y = x/4 */
        acc = 702602883L;                          /* Q31  c1 = a1*8 */         move32();
        z = mac_r(acc, w, -2751);                  /* Q15  c0 = a0*32 */
        acc = -1100849465L;                        /* Q31  c2 = a2*2 */         move32();
        z = mac_r(acc, w, z);                      /* z (in:Q15, out:Q14) */
        acc = 877095185L;                          /* Q30  c3 = a3 */           move32();
        z = mac_r(acc, w, z);                      /* z (in:Q14, out:Q12) */
        acc = 57332634L;                           /* Q28  c4 = a4 */           move32();
        acc = L_mac(acc, w, z);                    /* Q28 */
        angle = extract_l(L_shr(acc, (28 - 14)));  /* Q14  result of atan(x) where 2 <= x < 4 */
    }
    ELSE IF (L_shr(arg, 15) != 0)
    /*==========================*
     *      1.0 <= x < 2.0      *
     *==========================*/
    {
        /* interval: [0.999, 2.001]
         * atan(x) ~ (((a0*x   +  1)*x   + a2)*x   +   a3)*x   + a4
         *         = (((a0*2*y + a1)*2*y + a2)*2*y +   a3)*2*y + a4    Substitute 2*y -> x
         *         = (((a0*4*y + a1*2)*y + a2)*2*y +   a3)*2*y + a4
         *         = (((a0*4*y + a1*2)*y + a2)*y   + a3/2)*4*y + a4
         *         = (((  c0*y +   c1)*y + c2)*y   +   c3)*4*y + c4,
         *  where y = x/2
         *   and a0 = -0.0160706457245251, a1 = 0.1527106504065224,
         *       a2 = -0.6123208404800871, a3 = 1.3307896976322915,
         *       a4 = -0.0697089375247448
         */
        w = extract_l(L_shr(arg, 1));              /* Q15  y= x/2 */
        acc = 655887249L;                          /* Q31  c1 = a1*2 */         move32();
        z = mac_r(acc, w, -2106);                  /* Q15  c0 = a0*4 */
        acc = -1314948992L;                        /* Q31  c2 = a2 */           move32();
        z = mac_r(acc, w, z);
        acc = 1428924557L;                         /* Q31  c3 = a3/2 */         move32();
        z = mac_r(acc, w, z);                      /* z (in:Q15, out:Q13) */
        acc = -37424701L;                          /* Q29  c4 = a4 */           move32();
        acc = L_mac(acc, w, z);                    /* Q29 */
        angle = extract_l(L_shr(acc, (29 - 14)));  /* Q14  result of atan(x) where 1 <= x < 2 */
    }
    ELSE
    /*==========================*
     *      0.0 <= x < 1.0      *
     *==========================*/
    {
        /* interval: [-0.001, 1.001]
         * atan(x) ~ ((((a0*x   +   a1)*x   + a2)*x + a3)*x + a4)*x + a5
         *         = ((((a0*2*x + a1*2)*x/2 + a2)*x + a3)*x + a4)*x + a5
         *         = ((((  c0*x +   c1)*x/2 + c2)*x + c3)*x + c4)*x + c5
         *  where
         *    a0 = -5.41182677118661e-02, a1 = 2.76690449232515e-01,
         *    a2 = -4.63358392562492e-01, a3 = 2.87188466598566e-02,
         *    a4 =  9.97438122814383e-01, a5 = 5.36158556179092e-05.
         */
        w = extract_l(arg);                         /* Q15 */
        acc = 1188376431L;                          /* Q31  c1 = a1*2 */        move32();
        z = mac_r(acc, w, -3547);                   /* Q15  c0 = a0*2 */
        acc = -995054571L;                          /* Q31  c2 = a2 */          move32();
        z = extract_h(L_mac0(acc, w, z));           /* Q15  non-fractional mode multiply */
        acc = 61673254L;                            /* Q31  c3 = a3 */          move32();
        z = mac_r(acc, w, z);
        acc = 2141982059L;                          /* Q31  c4 = a4 */          move32();
        z = mac_r(acc, w, z);
        acc = 115139L;                              /* Q31  c5 = a5 */          move32();
        acc = L_mac(acc, w, z);                     /* Q31 */
        angle = extract_l(L_shr(acc, 31 - 14));     /* Q14  result of atan(x), where 0 <= x < 1 */
    }

    return angle;  /* Q14 between 0 and EVS_PI/2 radian. */
}

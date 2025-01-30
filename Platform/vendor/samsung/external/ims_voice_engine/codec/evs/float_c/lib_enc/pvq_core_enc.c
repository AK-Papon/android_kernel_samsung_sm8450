/*====================================================================================
    EVS Codec 3GPP TS26.443 Oct 20, 2015. Version 12.4.0
  ====================================================================================*/

#include <stdlib.h>
#include <math.h>
#include "options.h"
#include "rom_com.h"
#include "prot.h"
#include "prot.h"
#include "stl.h"

/*-------------------------------------------------------------------*
* Local functions
*--------------------------------------------------------------------*/

static short calc_pvq_splits( Encoder_State *st, const short band_bits, const short sfmsize, const float *y, short *bits );


/*-------------------------------------------------------------------*
* pvq_encode_band()
*
* Encode band with PVQ
*--------------------------------------------------------------------*/

static void pvq_encode_band(
    Encoder_State *st,
    const float *coefs_norm,
    short *pulse_vector,
    short *npulses,
    float *coefs_quant,
    const short sfmsize,
    const short band_bits,
    short *bits_left,
    const short strict_bits
)
{
    short K_val, K_idx;
    short used_bits;

    short j, Np;
    float enr, E_part[MAX_SPLITS+1];
    short part_start[MAX_SPLITS+1], dim_part[MAX_SPLITS+1], bits_part[MAX_SPLITS+1];
    short pool_tot, pool_part, dim_parts;
    float g_part[MAX_SPLITS];
    short g_part_s[MAX_SPLITS];
    short sg_part[MAX_SPLITS+1];
    short idx_sort[MAX_SPLITS+1];
    short js, band_bits_tot, split_bit;

    Np = calc_pvq_splits(st, band_bits, sfmsize, coefs_norm, &split_bit);
    band_bits_tot = band_bits - split_bit;

    enr = 0.0f;
    for(j = 0; j<sfmsize; j++)
    {
        enr += coefs_norm[j]*coefs_norm[j];
    }

    dim_parts = (short) floor(sfmsize/Np);
    set_s(dim_part,dim_parts,Np-1);
    dim_part[Np-1] = sfmsize-dim_parts*(Np-1);

    part_start[0] = 0;
    for(j = 1; j<Np; j++)
    {
        part_start[j] = part_start[j-1] + dim_part[j-1];
    }

    /* Encode energies */
    set_s( g_part_s, -32768, Np );
    if(Np > 1)
    {
        encode_energies( st, coefs_norm, Np, dim_part, E_part, bits_part, g_part_s, band_bits_tot, bits_left, enr, sfmsize, strict_bits );
    }
    else
    {
        bits_part[0] = band_bits_tot;
    }

    pool_tot = 0;
    pool_part = 0;

    for (j = 0; j < Np; j++)
    {
        g_part[j] = -((float)g_part_s[j])/32768;
        g_part_s[j] = -g_part_s[j];
    }

    srt_vec_ind(g_part_s,sg_part,idx_sort,Np);
    for(j = 0; j < Np; j++)
    {
        js = idx_sort[Np-1-j];
        pool_part = pool_tot / (Np-j);

        bits_part[js] = max(0, min(bits_part[js]+pool_part, 256)); /* limit of 32 bits */

        /* Determine number of pulses */
        K_idx = bits2pulses(dim_part[js], bits_part[js], strict_bits );
        used_bits = pulses2bits(dim_part[js], K_idx);
        *bits_left -= used_bits;
        pool_tot += bits_part[js] - used_bits;

        while (*bits_left < 0 && K_idx > 0)
        {
            *bits_left += used_bits;
            K_idx--;
            used_bits = pulses2bits(dim_part[js], K_idx);
            *bits_left -= used_bits;
        }

        if( K_idx!=0 )
        {
            K_val = get_pulse(K_idx);
            *npulses += K_val;
            pvq_encode(st, coefs_norm + part_start[js], pulse_vector + part_start[js],
                       coefs_quant + part_start[js], K_val, dim_part[js], g_part[js]);
        }
        else
        {
            set_f(coefs_quant + part_start[js],0.0f,dim_part[js]);
            set_s(pulse_vector + part_start[js],0,dim_part[js]);
        }
    }

    return;
}

/*-------------------------------------------------------------------*
* pvq_encode_frame()
*
*
*--------------------------------------------------------------------*/

void pvq_encode_frame(
    Encoder_State *st,
    const float *coefs_norm,       /* i  : normalized coefficients to encode */
    float *coefs_quant,      /* o  : quantized coefficients */
    float *gopt,             /* o  : optimal shape gains */
    short *npulses,          /* o  : number of pulses per band */
    short *pulse_vector,     /* o  : non-normalized pulse shapes */
    const short *sfm_start,        /* i  : indices of first coefficients in the bands */
    const short *sfm_end,          /* i  : indices of last coefficients in the bands */
    const short *sfmsize,          /* i  : band sizes */
    const short nb_sfm,            /* i  : total number of bands */
    const short *R,                /* i  : bitallocation per band (Q3)*/
    const short pvq_bits,          /* i  : number of bits avaiable */
    const short core               /* i  : core */
)
{
    short i, j;
    short band_bits, rc_bits, bits_left;
    short bit_adj, bit_pool = 0;
    short coded_bands, bands_to_code;
    short bits;
    short R_sort[NB_SFM]; /*Q3*/
    short is, i_sort[NB_SFM];
    short strict_bits;

    rc_enc_init(st, pvq_bits);
    bits = (pvq_bits - RC_BITS_RESERVED)<<3;

    bands_to_code = 0;
    for (i = 0; i < nb_sfm; i++)
    {
        if (R[i] > 0)
        {
            bands_to_code++;
        }
    }

    if (core == ACELP_CORE)
    {
        strict_bits = 1;
        srt_vec_ind (R, R_sort, i_sort, nb_sfm);
    }
    else
    {
        strict_bits = 0;
        for(i=0; i<nb_sfm; i++)
        {
            i_sort[i] = i;
        }
    }

    coded_bands = 0;
    for (i = 0; i < nb_sfm; i++)
    {
        is = i_sort[i];
        gopt[is] = 0;
        if(R[is] > 0)
        {
            /* Bit allocation adjustment */

            rc_bits = (rc_get_bits_f2(st->rc_num_bits, st->rc_range));
            bits_left = bits - rc_bits;

            if (coded_bands > 0)
            {
                bit_pool -= rc_bits;
            }

            bit_adj = bit_pool / min(3, bands_to_code-coded_bands);
            band_bits = (short) min(sfmsize[is]*MAX_PVQ_BITS_PER_COEFFICIENT, R[is]);
            band_bits = band_bits + bit_adj;
            band_bits = max(0,min(bits_left,band_bits));

            pvq_encode_band( st, &coefs_norm[sfm_start[is]], &pulse_vector[sfm_start[is]],
                             &npulses[is], &coefs_quant[sfm_start[is]], sfmsize[is], band_bits,
                             &bits_left, strict_bits);
            gopt[is] = dotp(coefs_quant+sfm_start[is], coefs_norm+sfm_start[is], sfmsize[is]) /
                       (dotp(coefs_quant+sfm_start[is], coefs_quant+sfm_start[is], sfmsize[is]) + 1e-15f);
            if (gopt[is] == 0.0f)
            {
                gopt[is] = 1e-10f;
            }
            /* Updates */
            coded_bands++;
            bit_pool += (short) (R[is]) + rc_bits;
        }
        else
        {
            for (j = sfm_start[is]; j < sfm_end[is]; j++)
            {
                coefs_quant[j] = 0.0f;
                pulse_vector[j] = 0;
            }
        }
    }

    rc_enc_finish(st);

    return;
}

/*---------------------------------------------------------------------*
 * pvq_core_enc()
 *
 * Main Generic Audio Encoder Routine
 *---------------------------------------------------------------------*/

short pvq_core_enc (
    Encoder_State *st,
    float coefs_norm[],
    float coefs_quant[],
    short bits_tot,                           /* total number of bits */
    short nb_sfm,
    const short *sfm_start,
    const short *sfm_end,
    const short *sfmsize,
    short *R,
    short *Rs,
    short *npulses,
    short *maxpulse,
    const short core
)
{
    short i;
    short  R_upd; /*Q3*/
    short  ord[NB_SFM_MAX];
    float  fg_pred[NB_SFM_MAX];
    short  pvq_bits;
    short  pulse_vector[L_FRAME48k];
    float gopt[NB_SFM];
    short gain_bits_array[NB_SFM];
    short gain_bits_tot;

    R_upd = bits_tot * 8;
    gain_bits_tot = assign_gain_bits( core, nb_sfm, sfmsize, R, gain_bits_array, &R_upd );
    pvq_bits = R_upd >> 3;
    pvq_encode_frame( st, coefs_norm, coefs_quant, gopt, npulses, pulse_vector,
                      sfm_start, sfm_end, sfmsize, nb_sfm, R, pvq_bits, core );
    bits_tot = pvq_bits + gain_bits_tot;



    if( Rs != NULL )
    {
        for(i=0; i<nb_sfm; i++)
        {
            Rs[i]   = Rs[i] * (npulses[i] > 0); /* Update Rs in case no pulses were assigned */
        }
    }

    for(i=0; i<nb_sfm; i++)
    {
        ord[i] = i;
        R[i]   = R[i] * (npulses[i] > 0); /* Update in case no pulses were assigned */
    }

    get_max_pulses( sfm_start, sfm_end, ord, npulses, nb_sfm, pulse_vector, maxpulse );

    /* Fine gain prediction */
    fine_gain_pred( sfm_start, sfm_end, sfmsize, ord, npulses, maxpulse, R, nb_sfm,
                    coefs_quant, pulse_vector, fg_pred, core);

    fine_gain_quant(st, ord, nb_sfm, gain_bits_array, fg_pred, gopt);

    apply_gain(ord, sfm_start, sfm_end, nb_sfm, fg_pred, coefs_quant);

    return bits_tot;
}


/*-------------------------------------------------------------------*
* encode_energies()
*
*
*--------------------------------------------------------------------*/

void encode_energies(
    Encoder_State *st,
    const float *coefs,
    short Np,
    short *dim_part,
    float *E_part,
    short *bits_part,
    short *g_part,
    short bits,
    short *bits_left,
    float enr,
    short dim,
    const short strict_bits
)
{
    short res;
    short alpha = 0;
    short i, j, l_Np, r_Np;
    short l_bits, r_bits, l_dim, r_dim;
    float l_enr, r_enr;
    short il, ir, c, res_alpha, res_c;
    short offset, rc_bits, used_bits;
    int sym_freq = 1, cum_freq, tot;
    short K_idx;
    short avg_bits;
    short dim_min, bit_diff, bit_min;
    short angle;

    l_Np = Np>>1;
    r_Np = Np-l_Np;

    l_enr = 0.0f;
    l_bits = 0;
    l_dim = 0;
    for(i=0; i<l_Np; i++)
    {
        l_dim += dim_part[i];
    }
    for(j = 0; j<l_dim; j++)
    {
        l_enr += coefs[j]*coefs[j];
    }
    r_enr = enr - l_enr;
    r_dim = dim - l_dim;

    res = get_angle_res(dim, bits);

    alpha = (short)floor(.5f+16384*0.63662f*atan2((float)sqrt(r_enr),(float)sqrt(l_enr)));

    rc_bits = (rc_get_bits_f2(st->rc_num_bits, st->rc_range));

    if (res!=1)
    {
        alpha = (alpha*res+8192)>>14;

        angle = atan2_fx(SQRT_DIM_fx[r_dim], SQRT_DIM_fx[l_dim]);  /* Replace atan2() by fixed point.*/
        angle = shl(angle, 1);
        angle = mult_r(angle, 20861);
        c = mult_r(res, angle);

        res_alpha = res-alpha;
        res_c = res-c;

        if(c == 0)
        {
            tot = res*(res+1) + 1;
            sym_freq = 2*(res-alpha) + 1;
            cum_freq = alpha*(2*(res+1)-alpha);
        }
        else if(c == res)
        {
            tot = res*(res+1) + 1;
            sym_freq = 2*alpha + 1;
            cum_freq = alpha*alpha;
        }
        else
        {
            tot = res*c*(res-c) + res+1;
            sym_freq = alpha <= c ? 2*alpha*res_c + 1 : 2*res_alpha*c + 1;
            cum_freq = alpha <= c ? alpha*((alpha-1)*res_c + 1) :
                       tot -(res+1) - res_alpha*(res_alpha+1)*c + alpha;
        }
        rc_encode(st, cum_freq, sym_freq, tot);
        alpha = (int)alpha*16384/res;
    }
    else
    {
        alpha = 8192;
    }

    used_bits = (rc_get_bits_f2(st->rc_num_bits, st->rc_range)) - rc_bits;

    bits -= used_bits;
    *bits_left -= used_bits;

    if (alpha == 0)
    {
        il = 32767;
        ir = 0;
        offset = -16384;
    }
    else if (alpha == 16384)
    {
        il = 0;
        ir = 32767;
        offset = 16384;
    }
    else
    {
        il = own_cos(alpha<<1);
        ir = own_cos((16384-alpha)<<1);
        offset = (log2_div(ir,il)+128)>>8;
    }

    for(i = 0; i<l_Np; i++)
    {
        g_part[i] = ((int)g_part[i] * il + 16384) >> 15;
    }

    for(i = l_Np; i<Np; i++)
    {
        g_part[i] = ((int)g_part[i] * ir + 16384) >> 15;
    }

    dim_min = dim_part[0];
    if(dim_min > 1)
    {
        avg_bits = bits/Np;
        K_idx = bits2pulses(dim_part[Np-1], avg_bits, strict_bits );
        bit_min = pulses2bits(dim_min, K_idx);

        bit_diff = avg_bits - bit_min;
        bit_diff = max(0,bit_diff);
    }
    else
    {
        bit_diff = 0;
    }

    l_bits = max(0, min(bits, (bits-r_dim*offset-bit_diff)/(r_dim/l_dim+1)));

    r_bits = bits-l_bits;

    if(l_Np > 1)
    {
        encode_energies( st, coefs, l_Np, dim_part, E_part, bits_part, g_part, l_bits, bits_left, l_enr, l_dim, strict_bits );
    }
    else
    {
        E_part[0] = l_enr;
        bits_part[0] = l_bits;
    }
    if(r_Np > 1)
    {
        encode_energies( st, &coefs[l_dim], r_Np, &dim_part[l_Np], &E_part[l_Np], &bits_part[l_Np], &g_part[l_Np], r_bits, bits_left, r_enr, r_dim, strict_bits );
    }
    else
    {
        E_part[1] = r_enr;
        bits_part[1] = r_bits;
    }

    return;
}

/*--------------------------------------------------------------------------*
 * calc_pvq_splits()
 *
 * Calculate the number of segments needed
 *--------------------------------------------------------------------------*/

static short calc_pvq_splits(          /* o  : Number of segments           */
    Encoder_State *st,                 /* i/o: Encoder state                */
    const short band_bits,             /* i  : Band bit rate                */
    const short sfmsize,               /* i  : Band width                   */
    const float *y,                    /* i  : Target vector                */
    short *bits                  /* o  : Consumed bits                */
)
{
    short Np;
    short Npart;
    short i,j,k;
    float E[MAX_SPLITS];
    float Emean;
    float tmp;
    float max_dev;

    Np = max(1,(short) ceil(band_bits/((32+SPLIT_COST)*8)));
    Npart = sfmsize / Np; /* Integer division */
    *bits = 0;

    /* Measure energy variation to determine if an additional split should be used */
    if ( Np < MAX_SPLITS && (band_bits - (8*sfmsize * THR_ADD_SPLIT ) > 0))
    {
        *bits = 8;
        Emean = 0;
        k = 0;
        for ( i = 0; i < Np; i++)
        {
            E[i] = EPSILON;
            for (j = 0; j < Npart; j++, k++)
            {
                E[i] += y[k]*y[k];
            }
            E[i] = (short)log2_i((int)E[i]);
            Emean += E[i];
        }
        Emean /= Np;

        max_dev = -1;
        for ( i = 0; i < Np; i++)
        {
            tmp = (float)fabs(E[i] - Emean);
            if ( tmp > max_dev )
            {
                max_dev = tmp;
            }
        }

        if ( max_dev > (32 - band_bits/(8*Np)) )
        {
            rc_enc_bits(st, 1, 1);
            Np += 1;
        }
        else
        {
            rc_enc_bits(st, 0, 1);
        }
    }

    /* Check constraints for number of segments */
    Np = max(Np, (short)(ceil((float)sfmsize/PVQ_MAX_BAND_SIZE)));
    Np = min(MAX_SPLITS, Np);
    Np = min((short)floor((float)sfmsize/MIN_BAND_SIZE), Np);

    return Np;
}


/*====================================================================================
    EVS Codec 3GPP TS26.443 Oct 20, 2015. Version 12.4.0
  ====================================================================================*/

#include "options.h"
#include "prot.h"
#include "rom_com.h"
#include "prot.h"
#include "math.h"

/*-------------------------------------------------------------------*
 * Function pvq_encode()                                             *
 *                                                                   *
 * PVQ search algorithm: projection to K-1 pyramid and greedy search *
 *-------------------------------------------------------------------*/

void pvq_encode(
    Encoder_State *st,
    const float *x,         /* i:   vector to quantize               */
    short *y,               /* o:   quantized vector (non-scaled int)*/
    float *xq,              /* o:   quantized vector (scaled float)  */
    const short pulses,     /* i:   number of allocated pulses       */
    const short dim,        /* i:   Length of vector                 */
    const float gain        /* i:   Gain                             */
)
{
    short i,imax;
    short xsign[PVQ_MAX_BAND_SIZE];
    short pulse_tot;
    float xabs[PVQ_MAX_BAND_SIZE];
    float xsum,proj_fac;
    float yy,xy;
    float yy_tmp,xy2_tmp;
    float cmax_num,cmax_den;
    float gain_fac;
    PvqEntry entry;
    short inp_short[PVQ_MAX_BAND_SIZE]; /* tmp vector as in FIP */
    /* Separate sign and calculate sum of abs vector */
    xsum = 0;
    for( i = 0; i < dim; i++)
    {
        xabs[i] = (float)fabs(x[i]);
        xsign[i] = (short)sign(x[i]);
        xsum += (float)xabs[i];
        y[i] = 0;
    }

    if(xsum != 0 && gain !=0 )
    {
        proj_fac = (pulses - 1)/xsum;
        pulse_tot = 0;

        yy = 0;
        xy = 0;

        /* Find a start position on a lower sub pyramid */
        if(pulses > (dim>>1) )
        {
            for( i = 0; i < dim ; i++)
            {
                y[i] = (short)floor(xabs[i] * proj_fac);
                pulse_tot += (short)y[i];
                yy += y[i] * y[i];
                xy += xabs[i] * y[i];
            }
        }
        /* Now run ACELP-like full corrsq/energy search */
        yy *= 0.5f;
        while( pulse_tot < pulses )
        {
            imax = 0;
            cmax_num = -1e15f;
            cmax_den = 0;

            yy += 0.5f;

            for(i = 0; i < dim; i++)
            {
                xy2_tmp = xy + xabs[i];
                xy2_tmp *= xy2_tmp;
                yy_tmp = yy + y[i];

                if(xy2_tmp * cmax_den > yy_tmp * cmax_num)
                {
                    cmax_num = xy2_tmp;
                    cmax_den = yy_tmp;
                    imax = i;
                }

            }

            xy += xabs[imax];
            yy += y[imax];
            y[imax]++;
            pulse_tot++;
        }
        yy *= 2.0f;
    }
    else
    {
        /*spread load between encoder indexing and decoder deindexing, no search */
        pulse_tot = pulses;
        yy = 0.0f;
        if( dim > 1 )
        {
            y[0]     =   (int)(pulses>>1);
            y[dim-1] = (int)-(pulses-(pulses>>1));
            yy        =   (float)y[0]*(float)y[0] + (float)y[dim-1]*(float)y[dim-1] ;
        }
        else
        {
            y[0]     =   (int) pulses ;
            yy       =   (float)pulses*(float)pulses;
        }
    }


    /* Apply scaling, always at least one pulse so no div-by-zero*/
    gain_fac = gain * 1.0f/(float)sqrt(yy);
    for( i = 0; i < dim; i++)
    {
        y[i]  = y[i] * xsign[i];
        xq[i] = y[i] * gain_fac;
    }

    /* Index vector and send to range encoder */
    for(i = 0; i < dim; i++)
    {
        inp_short[i] = (short)(y[i]);
    }
    entry = mpvq_encode_vec(inp_short, dim, pulses);

    if(dim != 1)
    {
        rc_enc_bits(st, (unsigned int)entry.lead_sign_ind, 1);
        rc_enc_uniform(st, entry.index, entry.size);
    }
    else
    {
        rc_enc_bits(st, (unsigned int)entry.lead_sign_ind, 1);
    }

    return;

}

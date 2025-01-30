/*====================================================================================
    EVS Codec 3GPP TS26.443 Oct 20, 2015. Version 12.4.0
  ====================================================================================*/

#include "options.h"
#include "rom_com.h"
#include "prot.h"

/*--------------------------------------------------------------------------
 * normalizecoefs()
 *
 * Normalize MDCT coefficients with quantized norms
 *--------------------------------------------------------------------------*/

void normalizecoefs(
    float *coefs,                     /* i/o: MDCT coefficients                   */
    const short *ynrm,                      /* i  : quantization indices for norms      */
    const short num_bands,                  /* i  : Number of bands                     */
    const short *band_start,                /* i  : Start of bands                      */
    const short *band_end                   /* i  : End of bands                        */
)
{
    short i, band;
    float normq;

    for (band = 0; band < num_bands; band++)
    {
        normq = dicn_inv[ynrm[band]];

        for (i = band_start[band]; i < band_end[band]; i++)
        {
            coefs[i] *= normq;
        }
    }

    return;
}

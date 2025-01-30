/*                                                 Version 3.01 - 31.Jan.2000
=============================================================================

                          U    U   GGG    SSS  TTTTT
                          U    U  G      S       T
                          U    U  G  GG   SSS    T
                          U    U  G   G      S   T
                           UUUU    GGG    SSS    T

                   ========================================
                    ITU-T - USER'S GROUP ON SOFTWARE TOOLS
                   ========================================


       =============================================================
       COPYRIGHT NOTE: This source code, and all of its derivations,
       is subject to the "ITU-T General Public License". Please have
       it  read  in    the  distribution  disk,   or  in  the  ITU-T
       Recommendation G.191 on "SOFTWARE TOOLS FOR SPEECH AND  AUDIO 
       CODING STANDARDS".
       =============================================================


MODULE:	G711.C, G.711 ENCODING/DECODING FUNCTIONS

ORIGINAL BY:

     Simao Ferraz de Campos Neto          Rudolf Hofmann
     CPqD/Telebras                        PHILIPS KOMMUNIKATIONS INDUSTRIE AG
     DDS/Pr.11                            Kommunikationssysteme
     Rd. Mogi Mirim-Campinas Km.118       Thurn-und-Taxis-Strasse 14
     13.085 - Campinas - SP (Brazil)      D-8500 Nuernberg 10 (Germany)

     Phone : +55-192-39-6396              Phone : +49 911 526-2603
     FAX   : +55-192-53-4754              FAX   : +49 911 526-3385
     EMail : tdsimao@venus.cpqd.ansp.br   EMail : HF@PKINBG.UUCP


FUNCTIONS:

alaw_compress: ... compands 1 vector of linear PCM samples to A-law;
                   uses 13 Most Sig.Bits (MSBs) from input and 8 Least
                   Sig. Bits (LSBs) on output.

alaw_expand: ..... expands 1 vector of A-law samples to linear PCM;
                   use 8 Least Sig. Bits (LSBs) from input and
                   13 Most Sig.Bits (MSBs) on output.

ulaw_compress: ... compands 1 vector of linear PCM samples to u-law;
                   uses 14 Most Sig.Bits (MSBs) from input and 8 Least
                   Sig. Bits (LSBs) on output.

ulaw_expand: ..... expands 1 vector of u-law samples to linear PCM
                   use 8 Least Sig. Bits (LSBs) from input and
                   14 Most Sig.Bits (MSBs) on output.

PROTOTYPES: in g711.h

HISTORY:
Apr/91       1.0   First version of the G711 module
10/Dec/1991  2.0   Break-up in individual functions for A,u law;
                   correction of bug in compression routines (use of 1
                   and 2 complement); Demo program inside module.
08/Feb/1992  3.0   Demo as separate file;
31/Jan/2000  3.01  Updated documentation text; no change in functions 
                   <simao.campos@labs.comsat.com>
=============================================================================
*/

/*
 *	.......... I N C L U D E S ..........
 */

/* Global prototype functions */
#include "g711.h"

/*
 *	.......... F U N C T I O N S ..........
 */
 
/*
int G711_mode(short law_mode)
{
	int em = 0;
	
	
	if (law_mode == A_LAW)
	{
		compress = alaw_compress;
		expand = alaw_expand;
	}
	else if (law_mode== u_LAW)
	{
		compress = ulaw_compress;
		expand = ulaw_expand;
	}
	else
		em = 1;

	return em;
}
*/


int	G711_enc_block_size(long lseg)
{
	int em = 0;
	long enc_block_size = 0;
	
	if(lseg != 0)
		enc_block_size = lseg;
	else
		em = 1;
		
	return em;
}

int	G711_dec_block_size(long lseg)
{
	int em = 0;
	long dec_block_size = 0;
	
	if(lseg != 0)
		dec_block_size = lseg;
	else
		em = 1;
		
	return em;
}

/*
void G711_compress(short *linbuf, unsigned char *logbuf)
{
	compress(enc_block_size, linbuf, logbuf);
}

void G711_expand(unsigned char *logbuf, short *linbuf, long lseg)
{
	expand(dec_block_size, logbuf, linbuf);
}
*/
/* ................... Begin of alaw_compress() ..................... */
/*
  ==========================================================================

   FUNCTION NAME: alaw_compress

   DESCRIPTION: ALaw encoding rule according ITU-T Rec. G.711.

   PROTOTYPE: void alaw_compress(long lseg, short *linbuf, short *logbuf)

   PARAMETERS:
     lseg:	(In)  number of samples
     linbuf:	(In)  buffer with linear samples (only 12 MSBits are taken
                      into account)
     logbuf:	(Out) buffer with compressed samples (8 bit right justified,
                      without sign extension)

   RETURN VALUE: none.

   HISTORY:
   10.Dec.91	1.0	Separated A-law compression function

  ==========================================================================
*/
void alaw_compress(sG711Enc_INFO *sG711Enc)
{
	short	ix, iexp;
	long	n;
	short	Stmp;
	short	*linbuf;
	unsigned char *logbuf;

	linbuf = sG711Enc->p_in;
	logbuf = sG711Enc->p_out;

	for (n = 0; n < sG711Enc->frame_length; n++)
	{
		ix = linbuf[n] < 0		/* 0 <= ix < 2048 */
		? (~linbuf[n]) >> 4	/* 1's complement for negative values */
		: (linbuf[n]) >> 4;

		/* Do more, if exponent > 0 */
		if (ix > 15)		/* exponent=0 for ix <= 15 */
		{
			iexp = 1;			/* first step: */
			while (ix > 16 + 15)	/* find mantissa and exponent */
			{
				ix >>= 1;
				iexp++;
			}
			ix -= 16;			/* second step: remove leading '1' */

			ix += iexp << 4;		/* now compute encoded value */
		}
		if (linbuf[n] >= 0)
			ix |= (0x0080);		/* add sign bit */

		Stmp = ix ^ (0x0055);	/* toggle even bits */
		logbuf[n] = (unsigned char)Stmp;
	}
}
/* ................... End of alaw_compress() ..................... */


/* ................... Begin of alaw_expand() ..................... */
/*
  ==========================================================================

   FUNCTION NAME: alaw_expand

   DESCRIPTION: ALaw decoding rule according ITU-T Rec. G.711.

   PROTOTYPE: void alaw_expand(long lseg, short *logbuf, short *linbuf)

   PARAMETERS:
     lseg:	(In)  number of samples
     logbuf:	(In)  buffer with compressed samples (8 bit right justified,
                      without sign extension)
     linbuf:	(Out) buffer with linear samples (13 bits left justified)

   RETURN VALUE: none.

   HISTORY:
   10.Dec.91	1.0	Separated A-law expansion function

  ============================================================================
*/
void alaw_expand(sG711Dec_INFO *sG711Dec)
{
	short	ix, mant, iexp;
	long	n;
	short	Stmp;
	short	*linbuf;
	unsigned char	*logbuf;

	logbuf = sG711Dec->p_in;
	linbuf = sG711Dec->p_out;

	for (n = 0; n < sG711Dec->frame_length; n++)
	{
		Stmp = (short)logbuf[n];
		ix = Stmp ^ (0x0055);	/* re-toggle toggled bits */

		ix &= (0x007F);		/* remove sign bit */
		iexp = ix >> 4;		/* extract exponent */
		mant = ix & (0x000F);	/* now get mantissa */
		if (iexp > 0)
			mant = mant + 16;		/* add leading '1', if exponent > 0 */

		mant = (mant << 4) + (0x0008);	/* now mantissa left justified and */
		/* 1/2 quantization step added */
		if (iexp > 1)		/* now left shift according exponent */
			mant = mant << (iexp - 1);

		linbuf[n] = logbuf[n] > 127	/* invert, if negative sample */
		? mant
		: -mant;
	}
}
/* ................... End of alaw_expand() ..................... */


/* ................... Begin of ulaw_compress() ..................... */
/*
  ==========================================================================

   FUNCTION NAME: ulaw_compress

   DESCRIPTION: Mu law encoding rule according ITU-T Rec. G.711.

   PROTOTYPE: void ulaw_compress(long lseg, short *linbuf, short *logbuf)

   PARAMETERS:
     lseg:	(In)  number of samples
     linbuf:	(In)  buffer with linear samples (only 12 MSBits are taken
                      into account)
     logbuf:	(Out) buffer with compressed samples (8 bit right justified,
                      without sign extension)

   RETURN VALUE: none.

   HISTORY:
   10.Dec.91	1.0	Separated mu-law compression function

  ==========================================================================
*/
void ulaw_compress(sG711Enc_INFO *sG711Enc)
{
	long	n;            /* samples's count */
	short	i;		/* aux.var. */
	short	absno;	/* absolute value of linear (input) sample */
	short	segno;	/* segment (Table 2/G711, column 1) */
	short	low_nibble;	/* low  nibble of log companded sample */
	short	high_nibble;	/* high nibble of log companded sample */
	short	Stmp;
	short	*linbuf;
	unsigned char *logbuf;

	linbuf = sG711Enc->p_in;
	logbuf = sG711Enc->p_out;
	for (n = 0; n < sG711Enc->frame_length; n++)
	{
		/* -------------------------------------------------------------------- */
		/* Change from 14 bit left justified to 14 bit right justified */
		/* Compute absolute value; adjust for easy processing */
		/* -------------------------------------------------------------------- */
		absno = linbuf[n] < 0	/* compute 1's complement in case of  */
		? ((~linbuf[n]) >> 2) + 33/* negative samples */
		: ((linbuf[n]) >> 2) + 33;/* NB: 33 is the difference value */
		/* between the thresholds for */
		/* A-law and u-law. */
		if (absno > (0x1FFF))	/* limitation to "absno" < 8192 */
			absno = (0x1FFF);

		/* Determination of sample's segment */
		i = absno >> 6;
		segno = 1;
		while (i != 0)
		{
			segno++;
			i >>= 1;
		}

		/* Mounting the high-nibble of the log-PCM sample */
		high_nibble = (0x0008) - segno;

		/* Mounting the low-nibble of the log PCM sample */
		low_nibble = (absno >> segno)	/* right shift of mantissa and */
		& (0x000F);		/* masking away leading '1' */
		low_nibble = (0x000F) - low_nibble;

		/* Joining the high-nibble and the low-nibble of the log PCM sample */
		Stmp = (high_nibble << 4) | low_nibble;

		/* Add sign bit */
		if (linbuf[n] >= 0)
		{
			Stmp = Stmp | (0x0080);
		}
		logbuf[n]= (unsigned char)Stmp;
	}
}
/* ................... End of ulaw_compress() ..................... */



/* ................... Begin of ulaw_expand() ..................... */
/*
  ==========================================================================

   FUNCTION NAME: ulaw_expand

   DESCRIPTION: Mu law decoding rule according ITU-T Rec. G.711.

   PROTOTYPE: void ulaw_expand(long lseg, short *logbuf, short *linbuf)

   PARAMETERS:
     lseg:	(In)  number of samples
     logbuf:	(In)  buffer with compressed samples (8 bit right justified,
                      without sign extension)
     linbuf:	(Out) buffer with linear samples (14 bits left justified)

   RETURN VALUE: none.

   HISTORY:
   10.Dec.91	1.0	Separated mu law expansion function

  ============================================================================
*/

void ulaw_expand(sG711Dec_INFO *sG711Dec)
{
	long            n;		/* aux.var. */
	short           segment;	/* segment (Table 2/G711, column 1) */
	short           mantissa;	/* low  nibble of log companded sample */
	short           exponent;	/* high nibble of log companded sample */
	short           sign;		/* sign of output sample */
	short           step;
	short			  Stmp;
	short	*linbuf;
	unsigned char	*logbuf;

	logbuf = sG711Dec->p_in;
	linbuf = sG711Dec->p_out;

	for (n = 0; n < sG711Dec->frame_length; n++)
	{
		Stmp = (short)logbuf[n];
		sign = Stmp < (0x0080)	/* sign-bit = 1 for positiv values */
		? -1
		: 1;
		mantissa = ~Stmp;	/* 1's complement of input value */
		exponent = (mantissa >> 4) & (0x0007);	/* extract exponent */
		segment = exponent + 1;	/* compute segment number */
		mantissa = mantissa & (0x000F);	/* extract mantissa */

		/* Compute Quantized Sample (14 bit left justified!) */
		step = (4) << segment;	/* position of the LSB */
		/* = 1 quantization step) */
		linbuf[n] = sign *		/* sign */
		(((0x0080) << exponent)	/* '1', preceding the mantissa */
		+ step * mantissa	/* left shift of mantissa */
		+ step / 2		/* 1/2 quantization step */
		- 4 * 33
		);
	}
}
/* ................... End of ulaw_expand() ..................... */

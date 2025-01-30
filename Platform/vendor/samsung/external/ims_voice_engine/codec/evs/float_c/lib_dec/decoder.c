/*====================================================================================
    EVS Codec 3GPP TS26.443 Aug 18, 2015. Version 12.3.0
  ====================================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "options.h"
#include "prot.h"
#include "cnst.h"
#include "rom_com.h"
#include "g192.h"
#include "sEVS.h"
#include "mime.h"
#ifndef _WIN32
#ifndef DS5_SIMU
#include <netinet/in.h>
#include <stdint.h>
#endif
#else
#include <Winsock2.h>
#endif
#include "jbm_jb4sb.h"

/*------------------------------------------------------------------------------------------*
 * Global variables
 *------------------------------------------------------------------------------------------*/
//long frame;                 /* Counter of frames */



/*------------------------------------------------------------------------------------------*
 * Main decoder function
 *------------------------------------------------------------------------------------------*/

int dec_main( int argc, char *argv[] )
{
    FILE *f_stream;                     /* input bitstream file */
    FILE *f_synth;                      /* output synthesis file */
    short output_frame, dec_delay, zero_pad;
    short quietMode = 0;
    short noDelayCmp = 0;
    short data[L_FRAME48k];             /* 'short' buffer for output synthesis */
#ifdef SUPPORT_JBM_TRACEFILE
    char *jbmTraceFileName = NULL;      /* VOIP tracefile name */
#endif
    char *jbmFECoffsetFileName = NULL;  /* VOIP tracefile name */
	long frame = 0;                 /* Counter of frames */
#ifndef ADJUST_API
	float output[L_FRAME48k];			/* 'float' buffer for output synthesis */
	Decoder_State *st;					/* decoder state structure */
#else
	UWord8 header;
	Word16 qbit, num_bits;
	unsigned char input_buf[(MAX_BITS_PER_FRAME + 7) >> 3]; // this buffer is used for store the input streams
	void *st_handler = NULL;
	sEVS_Dec_Struct dec_struct;
	dec_struct.p_in = input_buf;
	dec_struct.p_out= data;
#endif



    /*------------------------------------------------------------------------------------------*
     * Allocate memory for static variables
     * Processing of command-line parameters
     * Decoder initialization
     *------------------------------------------------------------------------------------------*/
#ifndef ADJUST_API
    if ( (st = (Decoder_State *) malloc( sizeof(Decoder_State) ) ) == NULL )
    {
        fprintf(stderr, "Can not allocate memory for decoder state structure\n");
        exit(-1);
    }

    io_ini_dec( argc, argv, &f_stream, &f_synth,
                &quietMode, &noDelayCmp, st,
#ifdef SUPPORT_JBM_TRACEFILE
                &jbmTraceFileName,
#endif
                &jbmFECoffsetFileName
              );
	/*------------------------------------------------------------------------------------------*
	 * Allocate memory for static variables
	 * Decoder initialization
	 *------------------------------------------------------------------------------------------*/
	init_decoder( st );
	reset_indices_dec( st );
	/* output frame length */
	output_frame = (short)(st->output_Fs / 50);

#else     //ADJUST_API
	io_ini_dec( argc, argv, &f_stream, &f_synth,
				&quietMode, &noDelayCmp, &dec_struct, 
#ifdef SUPPORT_JBM_TRACEFILE
				&jbmTraceFileName,
#endif
				&jbmFECoffsetFileName
			  );

	st_handler = sEVSCreateDec( &dec_struct );
	/* output frame length */
	output_frame = (short)(dec_struct.output_Fs / 50);

#endif    //ADJUST_API

    /*------------------------------------------------------------------------------------------*
     * VOIP client
     *------------------------------------------------------------------------------------------*/
#ifndef ADJUST_API
    if( st->Opt_VOIP )
    {
        if( decodeVoip( st, f_stream, f_synth,
#ifdef SUPPORT_JBM_TRACEFILE
                        jbmTraceFileName,
#endif
                        jbmFECoffsetFileName,
                        quietMode
                      ) != 0 )
        {
            return -1;
        }
    }
#else
    if( dec_struct.Opt_VOIP )
    {
        if( sEVS_Dec_Voip_Frame( st_handler, f_stream, f_synth,
#ifdef SUPPORT_JBM_TRACEFILE
                        jbmTraceFileName,
#endif
                        jbmFECoffsetFileName,
                        quietMode
                      ) != 0 )
        {
            return -1;
        }
    }

#endif
    /*------------------------------------------------------------------------------------------*
     * Regular EVS decoder with ITU-T G.192 bitstream
     *------------------------------------------------------------------------------------------*/

    else
    {
        /*------------------------------------------------------------------------------------------*
         * Allocate memory for static variables
         * Decoder initialization
         *------------------------------------------------------------------------------------------*/

        srand( (unsigned int) time(0) );

        if( noDelayCmp == 0 )
        {
            /* calculate the delay compensation to have the decoded signal aligned with the original input signal */
            /* the number of first output samples will be reduced by this amount */
#ifndef ADJUST_API
			dec_delay = NS2SA(st->output_Fs, get_delay(DEC, st->output_Fs));
#else
			dec_delay = NS2SA(dec_struct.output_Fs, get_delay(DEC, dec_struct.output_Fs));
#endif
        }
        else
        {
            dec_delay = 0;
        }
        zero_pad = dec_delay;

        /*------------------------------------------------------------------------------------------*
         * Loop for every packet (frame) of bitstream data
         * - Read the bitstream packet
         * - Run the decoder
         * - Write the synthesized signal into output file
         *------------------------------------------------------------------------------------------*/

        if( quietMode == 0 )
        {
            fprintf( stdout, "\n------ Running the decoder ------\n\n" );
            fprintf( stdout, "Frames processed:       " );
        }
        else
        {
            fprintf( stdout, "\n-- Start the decoder (quiet mode) --\n\n" );
        }

#ifndef ADJUST_API
        while( st->bitstreamformat==G192 ? read_indices( st, f_stream, 0 ) : read_indices_mime( st, f_stream, 0) )
#else
		while(1)
#endif
        {
#ifndef ADJUST_API
            /* run the main decoding routine */
            if ( st->codec_mode == MODE1 )
            {
                if ( st->Opt_AMR_WB )
                {
                    amr_wb_dec( st, output );
                }
                else
                {
                    evs_dec( st, output, FRAMEMODE_NORMAL );
                }
            }
            else
            {
                if( !st->bfi )
                {
                    evs_dec( st, output, FRAMEMODE_NORMAL );
                }
                else
                {
                    evs_dec( st, output, FRAMEMODE_MISSING );
                }
            }

			/* convert 'float' output data to 'short' */
            syn_output( output, output_frame, data );
			/* increase the counter of initialization frames */
            if( st->ini_frame < MAX_FRAME_COUNTER )
            {
                st->ini_frame++;
            }
#else
			if ( fread( &header, sizeof(UWord8), 1, f_stream ) != 1 )
			{
				if( ferror( f_stream ) )
				{
					/* error during reading */
					fprintf(stderr, "\nError reading the bitstream !");
					exit(-1);
				}
				else
				{
					/* end of file reached */
					break;
				}
			}

			if( dec_struct.amrwb_rfc4867_flag != 0 )
			{
				/*	 RFC 4867
				5.3 ....
				Each stored speech frame starts with a one-octet frame header with
				the following format:
				0 1 2 3 4 5 6 7
				+-+-+-+-+-+-+-+-+
				|P| FT	  |Q|P|P|
				+-+-+-+-+-+-+-+-+
				The FT field and the Q bit are defined in the same way as in
				Section 4.3.2. The P bits are padding and MUST be set to 0, and MUST be ignored. */

				dec_struct.isAMRWB_IOmode	 = 1;
				qbit			 = (header>>2)&0x01 ;		  /* b2 bit 	  (b7 is the F bit ) */
				dec_struct.bfi = !qbit;
				dec_struct.core_mode  = ((header>>3) & 0x0F);	   /*  b6..b3	   */
				dec_struct.dec_total_brate = AMRWB_IOmode2rate[dec_struct.core_mode];   /* get the frame length from the header */
			}
			else
			{
				/*0 1 2 3 4 5 6 7	MS-bit ---> LS-bit
				 +-+-+-+-+-+-+-+-+
				 |H|F|E|x| brate |
				 +-+-+-+-+-+-+-+-+
				  where :
					"E|x|  brate "	is the 6 bit "FT" -field
					 x is unused	if E=0, (should be 0 )
					 x is the q-bit if E=1, q==1(good), Q==0(bad, maybe bit errors in payload )
					 H,F  always   0 in RTP format.
				*/
				dec_struct.isAMRWB_IOmode = (header & 0x20) > 0;	/* get EVS mode-from header */ /*	 b2   */
				dec_struct.core_mode	   = (header & 0x0F);		 /* b4,b5,b6,b7 */

				if( dec_struct.isAMRWB_IOmode )
				{
					qbit = (header & 0x10) > 0; 	 /* get Q bit,	  valid for IO rates */ /* b3 */
					dec_struct.dec_total_brate = AMRWB_IOmode2rate[ dec_struct.core_mode ];
				}
				else
				{
					qbit = 1;  /* assume good q_bit for the unused EVS-mode bit,	complete ToC validity checked later */
					dec_struct.dec_total_brate = PRIMARYmode2rate[ dec_struct.core_mode ];
				}
				dec_struct.bfi = !qbit;
			}

			num_bits = (Word16)(dec_struct.dec_total_brate/50);

			/* Check correctness of ToC headers  */
			if( dec_struct.amrwb_rfc4867_flag == 0 )
			{
				/* EVS ToC header (FT field(b2-b7), H bit (b0),    F bit (b1)  ,  (EVS-modebit(b2)=0  unused(Qbit)(b3)==0)	 */
				if ( (dec_struct.isAMRWB_IOmode == 0) &&  ((num_bits < 0)	||	((header & 0x80) > 0) || ((header & 0x40) > 0)	|| (header & 0x30) != 0x00 )  )
				{
					/* incorrect FT header */
					fprintf(stderr, "\nError in EVS  FT ToC header(%02x) ! ",header);
					exit(-1);
				}
				else if( (dec_struct.isAMRWB_IOmode != 0) && ( (num_bits < 0) ||  ((header & 0x80) > 0) || ((header & 0x40) > 0) )  )	/* AMRWBIO */
				{
					/* incorrect IO FT header */
					fprintf(stderr, "\nError in EVS(AMRWBIO)  FT ToC header(%02x) ! ",header);
				}
			}
			else
			{
				/* legacy AMRWB ToC, is only using	Padding bits which MUST be ignored */
				if ( num_bits < 0  )
				{
					/* incorrect FT header */
					fprintf(stderr, "\nError in AMRWB RFC4867  Toc(FT)	header(%02x) !", header);
					exit(-1);
				}
			}

			/* read serial stream of indices from file to the local buffer */
			if(fread( dec_struct.p_in, sizeof(UWord8), (num_bits + 7)>>3, f_stream )!= ((num_bits + 7)>>3))
				break;
			sEVSDecFrame(st_handler, &dec_struct);
#endif

            /* write the synthesized signal into output file */
            /* do final delay compensation */
            if ( dec_delay == 0 )
            {
                fwrite( data, sizeof(short), output_frame, f_synth );
            }
            else
            {
                if ( dec_delay <= output_frame )
                {
                    fwrite( &data[dec_delay], sizeof(short), output_frame - dec_delay, f_synth );
                    dec_delay = 0;
                }
                else
                {
                    dec_delay -= output_frame;
                }
            }

            frame++;
            if( quietMode == 0 )
            {
                fprintf( stdout, "%-8ld\b\b\b\b\b\b\b\b", frame );
            }



        }

        fflush( stderr );
        if (quietMode == 0)
        {
            fprintf( stdout, "\n\n" );
            fprintf(stdout, "Decoding finished\n\n");
        }
        else
        {
            fprintf(stdout, "Decoding of %ld frames finished\n\n", frame);
        }
        fprintf( stdout, "\n\n" );

        /* add zeros at the end to have equal length of synthesized signals */
        set_s( data, 0, zero_pad );
        fwrite( data, sizeof(short), zero_pad, f_synth );
#ifndef ADJUST_API
		destroy_decoder( st );
#endif
		}
#ifndef ADJUST_API
		free( st );
#else
		sEVSDeleteDec(st_handler);
#endif

    fclose( f_synth );
    fclose( f_stream );

    return 0;
}

Word16 rate2EVSmode_(
    Word32 rate                    /* i: bit rate */
)
{
    switch ( rate )
    {
    /* EVS Primary modes */
    case FRAME_NO_DATA :
        return NO_DATA;
    case SID_2k40      :
        return PRIMARY_SID;
    case PPP_NELP_2k80 :
        return PRIMARY_2800;
    case ACELP_7k20    :
        return PRIMARY_7200;
    case ACELP_8k00    :
        return PRIMARY_8000;
    case ACELP_9k60    :
        return PRIMARY_9600;
    case ACELP_13k20   :
        return PRIMARY_13200;
    case ACELP_16k40   :
        return PRIMARY_16400;
    case ACELP_24k40   :
        return PRIMARY_24400;
    case ACELP_32k     :
        return PRIMARY_32000;
    case ACELP_48k     :
        return PRIMARY_48000;
    case ACELP_64k     :
        return PRIMARY_64000;
    case HQ_96k        :
        return PRIMARY_96000;
    case HQ_128k       :
        return PRIMARY_128000;
    default            :
        return 0;//rate2AMRWB_IOmode(rate)
    }
}

static Word16 rate2AMRWB_IOmode_(
	Word32 rate                    /* i: bit rate */
)
{
	switch (rate)
	{
		/* EVS AMR-WB IO modes */
		case SID_1k75:
			return AMRWB_IO_SID;
		case ACELP_6k60:
			return AMRWB_IO_6600;
		case ACELP_8k85:
			return AMRWB_IO_8850;
		case ACELP_12k65:
			return AMRWB_IO_1265;
		case ACELP_14k25:
			return AMRWB_IO_1425;
		case ACELP_15k85:
			return AMRWB_IO_1585;
		case ACELP_18k25:
			return AMRWB_IO_1825;
		case ACELP_19k85:
			return AMRWB_IO_1985;
		case ACELP_23k05:
			return AMRWB_IO_2305;
		case ACELP_23k85:
			return AMRWB_IO_2385;
		default:
			return -1;
	}
 }
int  ReadVoipFrame_compact(FILE *ft_stream,
							   unsigned char *serial,
							   unsigned short *rtpSequenceNumber,
							   unsigned int *rtpTimeStamp,
							   unsigned int *rcvTime_ms)
{
    unsigned int   rtpPacketSize;
    unsigned short rtpPacketHeaderPart1;
    unsigned int   ssrc;
    unsigned short rtpPayloadG192[2];
    unsigned short rtpPayloadSize;
	short temp[2560+2];
	int i;
    /* RTP packet size */
    if(fread(&rtpPacketSize, sizeof(rtpPacketSize), 1, ft_stream) != 1)
        return 5;
    if(rtpPacketSize <= 12)
    {
        fprintf(stderr, "RTP Packet size too small: %ud\n", rtpPacketSize);
        return 5;
    }
    /* RTP packet arrival time */
    if(fread(rcvTime_ms, sizeof(*rcvTime_ms), 1, ft_stream) != 1)
        return 5;
    /* RTP packet header (part without sequence number) */
    if(fread(&rtpPacketHeaderPart1, sizeof(rtpPacketHeaderPart1), 1, ft_stream) != 1)
        return 5;
    if(rtpPacketHeaderPart1 != 22)
    {
        fprintf(stderr, "Unexpected RTP Packet header\n");
        return 5;
    }
    /* RTP sequence number */
    if(fread(rtpSequenceNumber, sizeof(*rtpSequenceNumber), 1, ft_stream) != 1)
        return 5;
#ifndef DS5_SIMU 
    *rtpSequenceNumber = ntohs(*rtpSequenceNumber);
#else
    *rtpSequenceNumber = t_ntohs(*rtpSequenceNumber);
#endif
    /* RTP timestamp */
    if(fread(rtpTimeStamp, sizeof(*rtpTimeStamp), 1, ft_stream) != 1)
        return 5;
#ifndef DS5_SIMU 
    *rtpTimeStamp = ntohl(*rtpTimeStamp);
#else
    *rtpTimeStamp = t_ntohl(*rtpTimeStamp);
#endif
    /* RTP ssrc */
    if(fread(&ssrc, sizeof(ssrc), 1, ft_stream) != 1)
        return 5;

    /* RTP payload size */
    rtpPayloadSize = rtpPacketSize - 12;
    if(rtpPayloadSize <= 2)
    {
        fprintf(stderr, "RTP payload size too small: %u\n", rtpPayloadSize);
        return 5;
    }
    /* RTP payload */
    if(fread(rtpPayloadG192, sizeof(short), 2, ft_stream) != 2)
    {
        fprintf(stderr, "Premature end of file, cannot read G.192 header\n");
        return 5;
    }
    if(rtpPayloadG192[0] != 0x6B21)
    {
        fprintf(stderr, "G192_SYNC_WORD missing from RTP payload!");
        return 5;
    }
	temp[0] = rtpPayloadG192[0];
    temp[1] = rtpPayloadG192[1];
    if(temp[1] == 0u || temp[1] + 2u != rtpPayloadSize || temp[1] > 2560)
    {
        fprintf(stderr, "error in parsing RTP payload: rtpPayloadSize=%u nBits=%d",
                rtpPayloadSize, temp[1]);
        return 5;
    }
    if( fread(&temp[2], sizeof(short), temp[1], ft_stream) != (unsigned short)temp[1])
    {
        fprintf(stderr, "Premature end of file, cannot read G.192 payload\n");
        return 5;
    }
	// make TOC + MIME data , here is only for EVS primary mode(not SID mode).
	serial[0] = 0;
	serial[0] = (UWord8)(rate2EVSmode_(temp[1] * 50));

    for(i=0; i<temp[1]; i++)
    {
        unsigned char bit = (temp[i+2] == 0x0081) ? 1 : 0;
        unsigned char bitinbyte = bit << (7- (i&0x7));
        if(!(i&0x7))
            serial[1+(i>>3)] = 0;
        serial[1+(i>>3)] |= bitinbyte;
    }	
	
	return 0;
	}


/*------------------------------------------------------------------------------------------*
 * Main decoder function for voip
 *------------------------------------------------------------------------------------------*/

int dec_main_voip( int argc, char *argv[] )
{
	FILE *f_stream; 					/* input bitstream file */
	FILE *f_synth;						/* output synthesis file */
	short output_frame, dec_delay, zero_pad;
	short quietMode = 0;
	short noDelayCmp = 0;
	short data[L_FRAME48k]; 			/* 'short' buffer for output synthesis */
#ifdef SUPPORT_JBM_TRACEFILE
	char *jbmTraceFileName = NULL;		/* VOIP tracefile name */
#endif
	char *jbmFECoffsetFileName = NULL;	/* VOIP tracefile name */
	long frame = 0;                 /* Counter of frames */
#ifndef ADJUST_API
	float output[L_FRAME48k];			/* 'float' buffer for output synthesis */
	Decoder_State *st;					/* decoder state structure */
#else
	UWord8 header;
	Word16 qbit, num_bits;
	signed char input_buf[(MAX_BITS_PER_FRAME + 7) >> 3]; // this buffer is used for store the input streams
	void *st_handler = NULL;
	sEVS_Dec_Struct dec_struct;
	dec_struct.p_in = input_buf;
	dec_struct.p_out= data;
#endif	

	/*------------------------------------------------------------------------------------------*
	 * Allocate memory for static variables
	 * Processing of command-line parameters
	 * Decoder initialization
	 *------------------------------------------------------------------------------------------*/
#ifndef ADJUST_API
	if ( (st = (Decoder_State *) malloc( sizeof(Decoder_State) ) ) == NULL )
	{
		fprintf(stderr, "Can not allocate memory for decoder state structure\n");
		exit(-1);
	}

	io_ini_dec( argc, argv, &f_stream, &f_synth,
				&quietMode, &noDelayCmp, st,
#ifdef SUPPORT_JBM_TRACEFILE
				&jbmTraceFileName,
#endif
				&jbmFECoffsetFileName
			  );
#else     //ADJUST_API
	io_ini_dec( argc, argv, &f_stream, &f_synth,
				&quietMode, &noDelayCmp, &dec_struct, 
#ifdef SUPPORT_JBM_TRACEFILE
				&jbmTraceFileName,
#endif
				&jbmFECoffsetFileName
			  );

	st_handler = sEVS_Voip_CreateDec( &dec_struct );
	/* output frame length */
	output_frame = (short)(dec_struct.output_Fs / 50);

#endif
	/*------------------------------------------------------------------------------------------*
	 * VOIP client
	 *------------------------------------------------------------------------------------------*/
#ifndef ADJUST_API
	if( decodeVoip( st, f_stream, f_synth,
#ifdef SUPPORT_JBM_TRACEFILE
					jbmTraceFileName,
#endif
					jbmFECoffsetFileName,
					quietMode
				  ) != 0 )
	{
		return -1;
	}
	free( st );
#else
	{
		int   ret;
		unsigned char short_serial[((MAX_BITS_PER_FRAME + 7) >> 3)+1]; 		// TOC+MIME data
		unsigned short	rtpSequenceNumber;
		unsigned int	rtpTimeStamp;
		/* main loop */
		unsigned int nextPacketRcvTime_ms = 0;
		unsigned int systemTime_ms = 0;
		
		Word16		 pcmBuf[3 * L_FRAME48k] = {0};
		unsigned int pcmBufSize  = 3 * L_FRAME48k;
		
		/* calculate the delay compensation to have the decoded signal aligned with the original input signal */
		/* the number of first output samples will be reduced by this amount */
		dec_delay = NS2SA(dec_struct.output_Fs, get_delay(DEC, dec_struct.output_Fs));
		zero_pad = dec_delay;
		
		ret = ReadVoipFrame_compact(f_stream, &short_serial[0],
												 &rtpSequenceNumber, &rtpTimeStamp, &nextPacketRcvTime_ms);
		if(ret != 0)
		{
			fprintf(stderr,"failed to read first RTP packet\n");
			return -1;
		}

		/* main receiving/decoding loop */
		for( ; ; )
		{
			unsigned int nSamples = 0;
			/* read all packets with a receive time smaller than the system time */
			while( nextPacketRcvTime_ms <= dec_struct.RX_SystemTime )
			{
				/* feed the previous read packet into the receiver now */
				ret = sEVS_Voip_FeedFrame(&dec_struct, rtpSequenceNumber, rtpTimeStamp,
										 nextPacketRcvTime_ms, short_serial);
				if (ret != 0)
				{
					printf("\nerror in feeding access unit: %8x", ret);
					break;
				}
				/* read the next packet */
				ret = ReadVoipFrame_compact(f_stream, &short_serial[0],
													 &rtpSequenceNumber, &rtpTimeStamp, &nextPacketRcvTime_ms);
				if(ret == 5)
				{
					/* finished reading */
					nextPacketRcvTime_ms = (unsigned int) -1;
				}
				else if(ret != 0)
				{
					fprintf(stderr,"failed to read RTP packet\n");
					break;
				}
			}

			if(ret != 0 && ret != 5)     //failed to read RTP packet or error in feeding access unit
				break;

			/* we are finished when all packets have been received and jitter buffer is empty */
			  if( nextPacketRcvTime_ms == (unsigned int)(-1) && s_EVS_RX_IsEmpty(dec_struct) )
				  break;
			
			  /* decode and get samples */
			  nSamples = sEVS_Voip_GetSamples(&dec_struct, pcmBuf, pcmBufSize);
			
			  if ( dec_delay == 0 )
			  {
				  fwrite( pcmBuf, sizeof(Word16), nSamples, f_synth );
			  }
			  else
			  {
				  if ( dec_delay <= (short)nSamples )
				  {
					  fwrite( pcmBuf + dec_delay, sizeof(Word16), nSamples - dec_delay, f_synth );
					  dec_delay = 0;
				  }
				  else
				  {
					  dec_delay -= nSamples;
				  }
			  }
			
			  if( quietMode == 0 )
			  {
				  fprintf( stdout, "%-8ld\b\b\b\b\b\b\b\b", frame );
			  }
			  frame++;
		
		}

    set_s( pcmBuf, 0, zero_pad );
    fwrite( pcmBuf, sizeof(Word16), zero_pad, f_synth );

	sEVS_Voip_DeleteDec(st_handler, &dec_struct);
	
	}
#endif

	fclose( f_synth );
	fclose( f_stream );

	return 0;
}



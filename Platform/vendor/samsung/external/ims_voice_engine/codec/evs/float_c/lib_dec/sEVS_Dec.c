#include "sEVS.h"
#include "prot.h"
#include "options.h"
#include "EvsRXlib.h"

/*-----------------------------------------------------------------------*
 * sEVS_Create_Dec
 *
 * Initialization of state variables for decoder
 *-----------------------------------------------------------------------*/
void *sEVSCreateDec(sEVS_Dec_Struct *dec_struct)
{
	Decoder_State *st;
    if ( (st = (Decoder_State *) calloc(1, sizeof(Decoder_State) ) ) == NULL )
    {
    }

	st->ini_frame = dec_struct->ini_frame;
	st->writeFECoffset = dec_struct->writeFECoffset;
	st->Opt_VOIP = dec_struct->Opt_VOIP;
	st->output_Fs = dec_struct->output_Fs;
	st->bfi = dec_struct->bfi;
	//st->total_brate = dec_struct->dec_total_brate;
	st->amrwb_rfc4867_flag = dec_struct->amrwb_rfc4867_flag;
	//st->bitstreamformat = 1;

	st->codec_mode = 0; /* unknown before first frame */
	st->Opt_AMR_WB = 0;
	//st->Opt_AMR_WB = dec_struct->Opt_AMR_WB;

	/*need read stream from file to parse first, especially using for decoder under AMRWB mode*/
	read_indices_mime_new(st, dec_struct, 1);

	init_decoder( st );
	reset_indices_dec( st );

	return st;
}

/*-----------------------------------------------------------------------*
 * sEVSDecFrame
 *
 * Decode frame
 *-----------------------------------------------------------------------*/
int sEVSDecFrame(void *st_handler, sEVS_Dec_Struct *dec_struct)
{
	frameMode fm;
	float output[L_FRAME48k];           /* 'float' buffer for output synthesis */
	short output_number = dec_struct->output_Fs / 50;
	Decoder_State *st = (Decoder_State *)st_handler;

	st->bfi = dec_struct->bfi;
	//st->total_brate = dec_struct->dec_total_brate;

	/*read and parse the stream*/
	read_indices_mime_new(st, dec_struct, 0);

    if ( st->codec_mode == MODE1 )
	{
		fm = FRAMEMODE_NORMAL;
    }else{

		if( !st->bfi )
			fm = FRAMEMODE_NORMAL;
		else
			fm = FRAMEMODE_MISSING;

	}

	if ( st->Opt_AMR_WB )
	{

		/*
                Notice:
                If the var Opt_AMR_WB was set  or was introduce at init (EQU to 1 by setting dec_struct->Opt_AMR_WB),
                then the program for setting last_core at here can be delete. Because it has already been set
                at sEVSCreateDec; 
		*/
	    st->last_core = (st->last_core < 0)? AMR_WB_CORE :st->last_core;

		amr_wb_dec( st, output);
	}
	else
	{
		evs_dec( st, output, fm );
	}

	/* increase the counter of initialization frames */
	if( st->ini_frame < MAX_FRAME_COUNTER )
	{
		st->ini_frame++;
	}

	/* convert 'float' output data to 'short' */
	syn_output( output, output_number, dec_struct->p_out );

	return 0;

}

/*-----------------------------------------------------------------------*
 * sEVSDeleteDec
 *
 * Delete Dec state struct
 *-----------------------------------------------------------------------*/

void sEVSDeleteDec(void *st_handler)
{
	Decoder_State *st = (Decoder_State *)st_handler;

	if(st->Opt_VOIP == 0)
	{
		destroy_decoder( st );
	}

	free( st );
}


/*-----------------------------------------------------------------------*
 * sEVS_Dec_Voip_Frame
 *
 * Decode Voip
 *-----------------------------------------------------------------------*/
int sEVS_Dec_Voip_Frame(
		void *st_handler,
		FILE *f_stream,
		FILE *f_synth,
		const char *jbmTraceFileName
		,const char *jbmFECoffsetFileName, /* : Output file	for Optimum FEC offset		  */
		short quietMode
)
{
	int ret = -1;
	Decoder_State *st = (Decoder_State *)st_handler;

    ret=decodeVoip(st, f_stream, f_synth,
		jbmTraceFileName,
		jbmFECoffsetFileName, quietMode);

	return ret;
}

//******************for VOIP mode*****************************
void *sEVS_Voip_CreateDec(sEVS_Dec_Struct *dec_struct)
{
	Decoder_State *st;
	EVS_RX_HANDLE hEvsRX;	
    Word16 jbmSafetyMargin = 60; /* allowed delay reserve in addition to network jitter to reduce late-loss [milliseconds] */
	EVS_RX_ERROR rxerr = EVS_RX_NO_ERROR;
	
    if ( (st = (Decoder_State *) calloc(1, sizeof(Decoder_State) ) ) == NULL )
    {
    }
	st->ini_frame = dec_struct->ini_frame;
	st->writeFECoffset = dec_struct->writeFECoffset;
	st->Opt_VOIP = dec_struct->Opt_VOIP;
	st->output_Fs = dec_struct->output_Fs;
	st->bfi = dec_struct->bfi;
	//st->total_brate = dec_struct->dec_total_brate;
	st->amrwb_rfc4867_flag = dec_struct->amrwb_rfc4867_flag;

	st->codec_mode = 0; /* unknown before first frame */
	st->Opt_AMR_WB = 0;
	//st->Opt_AMR_WB = dec_struct->Opt_AMR_WB;

	dec_struct->RX_SystemTime = 0;
    /* initialize receiver */
    rxerr = EVS_RX_Open(&hEvsRX, st, jbmSafetyMargin);
    if(rxerr)
    {
        fprintf(stderr,"unable to open receiver\n");
        return NULL;
    }
	dec_struct->hRX = hEvsRX;

	return st;
}

int sEVS_Voip_FeedFrame(
		sEVS_Dec_Struct *dec_struct,
		unsigned short rtpSequenceNumber,
		unsigned int rtpTimeStamp,
		unsigned int nextPacketRcvTime_ms,
		unsigned char * payload                 //payload : TOC + MIME data
	)
{
	EVS_RX_HANDLE hEvsRX = (EVS_RX_HANDLE)dec_struct->hRX;
	int rxerr = 0;	
	/* feed the previous read packet into the receiver now */
	rxerr = EVS_RX_FeedFrame_new(hEvsRX, payload, rtpSequenceNumber, rtpTimeStamp, nextPacketRcvTime_ms);

	return rxerr;

}


int sEVS_Voip_GetSamples(
		sEVS_Dec_Struct *dec_struct,
		short *pcmBuf,
		int pcmBufSize
	)
{
	EVS_RX_HANDLE hEvsRX = (EVS_RX_HANDLE)dec_struct->hRX;
	unsigned int nSamples = 0;
	int rxerr;

	/* decode and get samples */
	rxerr = EVS_RX_GetSamples(hEvsRX, &nSamples, pcmBuf, pcmBufSize, dec_struct->RX_SystemTime);
	if(rxerr != 0)
		rxerr = 1;
	dec_struct->RX_SystemTime += 20;

	return nSamples;

}

void sEVS_Voip_DeleteDec(void *st_handler, sEVS_Dec_Struct *dec_struct)
{
	EVS_RX_HANDLE hEvsRX = (EVS_RX_HANDLE)dec_struct->hRX; 
	Decoder_State *st = (Decoder_State *)st_handler;

	EVS_RX_Close(&hEvsRX);

	free( st );

}


/* Returns 1 if the jitter buffer is empty, otherwise 0. */
unsigned int s_EVS_RX_IsEmpty(sEVS_Dec_Struct dec_struct )
{
    unsigned int isEmpty;
	EVS_RX_HANDLE hEvsRX = (EVS_RX_HANDLE)dec_struct.hRX;

	isEmpty = EVS_RX_IsEmpty(hEvsRX);
    return isEmpty;
}



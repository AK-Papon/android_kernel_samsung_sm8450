#ifndef _SEVS_H_
#define _SEVS_H_
#include <stdio.h>   //if do not use the function sEVS_Dec_Voip_Frame, this sentence can also be deleted

/*If want to use new change API for encoder and decoder,
   please define ADJUST_API, this macro only used for MIME mode(bit-packet mode) */
#define ADJUST_API

/*API for EVS encoder,it is used for io & init of the codec, include io & init members */
typedef struct {
	/* 1. io members, used for mandatory parameters */
    long   total_brate;                                /* total bitrate in kbps of the codec */
    int    input_Fs;    						       /* Fs */
	short  *p_in;                                      /* point to buffer for input_file */    
	unsigned char *p_out;                              /* point to buffer for output_file */

	/* 2. io members, used for options */	  
	/* -dtx D  */
    short Opt_DTX_ON;                                   /* flag indicating DTX operation */
    short interval_SID;                                 /* CNG and DTX - interval of SID update, default 8 */

    /* -rf  p o */
	short  Opt_RF_ON;                                   /* when -rf are specified, Opt_RF_ON=1 */                    
	short  rf_fec_indicator;                            /* p, get from the command or configuration file */
	short  rf_fec_offset;                               /* o, get from the command or configuration file */

    /* -max_band B */
	short  max_bwidth;									/* maximum encoded bandwidth */

	/* 3. temp variables indicate that some parameters need update*/
	short  rate_update_ok;                              /*ok : 1; fail : 0; default is ok*/
	short  Opt_RF_ON_loc;
	short  rf_fec_offset_loc;
}sEVS_Enc_Struct;

/*API Funcions for Encoder*/
void *sEVSCreateEnc(sEVS_Enc_Struct *enc_struct);
int sEVSEncFrame(void *st_handler, sEVS_Enc_Struct *enc_struct);
void  sEVSDeleteEnc(void *st_handler);

/*API for EVS decoder, it is used for io & init of the codec, include io & init members */
typedef struct {
	/* 1. io members, used for mandatory parameters */
    int   output_Fs;                                    /* output sampling rate */
	unsigned char *p_in;                                /* buffer for bitstream_file */
	short *p_out;                                       /* buffer for output_file */

	/* 2. io members, used for options */	   
    short Opt_VOIP;                                     /* flag indicating VOIP mode with JBM */
    short writeFECoffset;                               /* when -fec_cfg_file are specified, writeFECoffset=1;
                                                                                                  If no need to dump out FEC offset infor, this parameter can be deleted*/

	/* 3. io members, get from bitstream_file */	
    short bfi;                                          /* FEC - bad frame indicator */

    /* 4. init member and temporary variables */
    short ini_frame;                                    /* initialization frames counter */
	long  dec_total_brate; 	    						/* total bitrate got from file*/
	short dec_num_bits;                                 /* frame length */   

	/*5. get information from data packet TOC header*/
    short amrwb_rfc4867_flag;                           /* MIME from rfc4867 is used,0 : EVS primary; 1: AMR-WB; */
	short isAMRWB_IOmode;                               /* */
	short core_mode;                                    /* */
	short Opt_AMR_WB;

	/*6. io members, for VOIP mode*/
	void  *hRX; 										/*EVS_RX_HANDLE*/
	unsigned int	RX_SystemTime;	  
}sEVS_Dec_Struct;

void *sEVSCreateDec(sEVS_Dec_Struct *dec_struct);
int sEVSDecFrame(void *st_handler, sEVS_Dec_Struct *dec_struct);
void sEVSDeleteDec(void *st_handler);

int sEVS_Dec_Voip_Frame(
		void *st_handler,
		FILE *f_stream,
		FILE *f_synth,
		const char *jbmTraceFileName
		,const char *jbmFECoffsetFileName, /* : Output file	for Optimum FEC offset		  */
		short quietMode
);

//******************for VOIP mode*****************************
void *sEVS_Voip_CreateDec(sEVS_Dec_Struct *dec_struct);
int sEVS_Voip_FeedFrame(
		sEVS_Dec_Struct *dec_struct,
		unsigned short rtpSequenceNumber,
		unsigned int rtpTimeStamp,
		unsigned int nextPacketRcvTime_ms,
		unsigned char * payload                 //payload : TOC + MIME data
);

int sEVS_Voip_GetSamples(
		sEVS_Dec_Struct *dec_struct,
		short *pcmBuf,
		int pcmBufSize
);

void sEVS_Voip_DeleteDec(void *st_handler, sEVS_Dec_Struct *dec_struct);

unsigned int s_EVS_RX_IsEmpty(sEVS_Dec_Struct dec_struct );

#endif

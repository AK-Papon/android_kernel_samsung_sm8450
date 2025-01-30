#include "sEVS.h"
#include "rom_com.h"     /* Static table prototypes                */
#include "prot.h"
#include "cnst.h"
//#include <android/log.h>

static Word16 rate2AMRWB_IOmode_1(
    Word32 rate                    /* i: bit rate */
)
{
    switch ( rate )
    {
    /* EVS AMR-WB IO modes */
    case SID_1k75      :
        return AMRWB_IO_SID;
    case ACELP_6k60    :
        return AMRWB_IO_6600;
    case ACELP_8k85    :
        return AMRWB_IO_8850;
    case ACELP_12k65   :
        return AMRWB_IO_1265;
    case ACELP_14k25   :
        return AMRWB_IO_1425;
    case ACELP_15k85   :
        return AMRWB_IO_1585;
    case ACELP_18k25   :
        return AMRWB_IO_1825;
    case ACELP_19k85   :
        return AMRWB_IO_1985;
    case ACELP_23k05   :
        return AMRWB_IO_2305;
    case ACELP_23k85   :
        return AMRWB_IO_2385;
    default:
        return -1;
    }
}

/*-------------------------------------------------------------------*
* rate2EVSmode()
*
* lookup EVS mode
*-------------------------------------------------------------------*/
static Word16 rate2EVSmode_1(
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
        return rate2AMRWB_IOmode_1(rate);
    }
}


/*parse info base on the input parameters
* Encoder_State *st,     i/o: encode state structure
* int flag,                    i: 0-used in init phase; 1-used in encode frame phase
*/
void sEVS_Parse_Info(Encoder_State *st, int flag)
{
	short j, k;

    k = BRATE2IDX(HQ_128k);

	if(st->total_brate  == ACELP_5k90 )
	 {
		 st->Opt_SC_VBR = 1;
		 st->total_brate = ACELP_7k20;
		 st->last_Opt_SC_VBR = flag ? st->last_Opt_SC_VBR : 1;
	 }else
	 {
		 st->Opt_SC_VBR = 0;
		 st->last_Opt_SC_VBR = flag ? st->last_Opt_SC_VBR : 0;
	 }

	/* check if the entered bitrate is supported */
	 j = 0;
	 while ( j < SIZE_BRATE_TBL && st->total_brate != brate_tbl[j] )
	 {
		 j++;
	 }

	 /* AMR-WB IO mode/EVS primary mode determination */
	 if ( j >= SIZE_BRATE_TBL )
	 {
		 switch (st->total_brate)
		 {
		 case ACELP_6k60 :
		 case ACELP_8k85 :
		 case ACELP_12k65 :
		 case ACELP_14k25 :
		 case ACELP_15k85 :
		 case ACELP_18k25 :
		 case ACELP_19k85 :
		 case ACELP_23k05 :
		 case ACELP_23k85 :
			 break;
		 default :
		 {
			 fprintf(stderr, "Error: Incorrect bitrate specification: %ld\n\n", st->total_brate );
		 }
		 break;
		 }

		 st->Opt_AMR_WB = 1;
	 }
	 else
	 {
		 st->Opt_AMR_WB = 0;
	 }

	if(flag)
	{
		/* in case of 8kHz signal, limit the total bitrate to 13.20 kbps */
		if ( st->input_Fs == 8000 && st->total_brate > ACELP_24k40 )
		{
			st->total_brate = ACELP_24k40;
		}
	}

	if ( st->Opt_AMR_WB )
	{
		st->codec_mode = MODE1;
	}
	else
	{
		if(flag){
			switch ( st->total_brate )
			{
			case 2800:
				st->codec_mode = MODE1;
				break;
			case 3600:
				st->codec_mode = MODE1;
				break;
			case 3700:
				st->codec_mode = MODE1;
				break;
			case 5900:
				st->codec_mode = MODE1;
				break;
			case 7200:
				st->codec_mode = MODE1;
				break;
			case 8000:
				st->codec_mode = MODE1;
				break;
			case 9600:
				st->codec_mode = MODE2;
				break;
			case 13200:
				st->codec_mode = MODE1;
				break;
			case 16400:
				st->codec_mode = MODE2;
				break;
			case 24400:
				st->codec_mode = MODE2;
				break;
			case 32000:
				st->codec_mode = MODE1;
				break;
			case 48000:
				st->codec_mode = MODE2;
				break;
			case 64000:
				st->codec_mode = MODE1;
				break;
			case 96000:
				st->codec_mode = MODE2;
				break;
			case 128000:
				st->codec_mode = MODE2;
				break;
			}
		}
		else{
			switch ( st->total_brate )
			{
			case 5900:
				st->codec_mode = MODE1;
				break;
			case 7200:
				st->codec_mode = MODE1;
				break;
			case 8000:
				st->codec_mode = MODE1;
				break;
			case 9600:
				st->codec_mode = MODE2;
				break;
			case 13200:
				st->codec_mode = MODE1;
				break;
			case 16400:
				st->codec_mode = MODE2;
				break;
			case 24400:
				st->codec_mode = MODE2;
				break;
			case 32000:
				st->codec_mode = MODE1;
				break;
			case 48000:
				st->codec_mode = MODE2;
				break;
			case 64000:
				st->codec_mode = MODE1;
				break;
			case 96000:
				st->codec_mode = MODE2;
				break;
			case 128000:
				st->codec_mode = MODE2;
				break;
			}
		}
	}

	/*only used in init phase*/
	if(!flag)
	{
		if( st->total_brate == 13200 && st->Opt_RF_ON == 1)
		{
			st->codec_mode = MODE2;
		}
		
		st->last_codec_mode = st->codec_mode;
	}

}


/*-----------------------------------------------------------------------*
 * sEVS_Create_Enc
 *
 * Initialization of state variables and create the encoder stat struct
 *-----------------------------------------------------------------------*/
void *sEVSCreateEnc(sEVS_Enc_Struct *enc_struct)
{
	Encoder_State *st;
    if ( (st = (Encoder_State *) malloc( sizeof(Encoder_State) ) ) == NULL )
    {
        fprintf(stderr, "Can not allocate memory for encoder state structure\n");
        exit(-1);
    }

	if ( (st->ind_list = (Indice *) malloc( sizeof(Indice) * (MAX_NUM_INDICES) ) ) == NULL )
    {
        fprintf(stderr, "Can not allocate memory for temporary buffer indice list \n");
        exit(-1);
    }

	st->input_Fs = enc_struct->input_Fs;
	st->total_brate = enc_struct->total_brate;
	st->bitstreamformat = 1;//MIME : 1, force MIME mode
	st->Opt_RF_ON = enc_struct->Opt_RF_ON;
	st->rf_fec_offset = enc_struct->rf_fec_offset;
	st->rf_fec_indicator = enc_struct->rf_fec_indicator;
	st->max_bwidth = enc_struct->max_bwidth;
	st->interval_SID = enc_struct->interval_SID;
	st->Opt_DTX_ON = enc_struct->Opt_DTX_ON;

	enc_struct->rate_update_ok = 1;

	enc_struct->Opt_RF_ON_loc = enc_struct->Opt_RF_ON;
	enc_struct->rf_fec_offset_loc = enc_struct->rf_fec_offset;


	if(enc_struct->Opt_DTX_ON && (enc_struct->interval_SID >= 3 && enc_struct->interval_SID <= 100))
	{
		st->var_SID_rate_flag = 0;
	}else
	{
		st->var_SID_rate_flag = 1;
	}

	sEVS_Parse_Info(st, 0);	

    init_encoder( st );
  //  reset_indices_enc( st );

    return st;
}

/*-----------------------------------------------------------------------*
 * sEVSEncFrame
 *
 * Encode frame
 *-----------------------------------------------------------------------*/
int sEVSEncFrame(void *st_handler, sEVS_Enc_Struct *enc_struct)
{
    //__android_log_print(ANDROID_LOG_DEBUG, "SAE", "[sEVSEncFrame]\n");
    
	Encoder_State *st = (Encoder_State *)st_handler;
	short  bytes_count=0;

	st->rf_fec_offset = enc_struct->rf_fec_offset;
	st->rf_fec_indicator= enc_struct->rf_fec_indicator;

	st->total_brate = enc_struct->rate_update_ok ? enc_struct->total_brate : st->last_total_brate;
	sEVS_Parse_Info( st, 1 );

	st->max_bwidth = enc_struct->max_bwidth;
		
	if( ( st->Opt_RF_ON && ( st->total_brate != ACELP_13k20 ||	st->input_Fs == 8000 || st->max_bwidth == NB ) ) || st->rf_fec_offset == 0 )
	{
		if( st->total_brate == ACELP_13k20 )
		{
			st->codec_mode = MODE1;
			reset_rf_indices(st);
		}
		st->Opt_RF_ON = 0;
		st->rf_fec_offset = 0;
	}
	if( enc_struct->Opt_RF_ON_loc && enc_struct->rf_fec_offset_loc != 0 && L_sub( st->total_brate, ACELP_13k20 ) == 0 && L_sub( st->input_Fs, 8000 ) != 0 && st->max_bwidth != NB )
	{
		st->codec_mode = MODE2;
		if(st->Opt_RF_ON == 0)
		{
			reset_rf_indices(st);
		}
		st->Opt_RF_ON = 1;
		st->rf_fec_offset = enc_struct->rf_fec_offset_loc;
	}
	
	/* in case of 8kHz sampling rate or when in "max_band NB" mode, limit the total bitrate to 24.40 kbps */
	if ( ((st->input_Fs == 8000)|| (st->max_bwidth == NB)) && (st->total_brate > ACELP_24k40) )
	{
		st->total_brate = ACELP_24k40;
		st->codec_mode = MODE2;
	}

    //__android_log_print(ANDROID_LOG_DEBUG, "SAE", "[sEVSEncFrame] run the main encoding routine in\n");
	/* run the main encoding routine */
	if ( st->Opt_AMR_WB )
	{
		amr_wb_enc( st, enc_struct->p_in );
	}
	else
	{
		evs_enc( st, enc_struct->p_in );
	}
    //__android_log_print(ANDROID_LOG_DEBUG, "SAE", "[sEVSEncFrame] run the main encoding routine out\n");

	/* pack indices into serialized payload format */
	indices_to_serial( st, &enc_struct->p_out[1], &bytes_count );

	/*Create and write ToC header,
	  0  1 2  3  4 5 6 7   MS-bit ---> LS-bit
	+-+-+-+-+-+-+-+-+
	|H|F|E|x| brate |
	+-+-+-+-+-+-+-+-+
	  */
	  
	enc_struct->p_out[0] = (UWord8)( st->Opt_AMR_WB << 5 | st->Opt_AMR_WB << 4 | rate2EVSmode_1(st->nb_bits_tot * 50));
	bytes_count = ((bytes_count + 7)>>3) + 1;// TOC + MIME data

	reset_indices_enc(st); // Clearing of indices 
	
	return bytes_count;
}

/*-----------------------------------------------------------------------*
 * sEVSDeleteFrame
 *
 * Free the encoder stat struct
 *-----------------------------------------------------------------------*/

void  sEVSDeleteEnc(void *st_handler)
{
	Encoder_State *st = (Encoder_State *)st_handler ;

	destroy_encoder( st );
	free( st->ind_list);
    free( st );
}



#ifndef _SG711_H_
#define _SG711_H_ 

typedef struct {
	short frame_length;
	short *p_in;
	unsigned char *p_out;
} sG711Enc_INFO;

typedef struct {
	short frame_length;
	short *p_out;
	unsigned char *p_in;
} sG711Dec_INFO;

void alaw_compress(sG711Enc_INFO *sG711Enc);
void alaw_expand(sG711Dec_INFO *sG711Dec);
void ulaw_compress(sG711Enc_INFO *sG711Enc);
void ulaw_expand(sG711Dec_INFO *sG711Dec);
#endif /* _SG711_H_ */


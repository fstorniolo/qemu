#include "bpf_injection_msg.h"

struct bpf_injection_msg_t prepare_bpf_injection_message(const char* path){
	struct bpf_injection_msg_t mymsg;
	int len;
	mymsg.header.version = DEFAULT_VERSION;
	mymsg.header.type = PROGRAM_INJECTION;
	FILE* fp = fopen(path, "r");
	if(fp) {
		fseek(fp, 0 , SEEK_END);
		mymsg.header.payload_len = ftell(fp);
	  	fseek(fp, 0 , SEEK_SET);// needed for next read from beginning of file
	  	mymsg.payload = malloc(mymsg.header.payload_len);
	  	len = fread(mymsg.payload, 1, mymsg.header.payload_len, fp);
	  	// printf("readlen %d\n", len);
	  	if(len != mymsg.header.payload_len) {
	  		// printf("Error preparing the message\n");
	  		mymsg.header.type = ERROR;
	  		fclose(fp);
	  		free(mymsg.payload);
	  		return mymsg;
	  	}
	  fclose(fp);
	}
  	return mymsg;
}

void print_bpf_injection_message(struct bpf_injection_msg_header myheader){
	printf("  Version:%u\n  Type:%u\n  Payload_len:%u\n", myheader.version, myheader.type, myheader.payload_len);
}
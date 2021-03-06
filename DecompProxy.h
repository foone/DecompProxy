#ifndef DECOMPPROXY_H
#define DECOMPPROXY_H

#include <string>

#define EXPORTED extern "C" __declspec(dllexport)


typedef  int  (__stdcall *decompfunk)  (
		unsigned char*	compressed_data,
		int		compressed_size, 
		unsigned char*	outputbuffer,
		int		uncompressed_size,
		int*		output_size
	);

struct ExtractContext{
	decompfunk DecompressFunction[2];
	unsigned char *extracted_code[2];
};

EXPORTED ExtractContext* DP_Init(const char *filename);
EXPORTED int DP_Shutdown(ExtractContext*);
EXPORTED int DP_GetSize(unsigned char* section, int sectionsize);
EXPORTED int DP_DecompressSmart(ExtractContext*,unsigned char* section, int sectionsize,
																		unsigned char* output);


struct OffsetType{
	std::string version;
	std::string origin;
	unsigned int offset[2];
	unsigned int signature_offset[2];
	unsigned char signature[2][14];
	unsigned int length[2];
};
#endif

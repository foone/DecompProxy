// DecompProxy.cpp : Defines the entry point for the DLL application.

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <stdio.h>
#include <vector>
#include "DecompProxy.h"
std::vector<OffsetType> offsets;

unsigned char func1sig[16]={0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x55, 
															0x8B, 0x54, 0x24, 0x0C, 0x8B, 0xEC, 0x83};
unsigned char func2sig[16]={0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x55,
0x8B, 0x4C, 0x24, 0x0C, 0x8B, 0xEC, 0x83};


void SetupOffsets(){
	offsets.clear();
	OffsetType US={"3dmm US","Foone Turing",
	{212992,228624},
	{212992-6,228624-6},
	{{0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x55, 0x8B, 0x54, 0x24, 0x0C, 0x8B, 0xEC, 0x83},
   {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x55,0x8B, 0x4C, 0x24, 0x0C, 0x8B, 0xEC, 0x83}},
	{14637,9592}};
	offsets.push_back(US);
	OffsetType UK={"3dmm UK","Fredrick Arnoy",
	{212944,228576},
	{212944-6,228576-6},
	{{0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x55, 0x8B, 0x54, 0x24, 0x0C, 0x8B, 0xEC, 0x83},
   {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x55,0x8B, 0x4C, 0x24, 0x0C, 0x8B, 0xEC, 0x83}},
	{14637,9592}};
	offsets.push_back(UK);
	OffsetType French={"3dmm French","Cheezemaster",
	{212960,228592},
	{212960-6,228592-6},
	{{0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x55, 0x8B, 0x54, 0x24, 0x0C, 0x8B, 0xEC, 0x83},
   {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x55,0x8B, 0x4C, 0x24, 0x0C, 0x8B, 0xEC, 0x83}},
	{14637,9592}};
	offsets.push_back(French);
}
bool CheckOffset(FILE *fp,const OffsetType& offset){
	bool found[2]={false,false};
	unsigned char buffer[14];
	
	for(int i=0;i<2;i++){
		fseek(fp,offset.signature_offset[i],SEEK_SET);
		if(fread(buffer,14,1,fp)!=1){
			return false;
		}
		if(memcmp(buffer,offset.signature[i],14)!=0){
			return false;
		}
		found[i]=true;
	}
	return found[0] && found[1];
}
ExtractContext*  LoadFunctions(FILE *fp,const OffsetType& offset){
	//Shutdown();
	ExtractContext* ctx=new ExtractContext();
	for(int i=0;i<2;i++){
		ctx->extracted_code[i]=(unsigned char*)VirtualAlloc(NULL,offset.length[i],MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
		fseek(fp,offset.offset[i],SEEK_SET);
		if(fread(ctx->extracted_code[i],offset.length[i],1,fp)!=1){
			DP_Shutdown(ctx);
			return NULL;
		}
		ctx->DecompressFunction[i]=(decompfunk)ctx->extracted_code[i];
	}
	return ctx;
}
EXPORTED ExtractContext* DP_Init(const char *filename){
	SetupOffsets();
	FILE *fp=fopen(filename,"rb");
	if(!fp)return 0;
	ExtractContext *ctx;
	for(unsigned int i=0;i<offsets.size();i++){
		if(CheckOffset(fp,offsets[i])){
			ctx=LoadFunctions(fp,offsets[i]);
			if (ctx!=NULL){
				break;
			}
		}
	}
	fclose(fp);
	if(ctx){
		return ctx;
	}else{
		return NULL;
	}
}
EXPORTED int DP_Shutdown(ExtractContext *ctx){
	for(int i=0;i<2;i++){
		if (ctx->extracted_code[i]){
			VirtualFree(ctx->extracted_code[i],0,MEM_RELEASE);

			ctx->extracted_code[i]=NULL;
		}
		ctx->DecompressFunction[i]=NULL;
	}
	return 1;
}

EXPORTED int DP_GetSize(unsigned char* section, int sectionsize){
	if (sectionsize<8)return -1; // Too short!
	int size=section[7]|(((int)section[6])<<8)|(((int)section[5])<<16)|(((int)section[4])<<24);
	return size;
}
EXPORTED int DP_DecompressSmart(ExtractContext *ctx,unsigned char* section, int sectionsize,unsigned char* output){
	if(ctx->DecompressFunction[0]==NULL && ctx->DecompressFunction[1]==NULL){
		return -1;
	}
	int output_size=-1;
	int ret;
	int size=DP_GetSize(section,sectionsize);
	if(size<0)return -1;
	if (ctx->DecompressFunction[0]!=NULL){
		ret=ctx->DecompressFunction[0](section+8,sectionsize-8,output,size,&output_size);
		if(ret){
			return output_size;
		}
	}
	if (ctx->DecompressFunction[1]!=NULL){
		ret=ctx->DecompressFunction[1](section+8,sectionsize-8,output,size,&output_size);
		if(ret){
			return output_size;
		}

	}
	return -1;
}
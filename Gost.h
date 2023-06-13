#include <cstdint>
unsigned __int64 encrypt(unsigned long long i, unsigned* key, short (*arr)[16]);

unsigned __int64 round(unsigned __int64 block, unsigned __int32 i, short (*arr)[16]);

void CFB_ENC(unsigned __int32* key, short s_block[][16], unsigned __int64 gamma);

void CFB_DEC(unsigned __int32* key, short s_block[][16], unsigned __int64 gamma);

void CreateHandles(const char* input_file_path, const char* output_file_path);

void Encrypt(const char* input_file_path, const char* output_file_path, uint8_t* sha);

void Decrypt(const char* input_file_path, const char* output_file_path, uint8_t* sha);

void CloseHandles();

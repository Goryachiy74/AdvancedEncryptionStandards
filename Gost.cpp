#include <windows.h>
#include "Gost.h"

#include <cstdint>


HANDLE hFileIn;
HANDLE hFileOut;

unsigned __int32 key[8] = {1, 2, 3, 4, 5, 6, 7, 8};

unsigned __int64 ivalue = 170;

short s_block[8][16] = {
	{4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
	{14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
	{5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
	{7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
	{6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
	{4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
	{13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
	{1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12}
};

unsigned __int32* sha256ToGostKey(uint8_t* sha)
{
	auto key = new uint32_t[8]{ 0 };

	for(int i=0; i<32; i+=4)
	{
		key[i/4] <<= 8;
		key[i/4] += sha[i];
		key[i/4] <<= 8;
		key[i/4] += sha[i+1];
		key[i/4] <<= 8;
		key[i/4] += sha[i+2];
		key[i/4] <<= 8;
		key[i/4] += sha[i+3];
	}

	return key;
}

void Encrypt(const char* input_file_path, const char* output_file_path, uint8_t* sha)
{
	CreateHandles(input_file_path, output_file_path);

	auto shaKey = sha256ToGostKey(sha);

	CFB_ENC(shaKey, s_block, ivalue);

	CloseHandles();
}

void Decrypt(const char* input_file_path, const char* output_file_path, uint8_t* sha)
{
	CreateHandles(input_file_path, output_file_path);

	auto shaKey = sha256ToGostKey(sha);

	CFB_DEC(shaKey, s_block, ivalue);

	CloseHandles();
}

void CreateHandles(const char* input_file_path, const char* output_file_path)
{
	hFileIn = CreateFileA(
		input_file_path,
		GENERIC_READ,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);

	hFileOut = CreateFileA(
		output_file_path,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		nullptr,
		OPEN_ALWAYS,
		NULL,
		nullptr);
}

void CloseHandles()
{
	CloseHandle(hFileIn);
	CloseHandle(hFileOut);
}

void CFB_ENC(unsigned __int32* key, short s_block[][16], unsigned __int64 gamma)
{
	unsigned __int64 block;
	unsigned __int64 S = gamma;
	DWORD dwBytesRead = 0;
	BOOL bResult = FALSE;

	while (true)
	{
		block = 0;
		bResult = ReadFile(hFileIn, &block, 8, &dwBytesRead, nullptr);
		if (bResult && dwBytesRead == 0)
		{
			break;
		}

		block = block ^ encrypt(S, key, s_block);
		S = block;

		WriteFile(hFileOut, &block, 8, nullptr, nullptr);
	}
	SetEndOfFile(hFileOut);
}

void CFB_DEC(unsigned __int32* key, short s_block[][16], unsigned __int64 gamma)
{
	unsigned __int64 block;
	unsigned __int64 e_block;
	unsigned __int64 S = gamma;
	DWORD dwBytesRead = 0;
	BOOL bResult = FALSE;
	while (true)
	{
		block = 0;
		bResult = ReadFile(hFileIn, &block, 8, &dwBytesRead, nullptr);
		if (bResult && dwBytesRead == 0)
		{
			break;
		}
		e_block = block;
		block = block ^ encrypt(S, key, s_block);
		S = e_block;

		WriteFile(hFileOut, &block, 8, nullptr, nullptr);
	}
	SetEndOfFile(hFileOut);
}

unsigned __int64 encrypt(unsigned __int64 _block, unsigned __int32* key, short s_block[][16])
{
	unsigned __int64 block = _block;
	unsigned __int32 left = 0;

	for (int k = 1; k <= 3; k++)
		for (int i = 0; i <= 7; i++)
			block = round(block, key[i], s_block);

	for (int i = 7; i >= 0; i--)
		block = round(block, key[i], s_block);

	block = (block << 32) | (block >> 32);

	return block;
}

unsigned __int64 round(unsigned __int64 _block, unsigned __int32 subkey, short s_block[][16])
{
	unsigned __int64 block = 0;
	unsigned __int32 right = _block;
	unsigned __int32 left;
	unsigned __int32 N;
	unsigned __int32 SN = 0;
	unsigned __int32 right1 = right;
	left = _block >> 32;
	N = (right + subkey) % 4294967296; // first step of round function


	for (int j = 0; j <= 7; j++)
	{
		unsigned __int8 Ni = (N >> (4 * (7 - j))) % 16;
		Ni = s_block[j][Ni]; // substitution through s-blocks.

		unsigned __int32 mask = 0;
		mask = mask | Ni;
		mask = mask << (28 - (4 * j));
		SN = SN | mask;
	}
	N = SN;

	unsigned __int32 mask = N << 11;
	N = (N >> 21) | mask;

	right = N ^ left;
	left = right1;
	block = block | left;
	block = block << 32;
	block = block | right;

	return block;
}

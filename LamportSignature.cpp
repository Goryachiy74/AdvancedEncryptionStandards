#include <cstdlib>

#include "sha256.h"

#include "LamportSignature.h"

#include <bitset>
#include <sstream>

BASE_TYPE rand_uint64() {
	BASE_TYPE r = 0;
	for (int i = LOOP_COUNT; i > 0; i--) {
		r = r * (RAND_MAX + (BASE_TYPE)1) + rand();
	}
	return r;
}

std::string GetHashResult(BASE_TYPE value)
{
	SHA256 sha;
	sha.update(std::to_string(value));
	return SHA256::toString(sha.digest());
}

BASE_TYPE* PrivateKeyGeneration()
{
	BASE_TYPE* privateKey;

	size_t kSize = 2 * NUMBER_OF_KEYS * sizeof(BASE_TYPE);

	privateKey = (BASE_TYPE*)malloc(kSize);

	for (int i = 0; i < 2 * NUMBER_OF_KEYS; i++)
	{
		privateKey[i] = rand_uint64();
	}
	return privateKey;
}


std::string* PublicKeyGeneration(BASE_TYPE* privateKey)
{
	std::string* publicKey = new std::string[2 * NUMBER_OF_KEYS];
	SHA256 sha;
	for (int i = 0; i < 2 * NUMBER_OF_KEYS; i++)
	{
		publicKey[i] = GetHashResult(privateKey[i]);
	}
	return publicKey;
}

std::string GetBinaryRepresentationAsString(std::string message)
{
	std::stringstream buffer;

	for (int i = 0; i < message.length(); ++i)
	{
		std::bitset<4> bs4(message[i]);
		buffer << bs4;
	}
	buffer << std::endl;

	return buffer.str();
}


int* GetBinaryRepresentation(std::string message)
{
	std::string binaryMessage = GetBinaryRepresentationAsString(message);
	const char* binArrOfChars = binaryMessage.c_str();
	int* binArrOfInts = new int[NUMBER_OF_KEYS];
	for (int i = 0; i < (binaryMessage.length() - 1); i++)
	{
		binArrOfInts[i] = binArrOfChars[i] - '0';//Convert char to int
	}
	return binArrOfInts;
}

BASE_TYPE* GetSignature(BASE_TYPE* privateKey, int* document)
{
	size_t sSize = NUMBER_OF_KEYS * sizeof(BASE_TYPE);

	BASE_TYPE* signature = (BASE_TYPE*)malloc(sSize);

	for (int i = 0; i < NUMBER_OF_KEYS; i++)
	{
		signature[i] = privateKey[2 * i + document[i]];
	}
	return signature;
}

bool SignatureIsValid(BASE_TYPE* signature, int* document, std::string* publicKey)
{
	std::string validationStr[NUMBER_OF_KEYS];
	for (int i = 0; i < NUMBER_OF_KEYS; i++)
	{
		validationStr[i] = GetHashResult(signature[i]);
	}
	for (int i = 0; i < NUMBER_OF_KEYS; i++)
	{
		if (validationStr[i] != publicKey[2 * i + document[i]])
		{
			return false;
		}
	}
	return true;
}

int* GetDocument(std::string text)
{
	SHA256 sha;
	sha.update(text);
	uint8_t* digest = sha.digest();
	int* document = GetBinaryRepresentation(SHA256::toString(digest));
	delete[] digest;
	return document;
}

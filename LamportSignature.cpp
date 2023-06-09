

#include <cstdlib>

#include "sha256.h"

#include "LamportSignature.h"


BASE_TYPE rand_uint64() {
	BASE_TYPE r = 0;
	for (int i = LOOP_COUNT; i > 0; i--) {
		r = r * (RAND_MAX + (BASE_TYPE)1) + rand();
	}
	return r;
}


void SecretKeyGeneration(BASE_TYPE* privateKey)
{
	//size_t kSize = 2 * NUMBER_OF_KEYS * sizeof(BASE_TYPE);

	//privateKey = (BASE_TYPE*)malloc(kSize);

	for (int i = 0; i < 2 * NUMBER_OF_KEYS; i++)
	{
		privateKey[i] = rand_uint64();
	}
}

void PublicKeyGeneration(BASE_TYPE* privateKey, std::string* publicKey)
{
	//std::string hashedMessage;

	//size_t kSize = 2 * NUMBER_OF_KEYS * sizeof(std::string);

	//publicKey = (std::string*)malloc(kSize);

	SHA256 sha;
	for (int i = 0; i < 2 * NUMBER_OF_KEYS; i++)
	{
		sha.update(std::to_string(privateKey[i]));
		const std::string temp = SHA256::toString(sha.digest());
		publicKey[i] = temp;
	}
}

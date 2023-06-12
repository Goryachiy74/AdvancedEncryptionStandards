#ifndef LAMPORT_H
#define LAMPORT_H

#if RAND_MAX/256 >= 0xFFFFFFFFFFFFFF
#define LOOP_COUNT 1
#elif RAND_MAX/256 >= 0xFFFFFF
#define LOOP_COUNT 2
#elif RAND_MAX/256 >= 0x3FFFF
#define LOOP_COUNT 3
#elif RAND_MAX/256 >= 0x1FF
#define LOOP_COUNT 4
#else
#define LOOP_COUNT 5
#endif


#define BASE_TYPE unsigned __int64
#define NUMBER_OF_KEYS 256


BASE_TYPE* PrivateKeyGeneration();

std::string* PublicKeyGeneration(BASE_TYPE* privateKey);

std::string GetBinaryRepresentationAsString(std::string message);

int* GetBinaryRepresentation(std::string message);

BASE_TYPE* GetSignature(BASE_TYPE* privateKey, int* document);

bool SignatureIsValid(BASE_TYPE* signature, int* document, std::string* publicKey);

int* GetDocument(std::string text);

#endif

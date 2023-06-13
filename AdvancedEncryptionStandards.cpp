// AdvancedEncryptionStandards.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include "DiffieHellman.h"
#include "Gost.h"
#include "LamportSignature.h"
#include "sha256.h"


void testGOST()
{

	SHA256 sha;
	sha.update(std::to_string(INT_MAX));
	uint8_t* digest = sha.digest();

	//Encryption GOST

	std::cout << "Encryption Started!\n";

	const std::string inputFileForEncryption(SOLUTION_DIR R"(Example\GOST_Example.txt)");

	std::cout << "Input file for Encryption is " + inputFileForEncryption + "\n";

	const std::string outputFileForEncryption(SOLUTION_DIR R"(Example\GOST_Example_Encrypted_Result.txt)");

	Encrypt(inputFileForEncryption.c_str(), outputFileForEncryption.c_str(), digest);

	std::cout << "Encryption Completed!\n";

	std::cout << "Output file for saved as " + outputFileForEncryption + "\n";


	//Decryption GOST 

	std::cout << "Decryption Started!\n";

	const std::string inputFileForDecryption(SOLUTION_DIR R"(Example\GOST_Example_Encrypted_Result.txt)");

	std::cout << "Input file for Encryption is " + inputFileForDecryption + "\n";

	const std::string outputFileForDecryption(SOLUTION_DIR R"(Example\GOST_Example_Decrypted_Result.txt)");


	Decrypt(inputFileForDecryption.c_str(), outputFileForDecryption.c_str(), digest);

	std::cout << "Decryption Completed!\n";

	std::cout << "Output file for saved as " + outputFileForDecryption + "\n";
}

void testSHA256()
{
	//SHA256
	std::string messageToHash;

	for (int i = 0; i < 255; i++)
	{
		messageToHash += std::to_string(i);
	}

	SHA256 sha;
	sha.update(messageToHash);
	uint8_t* digest = sha.digest();

	std::cout << "Message to Hash is : " + messageToHash + "\n" << std::endl;

	std::string messageAfterSHA = SHA256::toString(digest);

	std::cout << "Message after Hash function is : " + messageAfterSHA + "\n" << std::endl;

	delete[] digest;

	std::string binary = GetBinaryRepresentationAsString(messageAfterSHA);

	std::cout << "Binary Representation is : " + binary + "\n" << std::endl;

	std::cout << "Size of Binary Representation is " + std::to_string(binary.length() - 1) + "\n" << std::endl;
	// -1 because of end of line 
	const char* binArr = binary.c_str();

	int* t = GetBinaryRepresentation(messageAfterSHA);
}

void testLamportSignature()
{
	//Lamport Signature test
	std::string text = "Test Message to sign and validate signature";

	int* document = GetDocument(text);

	BASE_TYPE* privateKey = PrivateKeyGeneration();

	std::string* publicKey = PublicKeyGeneration(privateKey);

	std::cout << "Public Key [0] " + publicKey[0] + "\n";

	std::cout << "Public Key [1] " + publicKey[1] + "\n";

	std::cout << "Public Key [511] " + publicKey[511] + "\n";

	BASE_TYPE* signature = GetSignature(privateKey, document);

	if (SignatureIsValid(signature, document, publicKey))
	{
		std::cout << "Signature is Valid\n";
	}
	else
	{
		std::cout << "Signature is Invalid\n";
	}
}

void testDH()
{
	//Diffie-Hellman

	long long int Ps, Gs, p, g, q, h, K_A, K_B;

	// Both persons agrees on public keys Gs and Ps
	Ps = getLargestPrime(297);
	std::cout << "Value of Ps is: " << Ps << std::endl;

	Gs = getPrimitive(Ps); // Gs is primitive root for Ps
	std::cout << "Value of Gs is: " << Gs << std::endl;

	// g is the private key chosen by Alice
	g = 4; // The chosen private key is g
	std::cout << "Private key g is: " << g << std::endl;

	p = power(Gs, g, Ps); // fetches the generated key

	// h will be the chosen private key by Bob
	h = 3; // The chosen private key is h
	std::cout << "Private key h is: " << h << std::endl;

	q = power(Gs, h, Ps); // fetches the generated key

	// After the exchange of keys, generating the secret key
	K_A = power(q, g, Ps); // Alice's Secret key
	K_B = power(p, h, Ps); // Bob's Secret key


	std::cout << "Alice's Secret key is: " << K_A << std::endl;

	std::cout << "Bob's Secret key is: " << K_B << std::endl;
}

void clientServerTest()
{
	long long int Ps, Gs, p, g, q, h, K_A, K_B;

	// Both persons agrees on public keys Gs and Ps
	Ps = getLargestPrime(24);
	std::cout << "Value of Ps is: " << Ps << std::endl;

	Gs = getPrimitive(Ps); // Gs is primitive root for Ps
	std::cout << "Value of Gs is: " << Gs << std::endl;

	std::cout << "Enter Private Key for Alice: " << std::endl;

	std::cin >> g;

	p = power(Gs, g, Ps); // fetches the generated key

	std::cout << "Enter Private Key for Bob: " << std::endl;

	std::cin >> h;

	q = power(Gs, h, Ps); // fetches the generated key

	std::string text = std::to_string(q);

	int* document = GetDocument(text);

	BASE_TYPE* privateKey = PrivateKeyGeneration();

	std::string* publicKey = PublicKeyGeneration(privateKey);

	BASE_TYPE* signature = GetSignature(privateKey, document);

	if (SignatureIsValid(signature, document, publicKey))
	{
		std::cout << "Bob's Signature is Valid\n";
	}
	else
	{
		std::cout << "Bob's Signature is Invalid\n";
	}

	// After the exchange of keys, generating the secret key
	K_A = power(q, g, Ps); // Alice's Secret key

	text = std::to_string(p);

	document = GetDocument(text);

	privateKey = PrivateKeyGeneration();

	publicKey = PublicKeyGeneration(privateKey);

	signature = GetSignature(privateKey, document);

	if (SignatureIsValid(signature, document, publicKey))
	{
		std::cout << "Alice's Signature is Valid\n";
	}
	else
	{
		std::cout << "Alice's Signature is Invalid\n";
	}


	K_B = power(p, h, Ps); // Bob's Secret key


	std::cout << "Alice's Secret key is: " << K_A << std::endl;

	std::cout << "Bob's Secret key is: " << K_B << std::endl;

	SHA256 sha;
	sha.update(std::to_string(K_A));
	uint8_t* digest = sha.digest();

	//Encryption GOST

	std::cout << "Enter file path for encryption: " << std::endl;

	std::string fileForEncryption;

	std::cin >> fileForEncryption;

	std::cout << "Input file for Encryption is " + fileForEncryption + "\n";

	std::string fileForEncryptionResult;

	std::cout << "Enter file path for encryption result: " << std::endl;

	std::cin >> fileForEncryptionResult;

	std::cout << "Encryption Started!\n";

	std::cout << "Output file  is " + fileForEncryptionResult + "\n";


	Encrypt(fileForEncryption.c_str(), fileForEncryptionResult.c_str(), digest);

	std::cout << "Encryption Completed!\n";

	SHA256 shaB;
	shaB.update(std::to_string(K_B));
	uint8_t* digestB = shaB.digest();

	//Decryption GOST

	std::cout << "Enter file path for decryption: " << std::endl;

	std::string fileForDecryption;

	std::cin >> fileForDecryption;

	std::cout << "Input file for Decryption is " + fileForDecryption + "\n";

	std::string fileForDecryptionResult;

	std::cout << "Enter file path for decryption result: " << std::endl;

	std::cin >> fileForDecryptionResult;

	std::cout << "Output file  is " + fileForDecryptionResult + "\n";

	std::cout << "Decryption Started!\n";

	Decrypt(fileForDecryption.c_str(), fileForDecryptionResult.c_str(), digestB);

	std::cout << "Decryption Completed!\n";

	std::cout << "Output file  is " + fileForDecryptionResult + "\n";

}

void systemTest()
{
	//Diffie-Hellman

	long long int Ps, Gs, p, g, q, h, K_A, K_B;

	// Both persons agrees on public keys Gs and Ps
	Ps = getLargestPrime(24);
	std::cout << "Value of Ps is: " << Ps << std::endl;

	Gs = getPrimitive(Ps); // Gs is primitive root for Ps
	std::cout << "Value of Gs is: " << Gs << std::endl;

	// g is the private key chosen by Alice
	g = 4; // The chosen private key is g
	std::cout << "Private key g is: " << g << std::endl;

	p = power(Gs, g, Ps); // fetches the generated key

	// h will be the chosen private key by Bob
	h = 3; // The chosen private key is h
	std::cout << "Private key h is: " << h << std::endl;

	q = power(Gs, h, Ps); // fetches the generated key

	// After the exchange of keys, generating the secret key
	K_A = power(q, g, Ps); // Alice's Secret key
	K_B = power(p, h, Ps); // Bob's Secret key


	std::cout << "Alice's Secret key is: " << K_A << std::endl;

	std::cout << "Bob's Secret key is: " << K_B << std::endl;


	SHA256 sha;
	sha.update(std::to_string(K_A));
	uint8_t* digest = sha.digest();

	std::cout << "Message to Hash is : " + std::to_string(K_A) + "\n" << std::endl;

	std::string messageAfterSHA = SHA256::toString(digest);

	std::cout << "Message after Hash function is : " + messageAfterSHA + "\n" << std::endl;

	std::string binary = GetBinaryRepresentationAsString(messageAfterSHA);

	std::cout << "Binary Representation is : " + binary + "\n" << std::endl;


	//Encryption GOST

	std::cout << "Encryption Started!\n";

	const std::string inputFileForEncryption(SOLUTION_DIR R"(Example\GOST_Example.txt)");

	std::cout << "Input file for Encryption is " + inputFileForEncryption + "\n";

	const std::string outputFileForEncryption(SOLUTION_DIR R"(Example\GOST_Example_Encrypted_Result.txt)");

	Encrypt(inputFileForEncryption.c_str(), outputFileForEncryption.c_str(), digest);

	std::cout << "Encryption Completed!\n";

	std::cout << "Output file for saved as " + outputFileForEncryption + "\n";


	SHA256 shaB;
	shaB.update(std::to_string(K_B));
	uint8_t* digestB = shaB.digest();

	std::cout << "Message to Hash is : " + std::to_string(K_B) + "\n" << std::endl;

	std::string messageAfterSHAB = SHA256::toString(digestB);

	std::cout << "Message after Hash function is : " + messageAfterSHAB + "\n" << std::endl;

	std::string binaryB = GetBinaryRepresentationAsString(messageAfterSHAB);

	std::cout << "Binary Representation is : " + binaryB + "\n" << std::endl;

	//Decryption GOST 

	std::cout << "Decryption Started!\n";

	const std::string inputFileForDecryption(SOLUTION_DIR R"(Example\GOST_Example_Encrypted_Result.txt)");

	std::cout << "Input file for Encryption is " + inputFileForDecryption + "\n";

	const std::string outputFileForDecryption(SOLUTION_DIR R"(Example\GOST_Example_Decrypted_Result.txt)");


	Decrypt(inputFileForDecryption.c_str(), outputFileForDecryption.c_str(), digestB);

	std::cout << "Decryption Completed!\n";

	std::cout << "Output file for saved as " + outputFileForDecryption + "\n";

}

int main()
{
	std::cout << "Advanced Encryption Standards!\n";

	clientServerTest();

	//testGOST();

	//testSHA256();

	//testLamportSignature();

	//testDH();

	return 0;
}

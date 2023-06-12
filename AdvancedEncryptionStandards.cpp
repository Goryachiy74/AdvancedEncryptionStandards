// AdvancedEncryptionStandards.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

#include "DiffieHellman.h"
#include "Gost.h"
#include "LamportSignature.h"
#include "sha256.h"


int main()
{
	std::cout << "Advanced Encryption Standards!\n";


	//Encryption GOST

	std::cout << "Encryption Started!\n";

	const std::string inputFileForEncryption(SOLUTION_DIR R"(Example\GOST_Example.txt)");

	std::cout << "Input file for Encryption is " + inputFileForEncryption + "\n";

	const std::string outputFileForEncryption(SOLUTION_DIR R"(Example\GOST_Example_Encrypted_Result.txt)");

	Encrypt(inputFileForEncryption.c_str(), outputFileForEncryption.c_str());

	std::cout << "Encryption Completed!\n";

	std::cout << "Output file for saved as " + outputFileForEncryption + "\n";


	//Decryption GOST 

	std::cout << "Decryption Started!\n";

	const std::string inputFileForDecryption(SOLUTION_DIR R"(Example\GOST_Example_Encrypted_Result.txt)");

	std::cout << "Input file for Encryption is " + inputFileForDecryption + "\n";

	const std::string outputFileForDecryption(SOLUTION_DIR R"(Example\GOST_Example_Decrypted_Result.txt)");


	Decrypt(inputFileForDecryption.c_str(), outputFileForDecryption.c_str());

	std::cout << "Decryption Completed!\n";

	std::cout << "Output file for saved as " + outputFileForDecryption + "\n";

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


	//Diffie-Hellman

	long long int Ps, Gs, p, g, q, h, K_A, K_B;

	// Both persons agrees on public keys Gs and Ps
	Ps = getLargestPrime(14000000);
	std::cout << "Value of Ps is: " << Ps << std::endl;

	Gs = getPrimitive(Ps); // Gs is primitive root for Ps
	std::cout << "Value of Gs is: " << Gs << std::endl;

	// g is the private key chosen by Alice
	g = 4902; // The chosen private key is g
	std::cout << "Private key g is: " << g << std::endl;

	p = power(Gs, g, Ps); // fetches the generated key

	// h will be the chosen private key by Bob
	h = 37519; // The chosen private key is h
	std::cout << "Private key h is: " << h << std::endl;

	q = power(Gs, h, Ps); // fetches the generated key

	// After the exchange of keys, generating the secret key
	K_A = power(q, g, Ps); // Alice's Secret key
	K_B = power(p, h, Ps); // Bob's Secret key
	std::cout << "Alice's Secret key is: " << K_A << std::endl;

	std::cout << "Bob's Secret key is: " << K_B << std::endl;
}

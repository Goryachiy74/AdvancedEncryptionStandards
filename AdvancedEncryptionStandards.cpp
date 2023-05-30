// AdvancedEncryptionStandards.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "Gost.h"


int main()
{
    std::cout << "Advanced Encryption Standards!\n";


    //Encryption

    std::cout << "Encryption Started!\n";

    const std::string inputFileForEncryption(SOLUTION_DIR  R"(Example\GOST_Example.txt)");

    std::cout << "Input file for Encryption is " + inputFileForEncryption + "\n";

    const std::string outputFileForEncryption(SOLUTION_DIR  R"(Example\GOST_Example_Encrypted_Result.txt)");

    Encrypt(inputFileForEncryption.c_str(), outputFileForEncryption.c_str());

	std::cout << "Encryption Completed!\n";

    std::cout << "Output file for saved as " + outputFileForEncryption + "\n";


    //Decryption

    std::cout << "Decryption Started!\n";

    const std::string inputFileForDecryption(SOLUTION_DIR  R"(Example\GOST_Example_Encrypted_Result.txt)");

    std::cout << "Input file for Encryption is " + inputFileForDecryption + "\n";

    const std::string outputFileForDecryption(SOLUTION_DIR  R"(Example\GOST_Example_Decrypted_Result.txt)");


	Decrypt(inputFileForDecryption.c_str(), outputFileForDecryption.c_str());

	std::cout << "Decryption Completed!\n";

    std::cout << "Output file for saved as " + outputFileForDecryption + "\n";


}


#pragma once
#include <string>

void store_message_bytes(const std::string& hex_str);

void pad_message();

// Parse message into word blocks
void parse_message();

// Set the inital hash value
void init_hash();

// Compute the hash value
void compute_hash();

// Output the generated hash value
void output_hash();

// Reset message to hash a new one
void clear();

std::string get_hash_value();

std::string hash_message(const std::string& hex_str);
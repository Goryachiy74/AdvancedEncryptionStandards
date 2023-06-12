#include <cmath>
using namespace std;

// Power function to return value of a ^ b mod P
long long int power(long long int g, long long int h,
                    long long int Ps)
{
	if (h == 1)
		return g;
	return (static_cast<long long int>(pow(g, h)) % Ps);
}

int modularExponentiation(int base, int expo, int mod)
{
	int result = 1;
	while (expo > 0)
	{
		if (expo & 1)result = (result * base) % mod;
		base = (base * base) % mod;
		expo = expo >> 1;
	}
	return result;
}

int getPrimitive(int p)
{
	for (int i = 2; i < p; i++)
	{
		bool isPrimitive = true;
		for (int j = p - 2; j > 0; j--)
		{
			if (modularExponentiation(i, j, p) == 1)
			{
				isPrimitive = false;
				break;
			}
		}
		if (isPrimitive)return i;
	}
	return -1;
}

bool isPrimeNumber(int Number) // function that checks if the number is prime
{
	int i = 2; // for iteration
	bool is_prime = true; // the variable that says if number is prime or not
	float half = Number / 2; // just so Number/2 wouldn't be calculated every iteration

	while (is_prime && i <= half) // the while only makes max half iterations
	{
		if (Number % i == 0)
			is_prime = false;
		i++;
	}

	return is_prime; // returns 1 if it is prime and 0 if it isn't prime
}

int getLargestPrime(int Number) // function that finds the maximum prime number smaller than Number
{
	int MaxPrime = 0; // variable that stores the max prime number that the function will return
	bool found_maxp = false; // variable that keeps track if the max prime number has been found
	int i = Number;

	while (!found_maxp && i > 2) // the while only makes max number-2 iterations
	{
		if (isPrimeNumber(i))
		{
			found_maxp = true; // the max prime number has been found, no need to search next iteration
			MaxPrime = i; // the max prime number is of course i
		}
		i--;
	}

	return MaxPrime; // returns the max prime smaller or equal to Number
}

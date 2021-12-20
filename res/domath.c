/* A super simple program that simply gets a random number and performs some calculations on it
 To the user, it appears to do nothing. Used to test basic block similarity hypothesis from lib-identify/00_intro_lib_identify
 IMPORTANT: compile with -fno-inline-functions to prevent these functions from being inlined */
#include <stdlib.h>
#include <math.h>

int main() {
	double num = (double)rand() / (double)(RAND_MAX/360);
	double ncos = cos(num);
	double nexp = exp(ncos);
	double nlog = log10(nexp);
	nlog = nlog + 1;
	return 0;
}


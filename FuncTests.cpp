#include <stdio.h>
#include <string.h>
#include "sha1.h"


enum
{
	shaSuccess = 0,
	shaNull,            /* Null pointer parameter */
	shaInputTooLong,    /* input data too long */
	shaStateError       /* called Input after Result */
};
#define SHA1HashSize 20

/*
*  This structure will hold context information for the SHA-1
*  hashing operation
*/
typedef struct SHA1Context
{
	uint32_t Intermediate_Hash[SHA1HashSize / 4]; /* Message Digest  */

	uint32_t Length_Low;            /* Message length in bits      */
	uint32_t Length_High;           /* Message length in bits      */

	/* Index into message block array   */
	int_least16_t Message_Block_Index;
	uint8_t Message_Block[64];      /* 512-bit message blocks      */

	int Computed;               /* Is the digest computed?         */
	int Corrupted;             /* Is the message digest corrupted? */
} SHA1Context;


/*
*  These functions are taken DIRECTLY from rfc3174 to be used for comparison during testing
*/
int SHA1Reset(SHA1Context *);
int SHA1Input(SHA1Context *,
	const uint8_t *,
	unsigned int);
int SHA1Result(SHA1Context *,
	uint8_t Message_Digest[SHA1HashSize]);
void SHA1ProcessMessageBlock(SHA1Context *context);
void SHA1PadMessage(SHA1Context *context);

#define SHA1CircularShift(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))

#define TEST4a  "01234567012345670123456701234567"
#define TEST4b  "01234567012345670123456701234567"
/* an exact multiple of 512 bits */
#define TEST4   TEST4a TEST4b

#define TESTCOUNT 4
char *testarray[TESTCOUNT] =
{
	TEST4,
	"asdqwagweageadawdageaeahjrahaeweageadawdageaeahjrahae3261",
	"",
	"asdqwagweageadawdageaeahjrahaeweageadawdageaeahjrahae326108abcdbcdecdefdefgefghfghighijhi"
};
long int repeatcount[TESTCOUNT] = { 1, 1, 1, 1};
char *resultarray[TESTCOUNT] =
{
	"E0 C0 94 E8 67 EF 46 C3 50 EF 54 A7 F5 9D D6 0B ED 92 AE 83",
	"04 22 B6 21 8D 10 4A C1 57 9F FF AB 0D E6 E5 11 9F 2F D2 D0",
	"DA 39 A3 EE 5E 6B 4B 0D 32 55 BF EF 95 60 18 90 AF D8 07 09",
	"81 73 29 3F 32 85 F6 99 0B E8 98 E1 6A E4 4E 6D D4 30 09 F2"
};


int SHA1Reset(SHA1Context *context)
{
	if (!context)
	{
		return shaNull;
	}

	context->Length_Low = 0;
	context->Length_High = 0;
	context->Message_Block_Index = 0;

	context->Intermediate_Hash[0] = 0x67452301;
	context->Intermediate_Hash[1] = 0xEFCDAB89;
	context->Intermediate_Hash[2] = 0x98BADCFE;
	context->Intermediate_Hash[3] = 0x10325476;
	context->Intermediate_Hash[4] = 0xC3D2E1F0;

	context->Computed = 0;
	context->Corrupted = 0;

	return shaSuccess;
}

int SHA1Result(SHA1Context *context,
	uint8_t Message_Digest[SHA1HashSize])
{
	int i;

	if (!context || !Message_Digest)
	{
		return shaNull;
	}

	if (context->Corrupted)
	{
		return context->Corrupted;
	}

	if (!context->Computed)
	{
		SHA1PadMessage(context);
		for (i = 0; i<64; ++i)
		{
			/* message may be sensitive, clear it out */
			context->Message_Block[i] = 0;
		}
		context->Length_Low = 0;    /* and clear length */
		context->Length_High = 0;
		context->Computed = 1;
	}

	for (i = 0; i < SHA1HashSize; ++i)
	{
		Message_Digest[i] = context->Intermediate_Hash[i >> 2]
			>> 8 * (3 - (i & 0x03));
	}

	return shaSuccess;
}

int SHA1Input(SHA1Context    *context,
	const uint8_t  *message_array,
	unsigned       length)
{
	if (!length)
	{
		return shaSuccess;
	}

	if (!context || !message_array)
	{
		return shaNull;
	}

	if (context->Computed)
	{
		context->Corrupted = shaStateError;

		return shaStateError;
	}

	if (context->Corrupted)
	{
		return context->Corrupted;
	}
	while (length-- && !context->Corrupted)
	{
		context->Message_Block[context->Message_Block_Index++] =
			(*message_array & 0xFF);

		context->Length_Low += 8;
		if (context->Length_Low == 0)
		{
			context->Length_High++;
			if (context->Length_High == 0)
			{
				/* Message is too long */
				context->Corrupted = 1;
			}
		}

		if (context->Message_Block_Index == 64)
		{
			SHA1ProcessMessageBlock(context);
		}

		message_array++;
	}

	return shaSuccess;
}

void SHA1ProcessMessageBlock(SHA1Context *context)
{
	const uint32_t K[] = {       /* Constants defined in SHA-1   */
		0x5A827999,
		0x6ED9EBA1,
		0x8F1BBCDC,
		0xCA62C1D6
	};
	int           t;                 /* Loop counter                */
	uint32_t      temp;              /* Temporary word value        */
	uint32_t      W[80];             /* Word sequence               */
	uint32_t      A, B, C, D, E;     /* Word buffers                */

	/*
	*  Initialize the first 16 words in the array W
	*/
	for (t = 0; t < 16; t++)
	{
		W[t] = context->Message_Block[t * 4] << 24;
		W[t] |= context->Message_Block[t * 4 + 1] << 16;
		W[t] |= context->Message_Block[t * 4 + 2] << 8;
		W[t] |= context->Message_Block[t * 4 + 3];
	}

	for (t = 16; t < 80; t++)
	{
		W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
	}
	A = context->Intermediate_Hash[0];
	B = context->Intermediate_Hash[1];
	C = context->Intermediate_Hash[2];
	D = context->Intermediate_Hash[3];
	E = context->Intermediate_Hash[4];

	for (t = 0; t < 20; t++)
	{
		temp = SHA1CircularShift(5, A) +
			((B & C) | ((~B) & D)) + E + W[t] + K[0];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);

		B = A;
		A = temp;
	}
	for (t = 20; t < 40; t++)
	{
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 40; t < 60; t++)
	{
		temp = SHA1CircularShift(5, A) +
			((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 60; t < 80; t++)
	{
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	context->Intermediate_Hash[0] += A;
	context->Intermediate_Hash[1] += B;
	context->Intermediate_Hash[2] += C;
	context->Intermediate_Hash[3] += D;
	context->Intermediate_Hash[4] += E;

	context->Message_Block_Index = 0;
}


void SHA1PadMessage(SHA1Context *context)
{
	/*
	*  Check to see if the current message block is too small to hold
	*  the initial padding bits and length.  If so, we will pad the
	*  block, process it, and then continue padding into a second
	*  block.
	*/
	if (context->Message_Block_Index > 55)
	{
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while (context->Message_Block_Index < 64)
		{
			context->Message_Block[context->Message_Block_Index++] = 0;
		}

		SHA1ProcessMessageBlock(context);

		while (context->Message_Block_Index < 56)
		{
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	}
	else
	{
		context->Message_Block[context->Message_Block_Index++] = 0x80;
		while (context->Message_Block_Index < 56)
		{
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	}

	/*
	*  Store the message length as the last 8 octets
	*/
	context->Message_Block[56] = context->Length_High >> 24;
	context->Message_Block[57] = context->Length_High >> 16;
	context->Message_Block[58] = context->Length_High >> 8;
	context->Message_Block[59] = context->Length_High;
	context->Message_Block[60] = context->Length_Low >> 24;
	context->Message_Block[61] = context->Length_Low >> 16;
	context->Message_Block[62] = context->Length_Low >> 8;
	context->Message_Block[63] = context->Length_Low;

	SHA1ProcessMessageBlock(context);
}


void printSHA1(SHA1_DIGEST *dig){
	uint32_t H0, H1, H2, H3, H4;
	H0 = dig->H0;
	H1 = dig->H1;
	H2 = dig->H2;
	H3 = dig->H3;
	H4 = dig->H4;
	printf("ASM:\t%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
		(H0 >> 24) & 0xFF, (H0 >> 16) & 0xFF, (H0 >> 8) & 0xFF, H0 & 0xFF,
		(H1 >> 24) & 0xFF, (H1 >> 16) & 0xFF, (H1 >> 8) & 0xFF, H1 & 0xFF,
		(H2 >> 24) & 0xFF, (H2 >> 16) & 0xFF, (H2 >> 8) & 0xFF, H2 & 0xFF,
		(H3 >> 24) & 0xFF, (H3 >> 16) & 0xFF, (H3 >> 8) & 0xFF, H3 & 0xFF,
		(H4 >> 24) & 0xFF, (H4 >> 16) & 0xFF, (H4 >> 8) & 0xFF, H4 & 0xFF);
}


int main(int argc, char* argv[]) {
	SHA1_DIGEST* dig1 = new SHA1_DIGEST;
	SHA1Context sha;
	int i, j, err;
	uint8_t Message_Digest[20];

	/*
	*  Perform SHA-1 tests
	*/
	for (j = 0; j < TESTCOUNT; ++j)
	{
		printf("\nTest %d: %d, '%s'\n",
			j + 1,
			repeatcount[j],
			testarray[j]);

		err = SHA1Reset(&sha);
		if (err)
		{
			fprintf(stderr, "SHA1Reset Error %d.\n", err);
			break;    /* out of for j loop */
		}

		for (i = 0; i < repeatcount[j]; ++i)
		{
			err = SHA1Input(&sha,
				(const unsigned char *)testarray[j],
				strlen(testarray[j]));
			if (err)
			{
				fprintf(stderr, "SHA1Input Error %d.\n", err);
				break;    /* out of for i loop */
			}
		}

		err = SHA1Result(&sha, Message_Digest);
		if (err)
		{
			fprintf(stderr,
				"SHA1Result Error %d, could not compute message digest.\n",
				err);
		}
		else
		{
			printf("\t");
			for (i = 0; i < 20; ++i)
			{
				printf("%02X ", Message_Digest[i]);
			}
			printf("\n");
		}
		printf("Should match:\n");
		printf("\t%s\n", resultarray[j]);

		doSHA1(dig1, testarray[j], strlen(testarray[j]));
		printSHA1(dig1);
	}

	delete dig1;
	return 0;
}

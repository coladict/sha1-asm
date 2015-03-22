#ifndef SHA_1_H
#define SHA_1_H
#include <stdint.h>

typedef struct {
	uint32_t H0;
	uint32_t H1;
	uint32_t H2;
	uint32_t H3;
	uint32_t H4;
} SHA1_DIGEST;

#ifdef __cplusplus
extern "C" {
#endif
/* This function is NOT null-safe. If you pass a null pointer it will crash,
*  so always check your inputs.
*/
	void doSHA1(SHA1_DIGEST* bufout, const void* bufin, uint64_t bufsize);
#ifdef __cplusplus
}
#endif

#endif

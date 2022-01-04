/* SHA256-based Unix crypt implementation.
   Released into the Public Domain by Ulrich Drepper <drepper@redhat.com>.  */
/* Windows VC++ port by Pierre Joye <pierre@php.net> */

#include "crypt_sha256.h"



// zend_portability.h =====================================
#ifdef __cplusplus
#define BEGIN_EXTERN_C() extern "C" {
#define END_EXTERN_C() }
#else
#define BEGIN_EXTERN_C()
#define END_EXTERN_C()
#endif
// zend_portability.h =====================================



// main/php_stdint.h ======================================
/* C99 requires these for C++ to get the definitions
 * of INT64_MAX and other macros used by Zend/zend_long.h
 * C11 drops this requirement, so these effectively
 * just backport that piece of behavior.
 *
 * These defines are placed here instead of
 * with the include below, because sys/types
 * and inttypes may include stdint themselves.
 * And these definitions MUST come first.
 */
#include <inttypes.h>
#include <stdint.h>

#if defined(_MSC_VER)
# ifndef u_char
typedef unsigned __int8   u_char;
# endif
#endif
// main/php_stdint.h ======================================



// zend_long.h ============================================
#ifdef ZEND_ENABLE_ZVAL_LONG64
typedef int64_t zend_long;
typedef uint64_t zend_ulong;
typedef int64_t zend_off_t;
# define ZEND_LONG_MAX INT64_MAX
# define ZEND_LONG_MIN INT64_MIN
# define ZEND_ULONG_MAX UINT64_MAX
# define Z_L(i) INT64_C(i)
# define Z_UL(i) UINT64_C(i)
# define SIZEOF_ZEND_LONG 8
#else
typedef int32_t zend_long;
typedef uint32_t zend_ulong;
typedef int32_t zend_off_t;
# define ZEND_LONG_MAX INT32_MAX
# define ZEND_LONG_MIN INT32_MIN
# define ZEND_ULONG_MAX UINT32_MAX
# define Z_L(i) INT32_C(i)
# define Z_UL(i) UINT32_C(i)
# define SIZEOF_ZEND_LONG 4
#endif

#ifdef ZEND_ENABLE_ZVAL_LONG64
# define ZEND_LONG_FMT "%" PRId64
# define ZEND_ULONG_FMT "%" PRIu64
# define ZEND_XLONG_FMT "%" PRIx64
# define ZEND_LONG_FMT_SPEC PRId64
# define ZEND_ULONG_FMT_SPEC PRIu64
# ifdef ZEND_WIN32
#  define ZEND_LTOA(i, s, len) _i64toa_s((i), (s), (len), 10)
#  define ZEND_ATOL(s) _atoi64((s))
#  define ZEND_STRTOL(s0, s1, base) _strtoi64((s0), (s1), (base))
#  define ZEND_STRTOUL(s0, s1, base) _strtoui64((s0), (s1), (base))
#  define ZEND_STRTOL_PTR _strtoi64
#  define ZEND_STRTOUL_PTR _strtoui64
#  define ZEND_ABS _abs64
# else
#  define ZEND_LTOA(i, s, len) \
    do { \
        int st = snprintf((s), (len), ZEND_LONG_FMT, (i)); \
        (s)[st] = '\0'; \
    } while (0)
#  define ZEND_ATOL(s) atoll((s))
#  define ZEND_STRTOL(s0, s1, base) strtoll((s0), (s1), (base))
#  define ZEND_STRTOUL(s0, s1, base) strtoull((s0), (s1), (base))
#  define ZEND_STRTOL_PTR strtoll
#  define ZEND_STRTOUL_PTR strtoull
#  define ZEND_ABS imaxabs
# endif
#else
# define ZEND_STRTOL(s0, s1, base) strtol((s0), (s1), (base))
# define ZEND_STRTOUL(s0, s1, base) strtoul((s0), (s1), (base))
# define ZEND_LONG_FMT "%" PRId32
# define ZEND_ULONG_FMT "%" PRIu32
# define ZEND_XLONG_FMT "%" PRIx32
# define ZEND_LONG_FMT_SPEC PRId32
# define ZEND_ULONG_FMT_SPEC PRIu32
# ifdef ZEND_WIN32
#  define ZEND_LTOA(i, s, len) _ltoa_s((i), (s), (len), 10)
#  define ZEND_ATOL(s) atol((s))
# else
#  define ZEND_LTOA(i, s, len) \
    do { \
        int st = snprintf((s), (len), ZEND_LONG_FMT, (i)); \
        (s)[st] = '\0'; \
    } while (0)
#  define ZEND_ATOL(s) atol((s))
# endif
# define ZEND_STRTOL_PTR strtol
# define ZEND_STRTOUL_PTR strtoul
# define ZEND_ABS abs
#endif
// zend_long.h ============================================



#include <stdbool.h>



// php.h ==================================================
#ifdef PHP_WIN32
#	include "tsrm_win32.h"
#	ifdef PHP_EXPORTS
#		define PHPAPI __declspec(dllexport)
#	else
#		define PHPAPI __declspec(dllimport)
#	endif
#	define PHP_DIR_SEPARATOR '\\'
#	define PHP_EOL "\r\n"
#else
#	if defined(__GNUC__) && __GNUC__ >= 4
#		define PHPAPI __attribute__ ((visibility("default")))
#	else
#		define PHPAPI
#	endif
#	define PHP_DIR_SEPARATOR '/'
#	define PHP_EOL "\n"
#endif

PHPAPI void php_explicit_bzero(void *dst, size_t siz)
{
#ifdef HAVE_EXPLICIT_MEMSET
    explicit_memset(dst, 0, siz);
#elif defined(PHP_WIN32)
    RtlSecureZeroMemory(dst, siz);
#elif defined(__GNUC__)
    memset(dst, 0, siz);
    asm __volatile__("" :: "r"(dst) : "memory");
#else
    size_t i = 0;
    volatile unsigned char *buf = (volatile unsigned char *)dst;

    for (; i < siz; i ++)
        buf[i] = 0;
#endif
}

#ifndef HAVE_EXPLICIT_BZERO
BEGIN_EXTERN_C()
PHPAPI void php_explicit_bzero(void *dst, size_t siz);
END_EXTERN_C()
#undef explicit_bzero
#define explicit_bzero php_explicit_bzero
#endif
// php.h ==================================================



#include <errno.h>
#include <limits.h>

#include <malloc.h>
# define alloca _alloca

#ifdef PHP_WIN32
# define __alignof__ __alignof
# define alloca _alloca
#else
# ifndef HAVE_ALIGNOF
#  include <stddef.h>
#  define __alignof__(type) offsetof (struct { char c; type member;}, member)
# endif
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef PHP_WIN32
# include <string.h>
#else
# include <sys/types.h>
# include <string.h>
#endif



char * __php_stpncpy(char *dst, const char *src, size_t len)
{
	size_t n = strlen(src);
	if (n > len) {
		n = len;
	}
	return strncpy(dst, src, len) + n;
}



void * __php_mempcpy(void * dst, const void * src, size_t len)
{
	return (((char *)memcpy(dst, src, len)) + len);
}



#ifndef MIN
# define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
# define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif



/* Structure to save state of computation between the single steps. */
struct sha256_ctx
{
	uint32_t H[8];

	uint32_t total[2];
	uint32_t buflen;
    char buffer[128]; /* NB: always correctly aligned for uint32_t. */
};



#if defined(PHP_WIN32) || (!defined(WORDS_BIGENDIAN))
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
#else
# define SWAP(n) (n)
#endif



/* This array contains the bytes used to pad the buffer to the next 64-byte boundary.
   (FIPS 180-2:5.1.1) */
static const unsigned char fillbuf[64] = { 0x80, 0 /* , 0, 0, ...  */ };



/* Constants for SHA256 from FIPS 180-2:4.2.2. */
static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};



/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0. */
static void sha256_process_block (const void *buffer, size_t len, struct sha256_ctx *ctx)
{
	const uint32_t *words = buffer;
	size_t nwords = len / sizeof (uint32_t);
	unsigned int t;

	uint32_t a = ctx->H[0];
	uint32_t b = ctx->H[1];
	uint32_t c = ctx->H[2];
	uint32_t d = ctx->H[3];
	uint32_t e = ctx->H[4];
	uint32_t f = ctx->H[5];
	uint32_t g = ctx->H[6];
	uint32_t h = ctx->H[7];

    /* First increment the byte count. FIPS 180-2 specifies the possible
       length of the file up to 2^64 bits. Here we only compute the
       number of bytes. Do a double word increment. */
	ctx->total[0] += (uint32_t)len;
	if (ctx->total[0] < len) {
		++ctx->total[1];
	}

    /* Process all bytes in the buffer with 64 bytes in each round of the loop. */
	while (nwords > 0) {
		uint32_t W[64];
		uint32_t a_save = a;
		uint32_t b_save = b;
		uint32_t c_save = c;
		uint32_t d_save = d;
		uint32_t e_save = e;
		uint32_t f_save = f;
		uint32_t g_save = g;
		uint32_t h_save = h;

/* Operators defined in FIPS 180-2:4.1.2. */
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (CYCLIC (x, 2) ^ CYCLIC (x, 13) ^ CYCLIC (x, 22))
#define S1(x) (CYCLIC (x, 6) ^ CYCLIC (x, 11) ^ CYCLIC (x, 25))
#define R0(x) (CYCLIC (x, 7) ^ CYCLIC (x, 18) ^ (x >> 3))
#define R1(x) (CYCLIC (x, 17) ^ CYCLIC (x, 19) ^ (x >> 10))

/* It is unfortunate that C does not provide an operator for
   cyclic rotation. Hope the C compiler is smart enough. */
#define CYCLIC(w, s) ((w >> s) | (w << (32 - s)))

        /* Compute the message schedule according to FIPS 180-2:6.2.2 step 2. */
		for (t = 0; t < 16; ++t) {
			W[t] = SWAP (*words);
			++words;
		}
		for (t = 16; t < 64; ++t)
			W[t] = R1 (W[t - 2]) + W[t - 7] + R0 (W[t - 15]) + W[t - 16];

        /* The actual computation according to FIPS 180-2:6.2.2 step 3. */
		for (t = 0; t < 64; ++t) {
			uint32_t T1 = h + S1 (e) + Ch (e, f, g) + K[t] + W[t];
			uint32_t T2 = S0 (a) + Maj (a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}

        /* Add the starting values of the context according to FIPS 180-2:6.2.2 step 4. */
		a += a_save;
		b += b_save;
		c += c_save;
		d += d_save;
		e += e_save;
		f += f_save;
		g += g_save;
		h += h_save;

        /* Prepare for the next round. */
		nwords -= 16;
	}

    /* Put checksum in context given as argument. */
	ctx->H[0] = a;
	ctx->H[1] = b;
	ctx->H[2] = c;
	ctx->H[3] = d;
	ctx->H[4] = e;
	ctx->H[5] = f;
	ctx->H[6] = g;
	ctx->H[7] = h;
}



/* Initialize structure containing state of computation.
   (FIPS 180-2:5.3.2) */
static void sha256_init_ctx(struct sha256_ctx *ctx)
{
	ctx->H[0] = 0x6a09e667;
	ctx->H[1] = 0xbb67ae85;
	ctx->H[2] = 0x3c6ef372;
	ctx->H[3] = 0xa54ff53a;
	ctx->H[4] = 0x510e527f;
	ctx->H[5] = 0x9b05688c;
	ctx->H[6] = 0x1f83d9ab;
	ctx->H[7] = 0x5be0cd19;

	ctx->total[0] = ctx->total[1] = 0;
	ctx->buflen = 0;
}



/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value. */
static void * sha256_finish_ctx(struct sha256_ctx *ctx, void *resbuf)
{
    /* Take yet unprocessed bytes into account. */
	uint32_t bytes = ctx->buflen;
	size_t pad;
	unsigned int i;

    /* Now count remaining bytes. */
	ctx->total[0] += bytes;
	if (ctx->total[0] < bytes) {
		++ctx->total[1];
	}

	pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
	memcpy(&ctx->buffer[bytes], fillbuf, pad);

    /* Put the 64-bit file length in *bits* at the end of the buffer. */
	*(uint32_t *) &ctx->buffer[bytes + pad + 4] = SWAP (ctx->total[0] << 3);
	*(uint32_t *) &ctx->buffer[bytes + pad] = SWAP ((ctx->total[1] << 3) |
						  (ctx->total[0] >> 29));

    /* Process last bytes. */
	sha256_process_block(ctx->buffer, bytes + pad + 8, ctx);

    /* Put result from CTX in first 32 bytes following RESBUF. */
	for (i = 0; i < 8; ++i) {
		((uint32_t *) resbuf)[i] = SWAP(ctx->H[i]);
	}

	return resbuf;
}



#ifdef ZEND_WIN32
# define ZEND_SET_ALIGNED(alignment, decl) __declspec(align(alignment)) decl
#elif defined(HAVE_ATTRIBUTE_ALIGNED)
# define ZEND_SET_ALIGNED(alignment, decl) decl __attribute__ ((__aligned__ (alignment)))
#else
# define ZEND_SET_ALIGNED(alignment, decl) decl
#endif



static void sha256_process_bytes(const void *buffer, size_t len, struct sha256_ctx *ctx)
{
    /* When we already have some bits in our internal buffer concatenate both inputs first. */
	if (ctx->buflen != 0) {
		size_t left_over = ctx->buflen;
		size_t add = 128 - left_over > len ? len : 128 - left_over;

		  memcpy(&ctx->buffer[left_over], buffer, add);
		  ctx->buflen += (uint32_t)add;

		if (ctx->buflen > 64) {
			sha256_process_block(ctx->buffer, ctx->buflen & ~63, ctx);
			ctx->buflen &= 63;
            /* The regions in the following copy operation cannot overlap. */
			memcpy(ctx->buffer, &ctx->buffer[(left_over + add) & ~63], ctx->buflen);
		}

		buffer = (const char *) buffer + add;
		len -= add;
	}

    /* Process available complete blocks. */
	if (len >= 64) {
/* To check alignment gcc has an appropriate operator. Other compilers don't. */
#if __GNUC__ >= 2
# define UNALIGNED_P(p) (((uintptr_t) p) % __alignof__ (uint32_t) != 0)
#else
# define UNALIGNED_P(p) (((uintptr_t) p) % sizeof (uint32_t) != 0)
#endif
		if (UNALIGNED_P (buffer))
			while (len > 64) {
				sha256_process_block(memcpy(ctx->buffer, buffer, 64), 64, ctx);
				buffer = (const char *) buffer + 64;
				len -= 64;
			} else {
				sha256_process_block(buffer, len & ~63, ctx);
				buffer = (const char *) buffer + (len & ~63);
				len &= 63;
			}
	}

    /* Move remaining bytes into internal buffer. */
	if (len > 0) {
		size_t left_over = ctx->buflen;

		memcpy(&ctx->buffer[left_over], buffer, len);
		left_over += len;
		if (left_over >= 64) {
			sha256_process_block(ctx->buffer, 64, ctx);
			left_over -= 64;
			memcpy(ctx->buffer, &ctx->buffer[64], left_over);
		}
		ctx->buflen = (uint32_t)left_over;
	}
}



/* Define our magic string to mark salt for SHA256 "encryption" replacement. */
static const char sha256_salt_prefix[] = "$5$";

/* Prefix for optional rounds specification. */
static const char sha256_rounds_prefix[] = "rounds=";

/* Maximum salt string length. */
#define SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified. */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds. */
#define ROUNDS_MIN 1000
/* Maximum number of rounds. */
#define ROUNDS_MAX 999999999

/* Table with characters for base64 transformation. */
static const char b64t[64] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#ifdef ZEND_WIN32
#define ZEND_SECURE_ZERO(var, size) RtlSecureZeroMemory((var), (size))
#else
#define ZEND_SECURE_ZERO(var, size) explicit_bzero((var), (size))
#endif



char * php_sha256_crypt_r(const char *key, const char *salt, char *buffer, int buflen)
{
#ifdef PHP_WIN32
	ZEND_SET_ALIGNED(32, unsigned char alt_result[32]);
	ZEND_SET_ALIGNED(32, unsigned char temp_result[32]);
#else
	ZEND_SET_ALIGNED(__alignof__ (uint32_t), unsigned char alt_result[32]);
	ZEND_SET_ALIGNED(__alignof__ (uint32_t), unsigned char temp_result[32]);
#endif

	struct sha256_ctx ctx;
	struct sha256_ctx alt_ctx;
	size_t salt_len;
	size_t key_len;
	size_t cnt;
	char *cp;
	char *copied_key = NULL;
	char *copied_salt = NULL;
	char *p_bytes;
	char *s_bytes;
    /* Default number of rounds. */
	size_t rounds = ROUNDS_DEFAULT;
	bool rounds_custom = 0;

    /* Find beginning of salt string. The prefix should normally always be present. Just in case it is not. */
	if (strncmp(sha256_salt_prefix, salt, sizeof(sha256_salt_prefix) - 1) == 0) {
        /* Skip salt prefix. */
		salt += sizeof(sha256_salt_prefix) - 1;
	}

	if (strncmp(salt, sha256_rounds_prefix, sizeof(sha256_rounds_prefix) - 1) == 0) {
		const char *num = salt + sizeof(sha256_rounds_prefix) - 1;
		char *endp;
		zend_ulong srounds = ZEND_STRTOUL(num, &endp, 10);
		if (*endp == '$') {
			salt = endp + 1;
			if (srounds < ROUNDS_MIN || srounds > ROUNDS_MAX) {
				return NULL;
			}

			rounds = srounds;
			rounds_custom = 1;
		}
	}

	salt_len = MIN(strcspn(salt, "$"), SALT_LEN_MAX);
	key_len = strlen(key);

	if ((key - (char *) 0) % __alignof__ (uint32_t) != 0) {
		char *tmp = (char *) alloca(key_len + __alignof__(uint32_t));
		key = copied_key = memcpy(tmp + __alignof__(uint32_t) - (tmp - (char *) 0) % __alignof__(uint32_t), key, key_len);
	}

	if ((salt - (char *) 0) % __alignof__(uint32_t) != 0) {
		char *tmp = (char *) alloca(salt_len + 1 + __alignof__(uint32_t));
		salt = copied_salt =
		memcpy(tmp + __alignof__(uint32_t) - (tmp - (char *) 0) % __alignof__ (uint32_t), salt, salt_len);
		copied_salt[salt_len] = 0;
	}

    /* Prepare for the real work. */
	sha256_init_ctx(&ctx);

    /* Add the key string. */
	sha256_process_bytes(key, key_len, &ctx);

    /* The last part is the salt string. This must be at most 16
       characters and it ends at the first `$' character (for
       compatibility with existing implementations). */
	sha256_process_bytes(salt, salt_len, &ctx);


    /* Compute alternate SHA256 sum with input KEY, SALT, and KEY. The
       final result will be added to the first context. */
	sha256_init_ctx(&alt_ctx);

    /* Add key. */
	sha256_process_bytes(key, key_len, &alt_ctx);

    /* Add salt. */
	sha256_process_bytes(salt, salt_len, &alt_ctx);

    /* Add key again. */
	sha256_process_bytes(key, key_len, &alt_ctx);

    /* Now get result of this (32 bytes) and add it to the other context. */
	sha256_finish_ctx(&alt_ctx, alt_result);

    /* Add for any character in the key one byte of the alternate sum. */
	for (cnt = key_len; cnt > 32; cnt -= 32) {
		sha256_process_bytes(alt_result, 32, &ctx);
	}
	sha256_process_bytes(alt_result, cnt, &ctx);

	/* Take the binary representation of the length of the key and for every
       1 add the alternate sum, for every 0 the key. */
	for (cnt = key_len; cnt > 0; cnt >>= 1) {
		if ((cnt & 1) != 0) {
			sha256_process_bytes(alt_result, 32, &ctx);
		} else {
			sha256_process_bytes(key, key_len, &ctx);
		}
	}

    /* Create intermediate result. */
	sha256_finish_ctx(&ctx, alt_result);

    /* Start computation of P byte sequence. */
	sha256_init_ctx(&alt_ctx);

    /* For every character in the password add the entire password. */
	for (cnt = 0; cnt < key_len; ++cnt) {
		sha256_process_bytes(key, key_len, &alt_ctx);
	}

    /* Finish the digest. */
	sha256_finish_ctx(&alt_ctx, temp_result);

    /* Create byte sequence P. */
	cp = p_bytes = alloca(key_len);
	for (cnt = key_len; cnt >= 32; cnt -= 32) {
		cp = __php_mempcpy((void *)cp, (const void *)temp_result, 32);
	}
	memcpy(cp, temp_result, cnt);

    /* Start computation of S byte sequence. */
	sha256_init_ctx(&alt_ctx);

    /* For every character in the password add the entire password. */
	for (cnt = 0; cnt < (size_t) (16 + alt_result[0]); ++cnt) {
		sha256_process_bytes(salt, salt_len, &alt_ctx);
	}

    /* Finish the digest. */
	sha256_finish_ctx(&alt_ctx, temp_result);

    /* Create byte sequence S. */
	cp = s_bytes = alloca(salt_len);
	for (cnt = salt_len; cnt >= 32; cnt -= 32) {
		cp = __php_mempcpy(cp, temp_result, 32);
	}
	memcpy(cp, temp_result, cnt);

    /* Repeatedly run the collected hash value through SHA256 to burn CPU cycles. */
	for (cnt = 0; cnt < rounds; ++cnt) {
        /* New context. */
		sha256_init_ctx(&ctx);

        /* Add key or last result. */
		if ((cnt & 1) != 0) {
			sha256_process_bytes(p_bytes, key_len, &ctx);
		} else {
			sha256_process_bytes(alt_result, 32, &ctx);
		}

        /* Add salt for numbers not divisible by 3. */
		if (cnt % 3 != 0) {
			sha256_process_bytes(s_bytes, salt_len, &ctx);
		}

        /* Add key for numbers not divisible by 7. */
		if (cnt % 7 != 0) {
			sha256_process_bytes(p_bytes, key_len, &ctx);
		}

        /* Add key or last result. */
		if ((cnt & 1) != 0) {
			sha256_process_bytes(alt_result, 32, &ctx);
		} else {
			sha256_process_bytes(p_bytes, key_len, &ctx);
		}

        /* Create intermediate result. */
		sha256_finish_ctx(&ctx, alt_result);
	}

    /* Now we can construct the result string. It consists of three	parts. */
	cp = __php_stpncpy(buffer, sha256_salt_prefix, MAX(0, buflen));
	buflen -= sizeof(sha256_salt_prefix) - 1;

	if (rounds_custom) {
#ifdef PHP_WIN32
		int n = _snprintf(cp, MAX(0, buflen), "%s" ZEND_ULONG_FMT "$", sha256_rounds_prefix, rounds);
#else
		int n = snprintf(cp, MAX(0, buflen), "%s%zu$", sha256_rounds_prefix, rounds);
#endif
		cp += n;
		buflen -= n;
	}

	cp = __php_stpncpy(cp, salt, MIN ((size_t) MAX (0, buflen), salt_len));
	buflen -= MIN(MAX (0, buflen), (int)salt_len);

	if (buflen > 0) {
		*cp++ = '$';
		--buflen;
	}

#define b64_from_24bit(B2, B1, B0, N)                       \
    do {                                                    \
        unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0); \
        int n = (N);							            \
        while (n-- > 0 && buflen > 0)                       \
        {                                                   \
            *cp++ = b64t[w & 0x3f];                         \
            --buflen;                                       \
            w >>= 6;                                        \
        }                                                   \
    } while (0)

	b64_from_24bit(alt_result[0], alt_result[10], alt_result[20], 4);
	b64_from_24bit(alt_result[21], alt_result[1], alt_result[11], 4);
	b64_from_24bit(alt_result[12], alt_result[22], alt_result[2], 4);
	b64_from_24bit(alt_result[3], alt_result[13], alt_result[23], 4);
	b64_from_24bit(alt_result[24], alt_result[4], alt_result[14], 4);
	b64_from_24bit(alt_result[15], alt_result[25], alt_result[5], 4);
	b64_from_24bit(alt_result[6], alt_result[16], alt_result[26], 4);
	b64_from_24bit(alt_result[27], alt_result[7], alt_result[17], 4);
	b64_from_24bit(alt_result[18], alt_result[28], alt_result[8], 4);
	b64_from_24bit(alt_result[9], alt_result[19], alt_result[29], 4);
	b64_from_24bit(0, alt_result[31], alt_result[30], 3);

	if (buflen <= 0) {
		errno = ERANGE;
		buffer = NULL;
	} else
        *cp = '\0';	/* Terminate the string. */

	/* Clear the buffer for the intermediate result so that people
       attaching to processes or reading core dumps cannot get any
       information.  We do it in this way to clear correct_words[]
       inside the SHA256 implementation as well. */
	sha256_init_ctx(&ctx);
	sha256_finish_ctx(&ctx, alt_result);
	ZEND_SECURE_ZERO(temp_result, sizeof(temp_result));
	ZEND_SECURE_ZERO(p_bytes, key_len);
	ZEND_SECURE_ZERO(s_bytes, salt_len);
	ZEND_SECURE_ZERO(&ctx, sizeof(ctx));
	ZEND_SECURE_ZERO(&alt_ctx, sizeof(alt_ctx));

	if (copied_key != NULL) {
		ZEND_SECURE_ZERO(copied_key, key_len);
	}
	if (copied_salt != NULL) {
		ZEND_SECURE_ZERO(copied_salt, salt_len);
	}

	return buffer;
}



#ifdef ZTS
#define ZEND_TLS static TSRM_TLS
#define ZEND_EXT_TLS TSRM_TLS
#else
#define ZEND_TLS static
#define ZEND_EXT_TLS
#endif



/* This entry point is equivalent to the `crypt' function in Unix libcs. */
char* php_sha256_crypt(const char *key, const char *salt)
{
	/* We don't want to have an arbitrary limit in the size of the
       password. We can compute an upper bound for the size of the
       result in advance and so we can prepare the buffer we pass to
       `sha256_crypt_r'. */
	ZEND_TLS char *buffer;
	ZEND_TLS int buflen = 0;
	int needed = (sizeof(sha256_salt_prefix) - 1
			+ sizeof(sha256_rounds_prefix) + 9 + 1
			+ (int)strlen(salt) + 1 + 43 + 1);

	if (buflen < needed) {
		char *new_buffer = (char *) realloc(buffer, needed);
		if (new_buffer == NULL) {
			return NULL;
		}

		buffer = new_buffer;
		buflen = needed;
	}

	return php_sha256_crypt_r(key, salt, buffer, buflen);
}



#ifdef TEST
static const struct
{
	const char *input;
	const char result[32];
} tests[] =
	{
	/* Test vectors from FIPS 180-2: appendix B.1.  */
	{ "abc",
	"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
	"\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad" },
	/* Test vectors from FIPS 180-2: appendix B.2.  */
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
	"\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1" },
	/* Test vectors from the NESSIE project.  */
	{ "",
	"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
	"\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55" },
	{ "a",
	"\xca\x97\x81\x12\xca\x1b\xbd\xca\xfa\xc2\x31\xb3\x9a\x23\xdc\x4d"
	"\xa7\x86\xef\xf8\x14\x7c\x4e\x72\xb9\x80\x77\x85\xaf\xee\x48\xbb" },
	{ "message digest",
	"\xf7\x84\x6f\x55\xcf\x23\xe1\x4e\xeb\xea\xb5\xb4\xe1\x55\x0c\xad"
	"\x5b\x50\x9e\x33\x48\xfb\xc4\xef\xa3\xa1\x41\x3d\x39\x3c\xb6\x50" },
	{ "abcdefghijklmnopqrstuvwxyz",
	"\x71\xc4\x80\xdf\x93\xd6\xae\x2f\x1e\xfa\xd1\x44\x7c\x66\xc9\x52"
	"\x5e\x31\x62\x18\xcf\x51\xfc\x8d\x9e\xd8\x32\xf2\xda\xf1\x8b\x73" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
	"\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1" },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	"\xdb\x4b\xfc\xbd\x4d\xa0\xcd\x85\xa6\x0c\x3c\x37\xd3\xfb\xd8\x80"
	"\x5c\x77\xf1\x5f\xc6\xb1\xfd\xfe\x61\x4e\xe0\xa7\xc8\xfd\xb4\xc0" },
	{ "123456789012345678901234567890123456789012345678901234567890"
	"12345678901234567890",
	"\xf3\x71\xbc\x4a\x31\x1f\x2b\x00\x9e\xef\x95\x2d\xd8\x3c\xa8\x0e"
	"\x2b\x60\x02\x6c\x8e\x93\x55\x92\xd0\xf9\xc3\x08\x45\x3c\x81\x3e" }
  };
#define ntests (sizeof (tests) / sizeof (tests[0]))


static const struct
{
	const char *salt;
	const char *input;
	const char *expected;
} tests2[] =
{
	{ "$5$saltstring", "Hello world!",
	"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5" },
	{ "$5$rounds=10000$saltstringsaltstring", "Hello world!",
	"$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2."
	"opqey6IcA" },
	{ "$5$rounds=5000$toolongsaltstring", "This is just a test",
	"$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8"
	"mGRcvxa5" },
	{ "$5$rounds=1400$anotherlongsaltstring",
	"a very much longer text to encrypt.  This one even stretches over more"
	"than one line.",
	"$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12"
	"oP84Bnq1" },
	{ "$5$rounds=77777$short",
	"we have a short salt string but not a short password",
	"$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/" },
	{ "$5$rounds=123456$asaltof16chars..", "a short string",
	"$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/"
	"cZKmF/wJvD" },
	{ "$5$rounds=10$roundstoolow", "the minimum number is still observed",
	"$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL97"
	"2bIC" },
};
#define ntests2 (sizeof (tests2) / sizeof (tests2[0]))


int main(void) {
	struct sha256_ctx ctx;
	char sum[32];
	int result = 0;
	int cnt, i;
	char buf[1000];
	static const char expected[32] =
	"\xcd\xc7\x6e\x5c\x99\x14\xfb\x92\x81\xa1\xc7\xe2\x84\xd7\x3e\x67"
	"\xf1\x80\x9a\x48\xa4\x97\x20\x0e\x04\x6d\x39\xcc\xc7\x11\x2c\xd0";

	for (cnt = 0; cnt < (int) ntests; ++cnt) {
		sha256_init_ctx(&ctx);
		sha256_process_bytes(tests[cnt].input, strlen(tests[cnt].input), &ctx);
		sha256_finish_ctx(&ctx, sum);
		if (memcmp(tests[cnt].result, sum, 32) != 0) {
			printf("test %d run %d failed\n", cnt, 1);
			result = 1;
		}

		sha256_init_ctx(&ctx);
		for (i = 0; tests[cnt].input[i] != '\0'; ++i) {
			sha256_process_bytes(&tests[cnt].input[i], 1, &ctx);
		}
		sha256_finish_ctx(&ctx, sum);
		if (memcmp(tests[cnt].result, sum, 32) != 0) {
			printf("test %d run %d failed\n", cnt, 2);
			result = 1;
		}
	}

	/* Test vector from FIPS 180-2: appendix B.3.  */

	memset(buf, 'a', sizeof(buf));
	sha256_init_ctx(&ctx);
	for (i = 0; i < 1000; ++i) {
		sha256_process_bytes (buf, sizeof (buf), &ctx);
	}

	sha256_finish_ctx(&ctx, sum);

	if (memcmp(expected, sum, 32) != 0) {
		printf("test %d failed\n", cnt);
		result = 1;
	}

	for (cnt = 0; cnt < ntests2; ++cnt) {
		char *cp = php_sha256_crypt(tests2[cnt].input, tests2[cnt].salt);
		if (strcmp(cp, tests2[cnt].expected) != 0) {
			printf("test %d: expected \"%s\", got \"%s\"\n", cnt, tests2[cnt].expected, cp);
			result = 1;
		}
	}

	if (result == 0)
	puts("all tests OK");

	return result;
}
#endif

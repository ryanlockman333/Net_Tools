#include <iostream>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>

typedef struct {
	u_char	perm[256];
	u_char	index1;
	u_char	index2;
} rc4_state;

static __inline void swap_bytes(u_char *a, u_char *b) {
	u_char temp_a = *a;
	*a = *b;
	*b = temp_a;
}

void rc4_init(rc4_state *const state, const u_char *key, int keylen) {
	u_char j = 0;
	int    i = 0;

	/* Initialize state with identity permutation */
	for(i = 0; i < 256; ++i)
		state->perm[i] = (u_char)i;

	state->index1 = 0;
	state->index2 = 0;
  
	/* Randomize the permutation using key data */
	for(u_char j = i = 0; i < 256; ++i) {
		j += state->perm[i] + key[i % keylen]; 
		swap_bytes(&state->perm[i], &state->perm[j]);
	}
}

/*
 * Encrypt some data using the supplied RC4 state buffer.
 * The input and output buffers may be the same buffer.
 * Since RC4 is a stream cypher, this function is used
 * for both encryption and decryption.
 */
void rc4_crypt(rc4_state *const state, const u_char *inbuf, u_char *outbuf, int buflen) {
	u_char j = 0;

	for(int i = 0; i < buflen; ++i) {
		/* Update modification indicies */
		++state->index1;
		state->index2 += state->perm[state->index1];

		/* Modify permutation */
		swap_bytes(&state->perm[state->index1], &state->perm[state->index2]);

		/* Encrypt/decrypt next byte */
		j         = state->perm[state->index1] + state->perm[state->index2];
		outbuf[i] = inbuf[i] ^ state->perm[j];
	}
}

int main(int argc, char **argv) {
    u_char *key = (u_char*)"abc", *secret = (u_char*)"fuck";
    u_char encrypt[std::strlen((char*)secret)];
    u_char decrypt[std::strlen((char*)secret)];
    rc4_state state;

    std::cout << "\n\n" << secret;

    rc4_init(&state, key, std::strlen((char*)key));
    rc4_crypt(&state, secret, encrypt, std::strlen((char*)secret));

    rc4_init(&state, key, std::strlen((char*)key));   
    rc4_crypt(&state, encrypt, decrypt, std::strlen((char*)encrypt));
    std::cout << "\n" << decrypt << std::endl;

    return 0;
}


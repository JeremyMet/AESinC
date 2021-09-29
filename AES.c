#include <stdio.h>
#include <stdint.h>
#include "constants.h"

#include <time.h>

#define rotword(x) ((x) << 8) | ((x) >> 24)
#define sb(x) SBOX[(x)&0xFF]

typedef struct {
  uint32_t basekey[4];
  uint32_t expanded_key[44];
} AES_128Key ;

uint32_t subword(uint32_t val) {
  return (sb(val >> 24) << 24) | (sb(val >> 16) << 16) | (sb(val >> 8) << 8) | (sb(val >> 0) << 0);
}

void expandKey(AES_128Key* key128) {
  int N = 4;
  int R = 11;
  uint32_t W = 0;
  for(int i=0;i<4*R;i++) {
    if (i<N) {
      W = key128->basekey[i];
    }
    else if (i >=N && (i%N)==0) {
      W = key128->expanded_key[i-N] ^ subword(rotword(W)) ^ rc[i/N-1];
    }
    else if (i >= N && i > 6 && i%N==4) {
      W = key128->expanded_key[i-N] ^ subword(W);
    }
    else {
      W = key128->expanded_key[i-N] ^ W;
    }
    key128->expanded_key[i] = W;
  }
}

AES_128Key keyConstructor(uint32_t* key) {
  AES_128Key ret;
  ret.basekey[0] = key[0];
  ret.basekey[1] = key[1];
  ret.basekey[2] = key[2];
  ret.basekey[3] = key[3];
  expandKey(&ret);
  return ret;
}

uint32_t apply_tboxes(uint32_t c0, uint32_t c1, uint32_t c2, uint32_t c3) {
  return (T0[c0 & 0xFF] ^ T1[c1 & 0xFF] ^ T2[c2 & 0xFF] ^ T3[c3 & 0xFF]);
}

void AES_Cipher128(AES_128Key* key128, uint32_t* src, uint32_t* dest) {
  int k = 4;
  uint32_t s0, s1, s2, s3;
  uint32_t t0, t1, t2, t3;
  // First Round
  s0 = src[0] ^ key128->basekey[0];
  s1 = src[1] ^ key128->basekey[1];
  s2 = src[2] ^ key128->basekey[2];
  s3 = src[3] ^ key128->basekey[3];
  // Middle Rounds
  for(int i=0; i<9; i++) {
        t0 = key128->expanded_key[k+0] ^ apply_tboxes(s0 >> 24, s1 >> 16, s2 >> 8, s3);
        t1 = key128->expanded_key[k+1] ^ apply_tboxes(s1 >> 24, s2 >> 16, s3 >> 8, s0);
        t2 = key128->expanded_key[k+2] ^ apply_tboxes(s2 >> 24, s3 >> 16, s0 >> 8, s1);
        t3 = key128->expanded_key[k+3] ^ apply_tboxes(s3 >> 24, s0 >> 16, s1 >> 8, s2);
        k += 4;
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
  } // fin de boucle sur i.
  // Last Round
  s0 = (sb(t0 >> 24) << 24) | (sb(t1 >> 16) << 16) | (sb(t2 >> 8) << 8) | sb(t3);
  s1 = (sb(t1 >> 24) << 24) | (sb(t2 >> 16) << 16) | (sb(t3 >> 8) << 8) | sb(t0);
  s2 = (sb(t2 >> 24) << 24) | (sb(t3 >> 16) << 16) | (sb(t0 >> 8) << 8) | sb(t1);
  s3 = (sb(t3 >> 24) << 24) | (sb(t0 >> 16) << 16) | (sb(t1 >> 8) << 8) | sb(t2);

  s0 ^= key128->expanded_key[k+0];
  s1 ^= key128->expanded_key[k+1];
  s2 ^= key128->expanded_key[k+2];
  s3 ^= key128->expanded_key[k+3];

  dest[0] = s0;
  dest[1] = s1;
  dest[2] = s2;
  dest[3] = s3;
}

void main() {
  // key = block2array(0x2b7e151628aed2a6abf7158809cf4f3c);
  // msg = block2array(0xae2d8a571e03ac9c9eb76fac45af8e51);

  uint32_t key[] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
  uint32_t msg[] = {0xae2d8a57, 0x1e03ac9c, 0x9eb76fac, 0x45af8e51};
  uint32_t res[] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
  AES_128Key key128 = keyConstructor(key);
  AES_Cipher128(&key128, msg, res);

  printf("0x%08x\n", res[0]);
  printf("0x%08x\n", res[1]);
  printf("0x%08x\n", res[2]);
  printf("0x%08x\n", res[3]);

  uint32_t _NB_TESTS = 10000000;
  clock_t t0 = clock();
  for(int i=0;i<_NB_TESTS;i++) {
    AES_Cipher128(&key128, msg, res);
    msg[0] = res[0]; msg[1] = res[1]; msg[2] = res[2]; msg[3] = res[3];
  }
  clock_t t1 = clock();
  double execution_time = (double) (t1-t0)/CLOCKS_PER_SEC;

  printf("Execution time for %i runs: %fs.\n", _NB_TESTS, execution_time);
  printf("0x%08x\n", res[0]);

}

#ifndef _MD5_H
#define _MD5_H

#ifndef uint8
#define uint8  unsigned char
#endif

#ifndef uint32
#define uint32 unsigned long int
#endif

typedef struct
{
    uint32 total[2];
    uint32 state[4];
    uint8 buffer[64];
}
md5_context;

int chash_cmp(char *try, unsigned char *pass,
		unsigned int seed);
unsigned char *chash_double(char *str, unsigned int seed);
#endif /* md5.h */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include "util.h"
#include "md5.h"

int conf_log_level;
FILE *conf_global_log_file;

int main(int argc, char **argv)
{
	int i;
	char *ret;
	char str[256];
	unsigned char *md5;
	unsigned int seed;

	srand(time(NULL));
	printf("Enter password:\n");
	ret = fgets(str, 256, stdin);
	srand(time(NULL));
	if (!ret)
		return 1;
	for (i = 0; i < 256 && str[i] != '\n'; i++)
		;
	if (i >= 256)
		return 2;
	str[i] = 0;

	seed = rand();
	md5 = chash_double(str, seed);
        for (i = 0; i < 20; i++)
		printf("%02x", md5[i]);
	printf("\n");
	free(md5);
	return 0;
}

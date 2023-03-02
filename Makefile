CC = gcc
CFLAGS = -Wall -Werror -O2
LDFLAGS = -lssl -lcrypto

apksigner: apksigner.c hash.c pkcs7.c zip.c config.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f apksigner

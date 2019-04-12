all:
	cc -o tcgetkey crypt.c twofish.c serpent.c tcgetkey.c -lcrypto -lm
	cc -o get_mem_dump get_mem_dump.c -lforensic1394

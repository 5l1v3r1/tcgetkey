#define _LARGEFILE64_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "crypt.h"

#define OFFSET 131072
#define FAT_OFFSET 0
#define EXT_OFFSET 2*512

int comp_entropy(unsigned char *xx, unsigned char *yy, int len)
{
    float freq[256];
    unsigned char met[256];
    int a,b,c,d,mpos,flag;
    float sum,sum1,diff;


    /* Calculate Shannon entropy of x */
    for (a=0;a<256;a++) freq[a] = 0;
    for (a=0;a<256;a++) met[a] = 0;
    mpos = 0;

    for (a=0;a<len;a++)
    {
        flag=0;
        for (b=0;b<mpos;b++) if (met[b] == xx[a]) flag = 1;
        if (flag == 0)
        {
            met[mpos]=xx[a];
            mpos++;
            d=0;
            for (c=a;c<len;c++) if (xx[a] == xx[c]) d++;
            freq[xx[a]] = (float)((float)d / (float)len);
        }
    }

    sum = (float)0;
    for (a=0;a<mpos;a++)
    {
        sum += ((freq[met[a]]) * log2f(freq[met[a]]));
    }
    sum *= (-1);

    /* Calculate Shannon entropy of y */
    for (a=0;a<256;a++) freq[a] = 0;
    for (a=0;a<256;a++) met[a] = 0;
    mpos = 0;

    for (a=0;a<len;a++)
    {
        flag=0;
        for (b=0;b<mpos;b++) if (met[b] == yy[a]) flag = 1;
        if (flag == 0)
        {
            met[mpos]=yy[a];
            mpos++;
            d=0;
            for (c=a;c<len;c++) if (yy[a] == yy[c]) d++;
            freq[yy[a]] = (float)((float)d / (float)len);
        }
    }

    sum1 = (float)0;
    for (a=0;a<mpos;a++)
    {
        sum1 += ((freq[met[a]]) * log2f(freq[met[a]]));
    }
    sum1 *= (float)(-1);

    diff = (sum1-sum);
    diff*=10;
    if (diff != diff) return 0;
    return (int)diff;
}



void usage(char *prog)
{
    printf("Usage: %s <memdump_filename> <tc_container_file> <decrypted_container>\n",prog);
    exit(1);
}


void main(int argc, char *argv[])
{
    int fd,fd1;
    off64_t off=0;
    int off_buf=0;
    off64_t origoff;
    off64_t size;
    char *buf;
    char *ptr,*sptr,*sptr2,*sptr3;
    unsigned int* iptr, *iptr2, *iptr3, *iptr4, *iptr5, *iptr6, *iptr7, *iptr8;
    uint64_t* uptr, *uptr2, *uptr3, *uptr4, *uptr5, *uptr6, *uptr7;
    int ent;
    char zerobuf[64]={0};
    uint64_t *offset;
    char *keys[1024*64];
    int keyc=0;
    int a,b,i,j,k;
    char ibuf[512];
    char obuf[512];


    if (argc<4) usage(argv[0]);
    fd=open(argv[1],O_RDONLY|O_LARGEFILE);
    if (fd<1)
    {
	printf("Cannot open %s, exiting..\n",argv[1]);
	exit(1);
    }
    size=lseek64(fd,0,SEEK_END);
    buf=malloc(1024*1024);

    printf("Scanning for keys...\n");
    lseek64(fd,0,SEEK_SET);
    off = (uint64_t)0;
    while (off<size)
    {
	/* Seek to next MB offset and read 1MB buf */
	lseek64(fd,off,SEEK_SET);
	if (read(fd,buf,1024*1024)<1) break;
	/* scan */
	for (off_buf=24+32;off_buf<(1024*1024-64-8);off_buf++)
	{
	    ptr = (char*)(buf+off_buf-4);
	    iptr2 = (unsigned int *)ptr;
	    ptr = (char*)(buf+off_buf);
	    iptr = (unsigned int *)ptr;
	    if ((*iptr == 64)&&((*iptr2 == 2)||(*iptr2 == 0)))
	    {
		/* Newer kernels: key resides 8 bytes from size */
		if (
			(comp_entropy((char*)ptr-24-32,(char*)ptr+8,64)>0) &&
			(comp_entropy((char*)ptr,(char*)ptr+8,8)>0) &&
			(comp_entropy((char*)ptr,(char*)ptr+8+8,8)>0) &&
			(*(int*)(ptr+4)==1)
		    )
		{
		    /*
		    printf("found candidate!\n",ent);
		    for (i=0;i<64;i++) printf("%02x",ptr[i+8]&255);
		    printf(" %d\n",*(int*)(ptr+4));
		    */
		    keys[keyc] = malloc(64);
		    memcpy(keys[keyc],ptr+8,64);
		    keyc++;
		}
		/* Older kernels: key resides 4 bytes from size */
		else if (
			    (comp_entropy((char*)ptr-28-32,(char*)ptr+4,64)>0) &&
			    (comp_entropy((char*)ptr,(char*)ptr+4,4)>0) &&
			    (comp_entropy((char*)ptr,(char*)ptr+4+4,4)>0) &&
			    (memcmp(ptr-32,"\x00\x00\x00\x00\x00\x00\x00\x00",8)==0)
			)
		{
		    keys[keyc] = malloc(64);
		    memcpy(keys[keyc],ptr+4,64);
		    keyc++;
		}
	    }
	}
	off+=(1024*1024)-64-128;
    }

    if (keyc==0)
    {
	printf("Unable to identify any keys :(\n");
	exit(1);
    }

    printf("Located %d key candidates in the dump.\n\n",keyc);

    /* Open the device */
    fd=open(argv[2],O_RDONLY|O_LARGEFILE);
    if (fd<1)
    {
        printf("Cannot open %s, exiting..\n",argv[1]);
        exit(1);
    }


    printf("Looking for a FAT filesystem...\n");
    lseek64(fd,OFFSET+FAT_OFFSET,SEEK_SET);
    read(fd,ibuf,512);
    /* Verifier is in the boot sector, looking for the version part, "MSDOS5.0" */

    for (a=0;a<keyc;a++)
    {
	printf("Trying AES (key %d)...\n",a);
	decrypt_aes_xts(keys[a], keys[a]+32, ibuf, obuf, 512, 256, 0);
	if (strcmp(obuf+3,"MSDOS5.0")==0)
	{
	    printf("Found FAT filesystem!\n");
	    lseek64(fd,OFFSET+FAT_OFFSET,SEEK_SET);
	    fd1 = open(argv[3],O_WRONLY|O_CREAT);
	    if (!fd1)
	    {
		printf("Cannot write to %s!\n",argv[3]);
		exit(2);
	    }
	    b=0;
	    while (read(fd,ibuf,512)==512)
	    {
		decrypt_aes_xts(keys[a], keys[a]+32, ibuf, obuf, 512, 256+b, 0);
		write(fd1,obuf,512);
		b++;
	    }
	    close(fd);
	    close(fd1);
	    printf("Device decrypted!\n\n");
	    printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
	    exit(0);
	}

	printf("Trying Twofish (key %d)...\n",a);
	decrypt_twofish_xts(keys[a], keys[a]+32, ibuf, obuf, 512, 256, 0);
	if (strcmp(obuf+3,"MSDOS5.0")==0)
	{
	    printf("Found FAT filesystem!\n");
	    lseek64(fd,OFFSET+FAT_OFFSET,SEEK_SET);
	    fd1 = open(argv[3],O_WRONLY|O_CREAT);
	    if (!fd1)
	    {
		printf("Cannot write to %s!\n",argv[3]);
		exit(2);
	    }
	    b=0;
	    while (read(fd,ibuf,512)==512)
	    {
		decrypt_twofish_xts(keys[a], keys[a]+32, ibuf, obuf, 512, 256+b, 0);
		write(fd1,obuf,512);
		b++;
	    }
	    close(fd);
	    close(fd1);
	    printf("Device decrypted!\n\n");
	    printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
	    exit(0);
	}

	printf("Trying Serpent (key %d)...\n",a);
	decrypt_serpent_xts(keys[a], keys[a]+32, ibuf, obuf, 512, 256, 0);
	if (strcmp(obuf+3,"MSDOS5.0")==0)
	{
	    printf("Found FAT filesystem!\n");
	    lseek64(fd,OFFSET+FAT_OFFSET,SEEK_SET);
	    fd1 = open(argv[3],O_WRONLY|O_CREAT);
	    if (!fd1)
	    {
		printf("Cannot write to %s!\n",argv[3]);
		exit(2);
	    }
	    b=0;
	    while (read(fd,ibuf,512)==512)
	    {
		decrypt_serpent_xts(keys[a], keys[a]+32, ibuf, obuf, 512, 256+b, 0);
		write(fd1,obuf,512);
		b++;
	    }
	    close(fd);
	    close(fd1);
	    printf("Device decrypted!\n\n");
	    printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
	    exit(0);
	}
    }

    /* 2-cipher cascades */
    if (keyc>1)
    {
        printf("Trying AES-Twofish...\n",a);
        for (i=0;i<keyc;i++)
        for (j=0;j<keyc;j++)
        if (i!=j)
        {
	    decrypt_aes_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256, 0);
	    decrypt_twofish_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256, 0);
	    if (strcmp(obuf+3,"MSDOS5.0")==0)
	    {
	        printf("Found FAT filesystem!\n");
	        lseek64(fd,OFFSET+FAT_OFFSET,SEEK_SET);
	        fd1 = open(argv[3],O_WRONLY|O_CREAT);
	        if (!fd1)
	        {
		    printf("Cannot write to %s!\n",argv[3]);
		    exit(2);
		}
		b=0;
		while (read(fd,ibuf,512)==512)
		{
		    decrypt_aes_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256+b, 0);
		    decrypt_twofish_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256+b, 0);
		    write(fd1,obuf,512);
		    b++;
		}
		close(fd);
		close(fd1);
		printf("Device decrypted!\n\n");
		printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
		exit(0);
	    }
	}

	printf("Trying Serpent-AES...\n",a);
	for (i=0;i<keyc;i++)
	for (j=0;j<keyc;j++)
	if (i!=j)
	{
	    decrypt_serpent_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256, 0);
	    decrypt_aes_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256, 0);
	    if (strcmp(obuf+3,"MSDOS5.0")==0)
	    {
	        printf("Found FAT filesystem!\n");
	        lseek64(fd,OFFSET+FAT_OFFSET,SEEK_SET);
	        fd1 = open(argv[3],O_WRONLY|O_CREAT);
	        if (!fd1)
	        {
		    printf("Cannot write to %s!\n",argv[3]);
		    exit(2);
		}
	        b=0;
	        while (read(fd,ibuf,512)==512)
	        {
		    decrypt_serpent_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256+b, 0);
		    decrypt_aes_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256+b, 0);
		    write(fd1,obuf,512);
		    b++;
		}
		close(fd);
		close(fd1);
		printf("Device decrypted!\n\n");
		printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
		exit(0);
	    }
	}

	printf("Trying Twofish-Serpent...\n",a);
	for (i=0;i<keyc;i++)
	for (j=0;j<keyc;j++)
	if (i!=j)
	{
	    decrypt_twofish_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256, 0);
	    decrypt_serpent_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256, 0);
	    if (strcmp(obuf+3,"MSDOS5.0")==0)
	    {
	        printf("Found FAT filesystem!\n");
	        lseek64(fd,OFFSET+FAT_OFFSET,SEEK_SET);
	        fd1 = open(argv[3],O_WRONLY|O_CREAT);
	        if (!fd1)
	        {
	    	    printf("Cannot write to %s!\n",argv[3]);
		    exit(2);
		}
		b=0;
		while (read(fd,ibuf,512)==512)
		{
		    decrypt_twofish_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256+b, 0);
		    decrypt_serpent_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256+b, 0);
		    write(fd1,obuf,512);
		    b++;
		}
		close(fd);
		close(fd1);
		printf("Device decrypted!\n\n");
		printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
		exit(0);
	    }
	}
    }

    /* 3-cipher cascades */
    if (keyc>2)
    {
        printf("Trying AES-Twofish-Serpent...\n",a);
        for (i=0;i<keyc;i++)
        for (j=0;j<keyc;j++)
        if (i!=j)
        for (k=0;k<keyc;k++)
        if ((k!=j)&&(k!=i))
        {
	    decrypt_aes_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256, 0);
	    decrypt_twofish_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256, 0);
	    decrypt_serpent_xts(keys[k], keys[k]+32, obuf, obuf, 512, 256, 0);
	    if (strcmp(obuf+3,"MSDOS5.0")==0)
	    {
	        printf("Found FAT filesystem!\n");
	        lseek64(fd,OFFSET+FAT_OFFSET,SEEK_SET);
	        fd1 = open(argv[3],O_WRONLY|O_CREAT);
	        if (!fd1)
	        {
		    printf("Cannot write to %s!\n",argv[3]);
		    exit(2);
		}
		b=0;
		while (read(fd,ibuf,512)==512)
		{
		    decrypt_aes_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256+b, 0);
		    decrypt_twofish_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256+b, 0);
		    decrypt_serpent_xts(keys[k], keys[k]+32, obuf, obuf, 512, 256+b, 0);
		    write(fd1,obuf,512);
		    b++;
		}
		close(fd);
		close(fd1);
		printf("Device decrypted!\n\n");
		printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
		exit(0);
	    }
	}

	printf("Trying Serpent-Twofish-AES...\n",a);
	for (i=0;i<keyc;i++)
	for (j=0;j<keyc;j++)
	if (i!=j)
	for (k=0;k<keyc;k++)
	if ((k!=j)&&(k!=i))
	{
	    decrypt_serpent_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256, 0);
	    decrypt_twofish_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256, 0);
	    decrypt_aes_xts(keys[k], keys[k]+32, obuf, obuf, 512, 256, 0);
	    if (strcmp(obuf+3,"MSDOS5.0")==0)
	    {
		printf("Found FAT filesystem!\n");
		lseek64(fd,OFFSET+FAT_OFFSET,SEEK_SET);
		fd1 = open(argv[3],O_WRONLY|O_CREAT);
		if (!fd1)
		{
		    printf("Cannot write to %s!\n",argv[3]);
		    exit(2);
		}
		b=0;
		while (read(fd,ibuf,512)==512)
		{
		    decrypt_serpent_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256+b, 0);
		    decrypt_twofish_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256+b, 0);
		    decrypt_aes_xts(keys[k], keys[k]+32, obuf, obuf, 512, 256+b, 0);
		    write(fd1,obuf,512);
		    b++;
		}
		close(fd);
		close(fd1);
		printf("Device decrypted!\n\n");
		printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
		exit(0);
	    }
	}
    }


    printf("Looking for an ext filesystem...\n");
    lseek64(fd,OFFSET+EXT_OFFSET,SEEK_SET);
    read(fd,ibuf,512);

    /* Verifier is in the 3rd sector (first superblock), looking for the magic bytes 0xef5e as well as the OS type u32 field, 0=linux */

    for (a=0;a<keyc;a++)
    {
	printf("Trying AES (key %d)...\n",a);
	decrypt_aes_xts(keys[a], keys[a]+32, ibuf, obuf, 512, 256+2, 0);
	if ((memcmp(obuf+56,"\x53\xef",2)==0)&&(memcmp(obuf+0x48,"\x00\x00\x00\x00",4)==0))
	{
	    printf("Found ext filesystem!\n");
	    lseek64(fd,OFFSET,SEEK_SET);
	    fd1 = open(argv[3],O_WRONLY|O_CREAT);
	    if (!fd1)
	    {
		printf("Cannot write to %s!\n",argv[3]);
		exit(2);
	    }
	    b=0;
	    while (read(fd,ibuf,512)==512)
	    {
		decrypt_aes_xts(keys[a], keys[a]+32, ibuf, obuf, 512, 256+b, 0);
		write(fd1,obuf,512);
		b++;
	    }
	    close(fd);
	    close(fd1);
	    printf("Device decrypted!\n\n");
	    printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
	    exit(0);
	}
	printf("Trying Twofish (key %d)...\n",a);
	decrypt_twofish_xts(keys[a], keys[a]+32, ibuf, obuf, 512, 256+2, 0);
	if ((memcmp(obuf+56,"\x53\xef",2)==0)&&(memcmp(obuf+0x48,"\x00\x00\x00\x00",4)==0))
	{
	    printf("Found ext filesystem!\n");
	    lseek64(fd,OFFSET,SEEK_SET);
	    fd1 = open(argv[3],O_WRONLY|O_CREAT);
	    if (!fd1)
	    {
		printf("Cannot write to %s!\n",argv[3]);
		exit(2);
	    }
	    b=0;
	    while (read(fd,ibuf,512)==512)
	    {
		decrypt_twofish_xts(keys[a], keys[a]+32, ibuf, obuf, 512, 256+b, 0);
		write(fd1,obuf,512);
		b++;
	    }
	    close(fd);
	    close(fd1);
	    printf("Device decrypted!\n\n");
	    printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
	    exit(0);
	}
	printf("Trying Serpent (key %d)...\n",a);
	decrypt_serpent_xts(keys[a], keys[a]+32, ibuf, obuf, 512, 256+2, 0);
	if ((memcmp(obuf+56,"\x53\xef",2)==0)&&(memcmp(obuf+0x48,"\x00\x00\x00\x00",4)==0))
	{
	    printf("Found ext filesystem!\n");
	    lseek64(fd,OFFSET,SEEK_SET);
	    fd1 = open(argv[3],O_WRONLY|O_CREAT);
	    if (!fd1)
	    {
		printf("Cannot write to %s!\n",argv[3]);
		exit(2);
	    }
	    b=0;
	    while (read(fd,ibuf,512)==512)
	    {
		decrypt_serpent_xts(keys[a], keys[a]+32, ibuf, obuf, 512, 256+b, 0);
		write(fd1,obuf,512);
		b++;
	    }
	    close(fd);
	    close(fd1);
	    printf("Device decrypted!\n\n");
	    printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
	    exit(0);
	}
    }


    /* 2-cipher cascades */
    if (keyc>1)
    {
        printf("Trying AES-Twofish...\n",a);
        for (i=0;i<keyc;i++)
        for (j=0;j<keyc;j++)
        if (i!=j)
        {
	    decrypt_aes_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256, 0);
	    decrypt_twofish_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256, 0);
	    if ((memcmp(obuf+56,"\x53\xef",2)==0)&&(memcmp(obuf+0x48,"\x00\x00\x00\x00",4)==0))
	    {
	        printf("Found FAT filesystem!\n");
	        lseek64(fd,OFFSET,SEEK_SET);
	        fd1 = open(argv[3],O_WRONLY|O_CREAT);
	        if (!fd1)
	        {
		    printf("Cannot write to %s!\n",argv[3]);
		    exit(2);
		}
		b=0;
		while (read(fd,ibuf,512)==512)
		{
		    decrypt_aes_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256+b, 0);
		    decrypt_twofish_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256+b, 0);
		    write(fd1,obuf,512);
		    b++;
		}
		close(fd);
		close(fd1);
		printf("Device decrypted!\n\n");
		printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
		exit(0);
	    }
	}

	printf("Trying Serpent-AES...\n",a);
	for (i=0;i<keyc;i++)
	for (j=0;j<keyc;j++)
	if (i!=j)
	{
	    decrypt_serpent_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256, 0);
	    decrypt_aes_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256, 0);
	    if ((memcmp(obuf+56,"\x53\xef",2)==0)&&(memcmp(obuf+0x48,"\x00\x00\x00\x00",4)==0))
	    {
	        printf("Found FAT filesystem!\n");
	        lseek64(fd,OFFSET,SEEK_SET);
	        fd1 = open(argv[3],O_WRONLY|O_CREAT);
	        if (!fd1)
	        {
		    printf("Cannot write to %s!\n",argv[3]);
		    exit(2);
		}
	        b=0;
	        while (read(fd,ibuf,512)==512)
	        {
		    decrypt_serpent_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256+b, 0);
		    decrypt_aes_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256+b, 0);
		    write(fd1,obuf,512);
		    b++;
		}
		close(fd);
		close(fd1);
		printf("Device decrypted!\n\n");
		printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
		exit(0);
	    }
	}

	printf("Trying Twofish-Serpent...\n",a);
	for (i=0;i<keyc;i++)
	for (j=0;j<keyc;j++)
	if (i!=j)
	{
	    decrypt_twofish_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256, 0);
	    decrypt_serpent_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256, 0);
	    if ((memcmp(obuf+56,"\x53\xef",2)==0)&&(memcmp(obuf+0x48,"\x00\x00\x00\x00",4)==0))
	    {
	        printf("Found FAT filesystem!\n");
	        lseek64(fd,OFFSET,SEEK_SET);
	        fd1 = open(argv[3],O_WRONLY|O_CREAT);
	        if (!fd1)
	        {
	    	    printf("Cannot write to %s!\n",argv[3]);
		    exit(2);
		}
		b=0;
		while (read(fd,ibuf,512)==512)
		{
		    decrypt_twofish_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256+b, 0);
		    decrypt_serpent_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256+b, 0);
		    write(fd1,obuf,512);
		    b++;
		}
		close(fd);
		close(fd1);
		printf("Device decrypted!\n\n");
		printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
		exit(0);
	    }
	}
    }

    /* 3-cipher cascades */
    if (keyc>2)
    {
        printf("Trying AES-Twofish-Serpent...\n",a);
        for (i=0;i<keyc;i++)
        for (j=0;j<keyc;j++)
        if (i!=j)
        for (k=0;k<keyc;k++)
        if ((k!=j)&&(k!=i))
        {
	    decrypt_aes_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256, 0);
	    decrypt_twofish_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256, 0);
	    decrypt_serpent_xts(keys[k], keys[k]+32, obuf, obuf, 512, 256, 0);
	    if ((memcmp(obuf+56,"\x53\xef",2)==0)&&(memcmp(obuf+0x48,"\x00\x00\x00\x00",4)==0))
	    {
	        printf("Found FAT filesystem!\n");
	        lseek64(fd,OFFSET,SEEK_SET);
	        fd1 = open(argv[3],O_WRONLY|O_CREAT);
	        if (!fd1)
	        {
		    printf("Cannot write to %s!\n",argv[3]);
		    exit(2);
		}
		b=0;
		while (read(fd,ibuf,512)==512)
		{
		    decrypt_aes_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256+b, 0);
		    decrypt_twofish_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256+b, 0);
		    decrypt_serpent_xts(keys[k], keys[k]+32, obuf, obuf, 512, 256+b, 0);
		    write(fd1,obuf,512);
		    b++;
		}
		close(fd);
		close(fd1);
		printf("Device decrypted!\n\n");
		printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
		exit(0);
	    }
	}

	printf("Trying Serpent-Twofish-AES...\n",a);
	for (i=0;i<keyc;i++)
	for (j=0;j<keyc;j++)
	if (i!=j)
	for (k=0;k<keyc;k++)
	if ((k!=j)&&(k!=i))
	{
	    decrypt_serpent_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256, 0);
	    decrypt_twofish_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256, 0);
	    decrypt_aes_xts(keys[k], keys[k]+32, obuf, obuf, 512, 256, 0);
	    if ((memcmp(obuf+56,"\x53\xef",2)==0)&&(memcmp(obuf+0x48,"\x00\x00\x00\x00",4)==0))
	    {
		printf("Found FAT filesystem!\n");
		lseek64(fd,OFFSET,SEEK_SET);
		fd1 = open(argv[3],O_WRONLY|O_CREAT);
		if (!fd1)
		{
		    printf("Cannot write to %s!\n",argv[3]);
		    exit(2);
		}
		b=0;
		while (read(fd,ibuf,512)==512)
		{
		    decrypt_serpent_xts(keys[i], keys[i]+32, ibuf, obuf, 512, 256+b, 0);
		    decrypt_twofish_xts(keys[j], keys[j]+32, obuf, obuf, 512, 256+b, 0);
		    decrypt_aes_xts(keys[k], keys[k]+32, obuf, obuf, 512, 256+b, 0);
		    write(fd1,obuf,512);
		    b++;
		}
		close(fd);
		close(fd1);
		printf("Device decrypted!\n\n");
		printf("Now you can do:\n===================\nlosetup /dev/loop0 %s\nmount /dev/loop0 /mnt/decrypted\n\n",argv[3]);
		exit(0);
	    }
	}
    }





    close(fd);
}

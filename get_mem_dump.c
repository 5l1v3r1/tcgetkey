#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <assert.h>
#include <forensic1394.h>

void usage(char *myprog)
{
    printf("Usage: %s <memdump_file>\n",myprog);
    exit(1);
}


void main(int argc, char *argv[])
{
    forensic1394_bus *bus;
    forensic1394_dev **dev;
    char data[2048];
    char zerodata[2048];
    forensic1394_result result;
    uint64_t a,b;
    int fd;
    int ndev;
    uint64_t readcnt;

    if (argc<2) usage(argv[0]);

    fd=open(argv[1],O_WRONLY|O_CREAT,0744);
    if (fd<1) 
    {
	printf("cannot open memdump for writng!\n");
	exit(1);
    }

    // Allocate a bus handle
    bus = forensic1394_alloc();
    assert(bus);

    // Enable SBP-2
    result = forensic1394_enable_sbp2(bus);
    if (result!=FORENSIC1394_RESULT_SUCCESS)
    {
	printf("Could not enable SBP2, exiting!\n");
	exit(2);
    }

    // Give the bus time to reinitialize
    sleep(2);

    // Get the devices attached to the systen
    dev = forensic1394_get_devices(bus, &ndev, NULL);
    assert(dev);

    // Open the first device
    result = forensic1394_open_device(dev[0]);
    if (result!=FORENSIC1394_RESULT_SUCCESS)
    {
	printf("Could not open the firewire device, exiting!\n");
	exit(2);
    }

    b=0;
    printf("Device info: %s - %s\n",forensic1394_get_device_vendor_name(dev[0]),forensic1394_get_device_product_name(dev[0]));

    printf("Getting data...\n");

    for (b=0;b<(1024*4);b++)
    for (a=0;a<(1024*1024);a+=2048)
    {
	readcnt = (uint64_t)(b*(uint64_t)(1024*1024)+a);
	result = forensic1394_read_device(dev[0],readcnt , 2048, data);

	if (result!=FORENSIC1394_RESULT_SUCCESS) goto out;
	if (((b%16)==0)&&(a==0)&&(b!=0)) {printf("\r%d MB read         ",b);fflush(stdout);}
	write(fd,data,2048);
	usleep(1);
    }

    out:
    printf("\n\n");
    printf("Finished at MB: %d\n",b);
    close(fd);

    // Close the device and destroy the bus
    forensic1394_close_device(dev[0]);
    forensic1394_destroy(bus);
}

#include <stdlib.h>
#include <stdio.h>
#include <libnet.h>

#include "header.h"

int main()
{
	char errBuf[LIBNET_ERRBUF_SIZE];
	libnet_t *l;

	char *device = "enp0s8";
	
	l = libnet_init(LIBNET_LINK, "enp0s8", errBuf);

	if (l == NULL)
	{
		printf("Error. %s\n", errBuf);

		exit(1);
	}
	else
	{
		const char *device2;
		device2 = libnet_getdevice(l);
		printf("Dispositivo: %s\n", device2);

		//EMPEZAMOS A CAPTURAR EL ARP:
		getPackets(l);
	}

	libnet_destroy(l);

	return 0;
}
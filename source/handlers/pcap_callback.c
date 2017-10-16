#include <stdlib.h>
#include <stdio.h>

#include "conf-data.h"
#include "handlers.h"

void pcap_callback(u_char *user, const struct  pcap_pkthdr *h, const u_char *bytes)
{
	struct configuration *conf_data = (struct configuration *) user;
	
	// Ensuring that the package was completely captured
	if ((h->caplen) == (h->len)){
		
		// Checking if a packet injection is needed
		if (ether_handler(bytes, h->len, conf_data)){
			int bytes_written = libnet_write(conf_data->l);
			if (bytes_written != -1){
				printf("%d bytes written.\n", bytes_written);
			}
		}

	}
}

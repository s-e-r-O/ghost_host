#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "conf-data.h"
#include "recv.h"

/* Print timeval struct in human-readable form */
void print_time(struct timeval tv);

void pcap_callback(u_char *user, const struct  pcap_pkthdr *h, const u_char *bytes)
{
	//print_time(h->ts);
	
	struct configuration *conf_data = (struct configuration *) user;


	u_int8_t *ip_addr_p = (u_int8_t*)(&(conf_data->ghost_host.ip_addr));

    printf("Address read: %d.%d.%d.%d\n", ip_addr_p[0],\
        ip_addr_p[1], ip_addr_p[2], ip_addr_p[3]);
	// To ensure that the package was completely captured
	if ((h->caplen) == (h->len)){
		ether_reader(bytes, h->len);
	}
}

void print_time(struct timeval tv)
{
	time_t time;
	struct  tm *local_time;
	char time_str[64];

	time = tv.tv_sec;
	local_time = localtime(&time);

	strftime(time_str, sizeof(time_str), "%d-%m-%Y (%H:%M:%S", local_time);
	printf("%s.%06ld)\n", time_str, tv.tv_usec);
}

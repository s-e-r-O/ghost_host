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
	// To ensure that the package was completely captured
	if ((h->caplen) == (h->len)){
		ether_reader(bytes, h->len, conf_data);
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

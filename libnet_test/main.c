#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>

int main(int nargs, char* args[])
{
	/* INITIALIZATION OF LIBNET */
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *l = libnet_init(LIBNET_RAW4, "wlan0", errbuf);
	if (l == NULL){
		printf("libnet_init() failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	/* PREPARING A ICMP PACKAGE */
	char payload[] = "c v prron :v";

	libnet_seed_prand(l);
	u_int16_t id = (u_int16_t) libnet_get_prand(LIBNET_PR16);

	u_int16_t seq = 1;

	if ( libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, id, seq,\
	(u_int8_t*) payload, sizeof(payload), l, 0) == -1){
		printf("Error building ICMP header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}

	/* PREPARING IP HEADER */
	//u_int32_t ip_addr = 0xC0A800DC   // No dio por alguna razon
	u_int32_t ip_addr = libnet_name2addr4(l, "192.168.0.220", LIBNET_DONT_RESOLVE);

	if (ip_addr == -1){
		printf("Error converting IP address: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}
	/* Using auto-build */
	if (libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + sizeof(payload),\
		IPPROTO_ICMP, ip_addr, l) == -1){
		printf("Error building IP header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}

#if 0
	/* Building from the ground */

	u_int32_t ghost_ip_addr = libnet_name2addr4(l, "192.168.0.15", LIBNET_DONT_RESOLVE);
	if (libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + sizeof(payload), \
		0, 0, 0, IPPROTO_ICMP, 64, 0, ghost_ip_addr, ip_addr, NULL, 0, l, 0) == -1){
		printf("Error building IP header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);	
	}

#endif
#if 0
	/* PREPARING ETHERNET HEADER */
	int length = 6;
	u_int8_t *mac_addr = libnet_hex_aton("B0:10:41:80:4C:D7", &length);

	if (mac_addr == NULL){
		printf("Error converting MAC address: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}

	if (libnet_autobuild_ethernet(mac_addr, 0x0800, l) == -1){
		printf("Error building ETHERNET header: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}
#endif

	/* SENDING PACKET */
	int bytes_written = libnet_write(l);
	if (bytes_written == -1){
		printf("Error writing packet: %s\n", libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}
	printf("%d bytes written.\n", bytes_written);

	libnet_destroy(l);
    exit(0);
}

#include <netinet/ip.h>
#include <netinet/in.h>

#include "handlers.h"

/* Internet Protocol (RFC791) -> https://tools.ietf.org/html/rfc791 */
/* More info on libnet functions ->	https://github.com/sam-github/libnet/blob/master/libnet/include/libnet/libnet-functions.h */

int ip_handler(const u_char *bytes, struct configuration *conf_data)
{
    struct ip *headerIP = (struct ip *) bytes;
    
	/* 
		'send' will determinate if a package injection is needed
    	'send' will be true if the package contains an ICMP echo request for our ghost IP address
	*/
	int send = icmp_handler(bytes + headerIP -> ip_hl * 4, ntohs(headerIP->ip_len) - headerIP -> ip_hl * 4, conf_data);
    
    if (send){
		extern libnet_ptag_t ip_tag;
		ip_tag = libnet_build_ipv4(	ntohs(headerIP->ip_len),  			// Total Packet Length (from IP POV)
									0, 0, 0, 							// TOS, ID, Fragmentation flags and offset
									64, IPPROTO_ICMP, 0, 				// TTL, Protocol, Checksum
									conf_data->ghost_host.ip_addr, 		// Source IP Address
									*(u_int32_t *)&headerIP->ip_src, 	// Destination IP Address
									NULL, 0, 							// Payload (not considered in this layer), Payload Length
									conf_data->l, ip_tag);				// libnet_t pointer, libnet tag of this specific IP header

		/*
			Auto-build is a simpler way to achieve packet injection, but it uses the device's real IP Address, instead
			of the ghost one that we created. (Can be used for debugging purposes in certain cases).

			Can't be altered with the use of libnet tags!!

			libnet_autobuild_ipv4(	ntohs(headerIP->ip_len), 
									IPPROTO_ICMP,  
									ip_addr, l)
		*/
	}
	
    return send;
}

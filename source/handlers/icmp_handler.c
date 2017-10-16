#include <netinet/ip_icmp.h>

#include "handlers.h"

/* ICMP (RFC792) -> https://tools.ietf.org/html/rfc792 */
/* More info on libnet functions ->	https://github.com/sam-github/libnet/blob/master/libnet/include/libnet/libnet-functions.h */

int icmp_handler(const u_char *bytes, u_int16_t total_len, struct configuration *conf_data)
{

	// 'send' will determinate if a package injection is needed
  	int send = 0;

	struct icmphdr *headerICMP = (struct icmphdr *) bytes;
	
	// Checking if the headerICMP is of type 'Echo Request'
	if (headerICMP->type == ICMP_ECHO){

		printf("Received an ICMP Echo Request for our ghost IP.\n");
		/* 
			Data encapsulated by the ICMP header (timestamp + random data)
			The echo reply has to have the same data on it (echo :v) 
		*/
  		u_char *data = (u_char *) (bytes + sizeof(*headerICMP));
  		printf("Sending an ICMP Echo Reply: ");
  		*(conf_data->libnet_tags.icmp_tag) = 
                        libnet_build_icmpv4_echo(	ICMP_ECHOREPLY, 0, 0, 					             // Type, Code, Checksum
        										    ntohs(headerICMP->un.echo.id),			             // Identification number
        										    ntohs(headerICMP->un.echo.sequence),	             // Packet sequence number
        										    data, total_len - sizeof(*headerICMP),	             // Payload, Payload Length
        										    conf_data->l, *(conf_data->libnet_tags.icmp_tag));	 // libnet_t pointer, libnet tag of this specific ICMP header
  		// 'send' is finally true :D
  		send = 1;

  	}

	return send;
}     
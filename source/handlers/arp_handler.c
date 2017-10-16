#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include "handlers.h"
#include "conf-data.h"

/* More info on libnet functions ->	https://github.com/sam-github/libnet/blob/master/libnet/include/libnet/libnet-functions.h */

int arp_handler(const u_char *bytes, bpf_u_int32 total_len, struct configuration *conf_data)
{
	
	/* 'send' will determinate if a package injection is needed */
	int send = 0;

	struct arphdr *headerARP = (struct arphdr *) bytes;

	/* ARP Payload */
	struct arppld
	{
		uint8_t ar_sha[headerARP->ar_hln];	// Source hardware address
		uint8_t ar_sip[headerARP->ar_pln];	// Source IP (protocol address)
		uint8_t ar_tha[headerARP->ar_hln];	// Target hardware address (Ignored on ARPOP_REQUEST)
		uint8_t ar_tip[headerARP->ar_pln];	// Target IP (protocol address)
	};
	
	struct arppld *payloadARP = (struct arppld *) (bytes + sizeof (*headerARP));

	/* Checking if ARP operation is a request */
	if (ntohs(headerARP->ar_op) == ARPOP_REQUEST){

		/* Checking if IP asked on ARP is our ghost IP address */
		if (*(uint32_t *)payloadARP->ar_tip == conf_data->ghost_host.ip_addr) {
			
			/* psssst.... Someone is asking for our ghost host */
			
			printf("Received an ARP request for our ghost IP.\n");

			printf("Sending an ARP reply: ");
			*(conf_data->libnet_tags.arp_tag) = 
					libnet_build_arp(	ARPHRD_ETHER, ETHERTYPE_IP, 						// Hardware Type, Protocol Type
										headerARP->ar_hln, headerARP->ar_pln, 				// Hardware Address Length, Protocol Address Length
										ARPOP_REPLY, 										// Operation
										conf_data->ghost_host.hrd_addr, 					// Source Hardware Address
										(u_int8_t *) &conf_data->ghost_host.ip_addr, 		// Source IP Address (Protocol Address)
										payloadARP->ar_sha, 								// Target Hardware Address
										payloadARP->ar_sip, 								// Target IP Address (Protocol Address)
										NULL, 0, 											// Payload (not considered), Payload Length
										conf_data->l, *(conf_data->libnet_tags.arp_tag));	// libnet_t pointer, libnet tag of this specific ARP header
			
			/*
				ARP Build is almost the same as its Auto-build counterpart, 
				but the latter can't be altered with the use of libnet_tags,
				so its use becomes inefficient when multiple packets are being sent.

				libnet_autobuild_arp(	ARPOP_REPLY, 
										conf_data->ghost_host.hrd_addr, 
										(u_int8_t *) &conf_data->ghost_host.ip_addr, 
										payloadARP->ar_sha, 
										payloadARP->ar_sip,
										conf_data->l);
			*/

			/* A packet will be sent */
			send = 1;
		}
	}

	return send;
}
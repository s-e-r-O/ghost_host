#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include "recv.h"

/* RFC826 -> https://tools.ietf.org/html/rfc826 */

struct arppld
{
	struct ether_addr ar_sha;   	/* Sender hardware address.  */
	struct in_addr ar_sip;          /* Sender IP address.  */
	struct ether_addr ar_tha;   	/* Target hardware address.  */
	struct in_addr ar_tip;          /* Target IP address.  */
};

void arp_reader(const u_char *bytes, bpf_u_int32 total_len)
{
	struct arphdr *headerARP = (struct arphdr *) bytes;

	struct arppld
	{
		uint8_t ar_sha[headerARP->ar_hln];
		uint8_t ar_sip[headerARP->ar_pln];
		uint8_t ar_tha[headerARP->ar_hln];
		uint8_t ar_tip[headerARP->ar_pln];
	};
	
	struct arppld *payloadARP = (struct arppld *) (bytes + sizeof (*headerARP));

	switch(ntohs(headerARP->ar_op)){
		case ARPOP_REQUEST:
			printf("Who has %s? ", inet_ntoa(*(struct in_addr*) payloadARP->ar_tip));
			printf("Tell %s\n", inet_ntoa(*(struct in_addr*) payloadARP->ar_sip));
			break;
		case ARPOP_REPLY:
			printf("%s is at %s\n", inet_ntoa(*(struct in_addr*) payloadARP->ar_sip), ether_ntoa((struct ether_addr*) payloadARP->ar_sha));
			break;
	}
	
	/*
	printf("Sender Hardware Address: %s\n", ether_ntoa((struct ether_addr*) payloadARP->ar_sha));
	printf("Sender IP Address: %s\n", inet_ntoa(*(struct in_addr*) payloadARP->ar_sip));
	printf("Target Hardware Address: %s\n", ether_ntoa((struct ether_addr*) payloadARP->ar_tha));
	printf("Target IP Address: %s\n", inet_ntoa(*(struct in_addr*) payloadARP->ar_tip));
	*/
	
}
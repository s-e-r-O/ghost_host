#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include "headerReader.h"


void getArp(const u_char *bytes, bpf_u_int32 dataLength, libnet_t *l)
{
	/*char *ip = "192.168.1.20";
	struct in_addr *myIpStruct;
	inet_aton(ip, myIpStruct);*/

	//uint8_t ip[4] = {0xc0, 0xA8, 0x01, 0x14};
	
	uint32_t ip = 0xC0A80114; 
	

	printf("\n------------------ ARP ------------------\n\n");

  	struct arphdr *headerARP = (struct arphdr *) bytes;
	
	struct arppld
	{
		uint8_t ar_sha[headerARP->ar_hln];		//macSource (quien pregunta)
		uint8_t ar_sip[headerARP->ar_pln];		//IPSource  (quien pregunta)
		uint8_t ar_tha[headerARP->ar_hln];		//macTarget  (el que recibe)
		uint8_t ar_tip[headerARP->ar_pln];		//IPTarget  (el que recibe)
	};

	struct arppld *payloadARP = (struct arppld *) (bytes + sizeof (*headerARP));

	switch(ntohs(headerARP->ar_op))
	{
		case ARPOP_REQUEST:
			
			if (ntohl(*(uint32_t *)(payloadARP->ar_tip)) == ip)
			{	
				printf("Who has %s? ", inet_ntoa(*(struct in_addr*) payloadARP->ar_tip));
				printf("Tell %s\n", inet_ntoa(*(struct in_addr*) payloadARP->ar_sip));
				buildArp(payloadARP->ar_sha, payloadARP->ar_sip, payloadARP->ar_tip, l);  
			}
			/*else
			{
				printf("NOOOOOOO\n");
				printf("Who has %s? ", inet_ntoa(*(struct in_addr*) payloadARP->ar_tip));
				printf("Tell %s\n", inet_ntoa(*(struct in_addr*) payloadARP->ar_sip));
				
			}*/
			break;

		case ARPOP_REPLY:
			printf("%s is at %s\n", inet_ntoa(*(struct in_addr*) payloadARP->ar_sip), ether_ntoa((struct ether_addr*) payloadARP->ar_sha));
			break;
	}

}


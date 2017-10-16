#include <netinet/ip_icmp.h>

#include "headerReader.h"


//void prepare_msg_array(char* type_msg[]);

int getICMP(const u_char *bytes, bpf_u_int32 totalLength, libnet_t *l, uint8_t *macSource, uint32_t ipSource, uint32_t ipDest)
{


  printf("\n----------------- ICMP ------------------\n\n");

	struct icmphdr *headerICMP = (struct icmphdr *) bytes;

  if (ntohs(headerICMP -> type == ICMP_ECHO))
  {
    buildICMP(l, macSource, totalLength - sizeof(*headerICMP), ipSource, ipDest);
  }
	

 /* u_int8_t type = ntohs(headerICMP->type);

  char *type_msg[NR_ICMP_TYPES];*/

  /*prepare_msg_array(type_msg);

  printf("Type: %u (%s)\n", type, type_msg[type]);
  printf("Code: %u\n", ntohl(headerICMP->code));
  printf("Checksum: %u\n", ntohl(headerICMP->checksum));

  switch(type)
  {
    case ICMP_ECHOREPLY:
      printf("Identifier: %u\n", ntohl(headerICMP->un.echo.id));
      printf("Sequence Number: %u\n", ntohl(headerICMP->un.echo.sequence));
    break;
  }
}	*/

/* Different messages depending of Type property of the ICMP Header */
/*void prepare_msg_array(char* type_msg[])
{
  type_msg[ICMP_ECHOREPLY] = "Echo Reply";
  type_msg[ICMP_DEST_UNREACH] = "Destination Unreachable";
  type_msg[ICMP_SOURCE_QUENCH] = "Source Quench";
  type_msg[ICMP_REDIRECT] = "Redirect (change route)";
  type_msg[ICMP_ECHO] = "Echo Request";
  type_msg[ICMP_TIME_EXCEEDED] = "Time Exceeded";
  type_msg[ICMP_PARAMETERPROB] = "Parameter Problem";
  type_msg[ICMP_TIMESTAMP] = "Timestamp Request";
  type_msg[ICMP_TIMESTAMPREPLY] = "Timestamp Reply";
  type_msg[ICMP_INFO_REQUEST] = "Information Request";
  type_msg[ICMP_INFO_REPLY] = "Information Reply";
} */
}
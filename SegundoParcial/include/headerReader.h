#include <stdlib.h>
#include <stdio.h>
#include <libnet.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>

/* DATA LINK LAYER */
int getEthernet(const u_char *bytes, bpf_u_int32 dataLength, libnet_t *l);

/* NETWORK LAYER */
int getIp(const u_char *bytes, bpf_u_int32 dataLength, libnet_t *l, uint8_t *macSource);
void getArp(const u_char *bytes, bpf_u_int32 dataLength, libnet_t *l);
int getICMP(const u_char *bytes, bpf_u_int32 totalLength, libnet_t *l, uint8_t *macSource, uint32_t ipSource, uint32_t ipDest);
void buildArp(uint8_t *macDest, uint8_t *ipDest, uint8_t *ipSource, libnet_t *l);
void buildICMP(libnet_t *l, uint8_t *macDest, bpf_u_int32 totalLength, uint32_t ipDest, uint32_t ipSource);


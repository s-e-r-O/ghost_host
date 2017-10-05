#include <pcap/pcap.h>

void pcap_callback(u_char * user, const struct  pcap_pkthdr *h, const u_char *bytes);
void ether_reader(const u_char *bytes, bpf_u_int32 data_len);
void ip_reader(const u_char *bytes, bpf_u_int32 data_len);
void arp_reader(const u_char *bytes, bpf_u_int32 data_len);

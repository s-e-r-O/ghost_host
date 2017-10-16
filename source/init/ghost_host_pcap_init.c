#include "init.h"

/* Initialization of libpcap */
void ghost_host_pcap_init(pcap_t** p, const char* device){

    /* errbuf is a char buffer used by libpcap to store error messages */
    char errbuf[PCAP_ERRBUF_SIZE];

    printf("Initializing libpcap with device: %s...\n", device);

    /* 
        Initialization of pcap 
            -  BUFSIZ is the maximum size of the buffer used to store captured packets
            -  1 (or any non-zero value) is for opening in promiscuous mode
            -  Buffer timeout of 500 ms
    */
    *p = pcap_open_live(device, BUFSIZ, 1, 500, errbuf);

    if (*p == NULL){
        perror(errbuf);
        exit(EXIT_FAILURE);
    }
}
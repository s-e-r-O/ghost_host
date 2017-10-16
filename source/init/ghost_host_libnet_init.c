#include "init.h"

/* Initialization of libnet */
void ghost_host_libnet_init(libnet_t** l, const char* device){
    
    /* errbuf is a char buffer used by libnet to store error messages */
    char errbuf[LIBNET_ERRBUF_SIZE];

    printf("Initializing libnet with device: %s\n", device);
    /* 
        Initialization of libnet
            - LIBNET_LINK is for modification of packets from the Link layer 
    */
    *l = libnet_init(LIBNET_LINK, device, errbuf);

    if (*l == NULL){
        printf("libnet_init() failed: %s\n", errbuf);
        libnet_destroy(*l);
        exit(EXIT_FAILURE);
    }

    /* Initialization of tags for each header used in the project */
    extern libnet_ptag_t ether_tag;
    ether_tag = LIBNET_PTAG_INITIALIZER;

    extern libnet_ptag_t ip_tag;
    ip_tag = LIBNET_PTAG_INITIALIZER;
    
    extern libnet_ptag_t arp_tag;
    arp_tag = LIBNET_PTAG_INITIALIZER;
    
    extern libnet_ptag_t icmp_tag;
    icmp_tag = LIBNET_PTAG_INITIALIZER;
    
}

#include "conf-values.h"
#include "init.h"

/* Initialization of ghost host data */
void ghost_host_data_init(struct configuration *c, libnet_t* l){

    printf("Initializing ghost host data...\n");
    
    int hrd_addr_length = 6;
    /* 
        GHOST_IP_ADDR is a constant defined in conf-values.h 
        LIBNET_DONT_RESOLVE is used to avoid resolution of DNS of the address
    */
    c->ghost_host.ip_addr = libnet_name2addr4(l, GHOST_IP_ADDR, LIBNET_DONT_RESOLVE);

    if (c->ghost_host.ip_addr == -1){
        printf("Error initializing IP address: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    /* GHOST_HRD_ADDR is a constant definde in conf-values.h */
    c->ghost_host.hrd_addr = libnet_hex_aton(GHOST_HRD_ADDR, &hrd_addr_length);

    if (c->ghost_host.hrd_addr == NULL){
        printf("Error initializing Hardware address: %s\n", libnet_geterror(l));
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }

    printf("IP: %s\n", GHOST_IP_ADDR);
    printf("MAC: %s\n", GHOST_HRD_ADDR);
}
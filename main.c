#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "recv.h"

int main(int nargs, char* args[])
{
    in_addr_t host;
    if (nargs > 1) {
        host = inet_addr(args[1]);
	printf("Ghost Host Address: %s\n", args[1]);
    } else {
        char host_str[16];
	printf("Ghost Host Address: ");
        scanf("%s", host_str);
        host = inet_addr(host_str);
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    printf("Looking up for devices...\n");
    char *device = pcap_lookupdev(errbuf);

    if(device == NULL){
        printf("ERROR. No se pudo encontrar un dispositivo. %s\n", errbuf);
        exit(1);
    }
    printf("Opening %s...\n", device);

    pcap_t* p = pcap_open_live(device, BUFSIZ, 1, 5000, errbuf);   //EL BUFSIZ ES EL NUMERO MAX DE BYTES QUE QUEREMOS CAPTURAR

    if (p == NULL){
        perror(errbuf);
        exit(-1);
    }

    printf("Starting to capture...\n");
    pcap_loop(p, -1, pcap_callback, NULL);   //devuelve 0 si ha leido el numero de paquetes especificado en el segundo parametro y un numero neg si hubo error
    exit(0);
}

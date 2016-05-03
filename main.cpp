#include <pcap.h>
#include<stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>



struct sum //packging packet
{
    libnet_ethernet_hdr a;
    libnet_arp_hdr b;
};

int main(int args,char argv[])

{

    sum *s;

    pcap_t *handle;            /* Session handle */

    u_char *packet;
    char *dev;            /* The device to sniff on */

    char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */

    dev  =  pcap_lookupdev(errbuf);

    if (dev == NULL) {

        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);

        return(2);

    }

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);



    if (handle == NULL) {

        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);

        return(2);

    }


    libnet_ethernet_hdr *ethernet_header= (libnet_ethernet_hdr *)(packet);
    libnet_arp_hdr *arp= (libnet_arp_hdr *)ethernet_header;

        ethernet_header->ether_dhost[0] = (u_int8_t)0xFF;
        ethernet_header->ether_dhost[1] = (u_int8_t)0xFF;//destination mac
        ethernet_header->ether_dhost[2] = (u_int8_t)0xFF;
        ethernet_header->ether_dhost[3] = (u_int8_t)0xFF;
        ethernet_header->ether_dhost[4] = (u_int8_t)0xFF;
        ethernet_header->ether_dhost[5] = (u_int8_t)0xFF;
        ethernet_header->ether_shost[0] = (u_int8_t)0x00; //source mac
        ethernet_header->ether_shost[1] = (u_int8_t)0x0c;
        ethernet_header->ether_shost[2] = (u_int8_t)0x29;
        ethernet_header->ether_shost[3] = (u_int8_t)0xd6;
        ethernet_header->ether_shost[4] = (u_int8_t)0x34;
        ethernet_header->ether_shost[5] = (u_int8_t)0x32;
        ethernet_header->ether_type = htons(ETHERTYPE_ARP);
        arp->ar_hln = 6;
        arp->ar_pln = 4;
        arp->ar_hrd = htons(ARPHRD_ETHER);
        arp->ar_pro = htons(0x0800);
        arp->ar_op = 1;
        arp->ar_sendermac[0] = 0x00;
        arp->ar_sendermac[1] = 0x0c;
        arp->ar_sendermac[2] = 0x29;
        arp->ar_sendermac[3] = 0xd6;
        arp->ar_sendermac[4] = 0x34;
        arp->ar_sendermac[5] = 0x32;

        char *sender_ip,*target_ip;
        target_ip[0] = 0x0c;
        target_ip[1] = 0xa8;
        target_ip[2] = 0x11;
        target_ip[3] = 0xfe;
        sender_ip = strtok(".",argv);


            for(int i = 0 ; i < 4 ; i++)
            {
                arp->ar_senderip[i] = htonl(atoi(sender_ip));
                arp->ar_targetip[i] = htonl(target_ip[i]);
            }
            for(int i = 0; i<6 ; i++)
            arp->ar_targetmac[i] = 0x00;







         s->a = *ethernet_header;
         s->b = *arp;
        const u_char *a = (u_char*)s;

    if(pcap_sendpacket(handle,a,sizeof(*s)) != 0)

             printf("packet send error!!!");

    else
            printf("send packet!!");



    /* And close the session */

    pcap_close(handle);

    return(0);

    // ..

}

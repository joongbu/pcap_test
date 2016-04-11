#include <pcap.h>
#include<stdint.h>
#include <arpa/inet.h>
#include <stdio.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int ip_destination(const u_char *p, int a, int b);
int ip_source(const u_char *p, int a, int b);
void ethernet(const u_char *p, int a, int b);
int tcp_source(const u_char *p);
int tcp_destination(const u_char *p);
int udp_source(const u_char *p);
int udp_destination(const u_char *p);


int main()

{



    pcap_t *handle;            /* Session handle */

    char *dev;            /* The device to sniff on */

    char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */
    struct bpf_program fp;        /* The compiled filter */

    char filter_exp[] = "port 23";    /* The filter expression */

    bpf_u_int32 mask;        /* Our netmask */

    bpf_u_int32 net;        /* Our IP */


    /* Define the device */

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {

        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);

        return(2);

    }


    /* Find the properties for the device */

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {

        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);

        net = 0;

        mask = 0;

    }

    /* Open the session in promiscuous mode */

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {

        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);

        return(2);

    }

    /* Compile and apply the filter */

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {

        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));

        return(2);

    }


    pcap_loop(handle, -1, got_packet, NULL);


    /* And close the session */

    pcap_close(handle);

    return(0);

}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *ethernet_header) {
    const u_char *ip_header = ethernet_header + 14;
    const u_char *tcp_header = ip_header + (ip_header[0] & 0x0f) * 4;
    const u_char *udp_header = ip_header + (ip_header[0] & 0x0f) * 4;

    ethernet(ethernet_header,0,11);
    if((int)ethernet_header[12] == 8 && (int)ethernet_header[13] == 0)
    {
        ip_source(ip_header,12,15);
        ip_destination(ip_header,16,19);
        if((int)ethernet_header[23] == 6)
        {

           tcp_source(tcp_header);
           tcp_destination(tcp_header);
        }
       if((int)ethernet_header[23] == 17)
       {

           udp_source(udp_header);
           udp_destination(udp_header);

       }

    }


}
void ethernet(const u_char *p, int a, int b)
{
    int i = 0;
    printf("ethernet destination :");
    for(i = a ; i<=b/2; i = a++)
    {
        printf("%02x",p[a]);
        if(a<b/2)
        printf(":");
    }
    printf("\n");
    printf("ethernet source :");
    for(i=b/2;i <=b;i = a++)
    {
        printf("%02x",p[a]);
        if(a<b)
        printf(":");
    }
    printf("\n");
}

int ip_destination(const u_char *p, int a, int b)
{
    int i = 0;

    printf("ip destination : ");
    for(i= a; i<=b; i = a++)
    {
        printf("%02d",p[a]);
        if(a<b)
            printf(".");
    }
    printf("\n");
    return 0;
}

int ip_source(const u_char *p, int a, int b)
{
    int i = 0;
    printf("ip source : ");
    for(i = a; i<=b; i = a++)
    {
        printf("%02d",p[a]);
        if(a<b)
            printf(".");
    }
    printf("\n");
    return 0;
}

int tcp_destination(const u_char *p)
{
    uint8_t buffer[2] = {p[2],p[3]};
    uint16_t *s = (uint16_t*) buffer;
    printf("tcp destination port : %d\n",ntohs(*s));
    return 0;
}

int tcp_source(const u_char *p)
{
    uint8_t buffer[2]= {p[0],p[1]};
    uint16_t *s = (uint16_t*) buffer;
    printf("tcp source port : %d\n",ntohs(*s));
    return 0;
}

int udp_destination(const u_char *p)
{
    uint8_t buffer[2] = {p[2],p[3]};
    uint16_t *s = (uint16_t*) buffer;
    printf("udp destination port : %d\n",ntohs(*s));
    return 0;
}

int udp_source(const u_char *p)
{
    uint8_t buffer[2]= {p[0], p[1]};
    uint16_t *s = (uint16_t*) buffer;
    printf("udp source port : %d\n",ntohs(*s));
    return 0;
}


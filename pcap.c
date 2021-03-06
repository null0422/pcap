#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <ctype.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdint.h>


int main(int argc, char *argv[])
{
    pcap_t *handle;         /*session handle*/
    char *dev;          /*The device to sniff on*/
    char errbuf[PCAP_ERRBUF_SIZE];  /*Error string*/
    struct bpf_program fp;      /*The compiled filter*/
    char filter_exp[] = "port 80";  /*The filter expression*/
    bpf_u_int32 mask;       /*Our netmask*/
    bpf_u_int32 net;        /*Our IP*/
    struct pcap_pkthdr *header; /*The header that pcap gives us*/
    int success;        /*The actual success*/

    const u_char *pkt_data;
    int cnt=0;
    int pcnt=0;
    int idx,x,y;
    
    
    /*Define the device*/
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s \n", errbuf);
        return (2);
    }
    
    /*Find the properties for the device*/
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        {
            fprintf(stderr, "Couldn't open device %s \n", dev, errbuf);
            net = 0;
            mask = 0;
        }
    /*Open the Session in promiscous mode*/
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s: %s \n", dev, errbuf);
            return(2);
        }
    /*compile and apply the filter*/
    if (pcap_compile(handle, &fp, filter_exp,0,net) == -1)
        {
            fprintf(stderr, "Couldn't parse filter %s \n", filter_exp, pcap_geterr(handle));
            return(2);
        }
    if(pcap_setfilter(handle, &fp) == -1)
        {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            
            return (2);
        }
        
    /*Grab a success*/
    while(success = pcap_next_ex(handle, &header, &pkt_data))
    {
        if(cnt<10)
        {
            printf("Packet captures %s \n", (success == 1 ? "success" : "fail"));
            printf("Jacked a packet with length of [%d] \n", header->len);
            int leng = header->len;
            for (idx = 0; idx < leng; idx++) {
                if(*(pkt_data + idx) < 16)
                    printf("0%x ", (*(pkt_data + idx) & 0xff));
                else
                    printf("%x ", (*(pkt_data + idx) & 0xff));
                if(idx%16==15)
                    printf("\n");
                else if(idx%16==7)
                    printf(" ");
                
            }
            printf("\nDMac address : ");
            for(idx=0; idx<6; idx++)
                printf("%x ",(*(pkt_data + idx) & 0xff));
            printf("\nSMAC address : ");
            for(idx=6; idx<12; idx++)
                printf("%x ",(*(pkt_data + idx) & 0xff));

            struct ip *ip_hdr;
            struct tcphdr *tcph;
            struct ether_header *ep;
            unsigned short ether_type;

            ep = (struct ether_header *)pkt_data;
            int ip_hdr_len = ip_hdr->ip_hl * 4;

            ip_hdr = (pkt_data + sizeof(struct ether_header));
            tcph = (pkt_data + sizeof(struct ether_header) + ip_hdr_len);

            struct in_addr src_ip = ip_hdr->ip_src;
            struct in_addr dst_ip = ip_hdr->ip_dst;

            char src_ip_str[25];
            char dst_ip_str[25];
            inet_ntop(AF_INET, &src_ip, src_ip_str, 24);
            inet_ntop(AF_INET, &dst_ip, dst_ip_str, 24);

            printf("\nS-IP: %s ",&(src_ip_str));
            printf("\nD-IP : %s ",&(dst_ip_str));


            printf("\nS-Port : %d", ntohs(tcph->th_sport));
            printf("\nD-Port : %d", ntohs(tcph->th_dport));
            printf("\n ");
/*            printf("\nDIP address : ");
            for(idx=26; idx<30; idx++)
                printf("%d ",(*(pkt_data + idx) & 0xff));
            printf("\nSIP address : ");
            for(idx=30; idx<34; idx++)
                printf("%d ",(*(pkt_data + idx) & 0xff));
            printf("\nDPort address : ");

            x = (*(pkt_data+34) * 256) +(*(pkt_data+35));
            printf("%d ",x);
        
            printf("\nSPort address : ");
            x = (*(pkt_data+36) * 256) +(*(pkt_data+37));
            printf("%d ",x);

            x = *(pkt_data+46) >> 4;
            y = x *4;
*/
            int tcp_hdr_len = tcph->th_off * 4;
            int offset = sizeof(struct ether_header) + ip_hdr_len + tcp_hdr_len;

            for(idx=offset; idx<=header->len; idx++)
                printf("%c", *(pkt_data + idx));        
            
            printf("\n\n\n\n");
            cnt++;
        }
        else
            break;

    }
    pcap_close(handle);
    return(0);
}       
    
    
    

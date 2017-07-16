#include<pcap.h>
#include<stdio.h>

int main(int argc, char *argv[])
{
    pcap_t *handle;         /*session handle*/
    char *dev;          /*The device to sniff on*/
    char errbuf[PCAP_ERRBUF_SIZE];  /*Error string*/
    struct bpf_program fp;      /*The compiled filter*/
    char filter_exp[] = "port 80";  /*Our netmask*/
    bpf_u_int32 mask;       /*Our IP*/
    bpf_u_int32 net;        /*The header that pcap gives us*/
    struct pcap_pkthdr header;  /*The actual packet*/
    const u_char *packet;
    
    
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
        
    /*Grab a packet*/
    packet = pcap_next(handle, &header);

    printf("%s \n", packet);
    /*print its length*/
    printf("Jacked a packet with length of [%d] \n", header.len);
    /*And close the session*/
    pcap_close(handle);
    return(0);
}       
    
    
    

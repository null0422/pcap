pcap: pcap.c
	gcc -o pcap pcap.c -l pcap

pcap.o: pcap.c
	gcc -o pcap pcap.o -l pcap

clear:
	rm *.o pcap


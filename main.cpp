#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void printMAC(const u_char* data){
  int i;
  for(i=0; i<6; i++){
    printf("%02X", *(data+i));
    if(i!=5)
      printf(":");
    else
      printf("\n");
  }
}

void printIP(const u_char* data){
  for(int i=0;i<4;i++){
    printf("%d",*(data+i));
    if(i!=3) 
      printf(".");
    else
      printf("\n");
  }
}

void printPORT(const u_char* data){
  printf("%u\n", (unsigned int)ntohs(*(uint16_t *)(data)));
}

void printDATA(const u_char* data){
  for(int i=0;i<16;i++) {
    printf("%02x ",*(data+i));
  }
  printf("\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("Source MAC : ");
    printMAC(packet+6);
    printf("Destination MAC : ");
    printMAC(packet);
    if(packet[12]==8 && packet[13]==0){
      printf("Source IP : ");
      printIP(packet+26);
      printf("Destination IP : ");
      printIP(packet+30);
      printf("Source Port : ");
      printPORT(packet+34);
      printf("Destination Port : ");
      printPORT(packet+36);
      printf("Payload : ");
      printDATA(packet+54);
    }
  }

  pcap_close(handle);
  return 0;
}

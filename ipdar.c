// kudos to http://www.programming-pcap.aldabaknocking.com/code/arpsniffer.c

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <zmq.h>
#include <assert.h>

#include "zhelpers.h"

#define forever for(;;)

#define ARP_REQUEST 1
#define SNAPSHOT_LENGTH 2048
#define TIMEOUT 1024 // ms
#define DO_OPTIMIZE 1

// https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure
#define HW_TYPE_ETHERNET 1
#define PROTOCOL_TYPE_IPV4 0x0800

typedef struct ArpHeader { 
  uint16_t hwType;
  uint16_t protocolType;
  uint8_t hwAddressLen;
  uint8_t protocolAddressLen;
  uint16_t opCode;
  uint8_t senderHwAddress[6];
  uint8_t senderIpAddress[4];
  uint8_t targetHwAddress[6];
  uint8_t targetIpAddress[4];
} ArpHeader; 

char* macString(uint8_t *mac) {
  char* str = calloc(3 * 6 + 1, 1);
  sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return str;
}

char* ipString(uint8_t *ip) {
  char* str = calloc(4 * 4 + 1, 1);
  sprintf(str, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
  return str;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "usage: ipdar [interface] [zmq address]\n");
    exit(1);
  }

  char *interfaceName = argv[1];
  char *zmqAddress = argv[2];
  char *errbuf = calloc(PCAP_ERRBUF_SIZE, 1);

  void *context = zmq_ctx_new();
  void *publisher = zmq_socket(context, ZMQ_PUB);
  int rc = zmq_bind(publisher, zmqAddress);
  assert (rc == 0);

  // Open the network device
  pcap_t *captureHandle = pcap_open_live(interfaceName, SNAPSHOT_LENGTH, 0,  TIMEOUT, errbuf);

  if (captureHandle == NULL) {
    fprintf(stderr, "Failed to obtain handle to interface: %s\n", errbuf);
    exit(1);
  }
    
  // Find the IPv4 network number and netmask for a device
  bpf_u_int32 netaddr, netmask;

  if (pcap_lookupnet(interfaceName, &netaddr, &netmask, errbuf)) {
    fprintf(stderr, "Failed to look up capture device info: %s\n", errbuf);
    exit(1);
  }

  // Compile a filter expression
  struct bpf_program filter;
  if (pcap_compile(captureHandle, &filter, "arp", DO_OPTIMIZE, netmask)) {
    fprintf(stderr, "Filter compilation failed: %s\n", errbuf);
    exit(1);
  }

  // Load the filter
  if (pcap_setfilter(captureHandle, &filter)) {
    fprintf(stderr, "Failed to load the filter: %s\n", errbuf);
    exit(1);
  }

  const unsigned char *packet;

  forever {
    // Get a packet
    struct pcap_pkthdr packetInfo;
    packet = pcap_next(captureHandle, &packetInfo);

    if (packet != NULL) {
      ArpHeader *arpheader = (struct ArpHeader *)(packet + 14);

      if (ntohs(arpheader->hwType) == HW_TYPE_ETHERNET && ntohs(arpheader->protocolType) == PROTOCOL_TYPE_IPV4) {
        char* strSenderMac = macString(arpheader->senderHwAddress);
        char* strSenderIp = ipString(arpheader->senderIpAddress);
        char* strTargetMac = macString(arpheader->targetHwAddress);
        char* strTargetIp = ipString(arpheader->targetIpAddress);

        s_send(publisher, strSenderMac);
        s_send(publisher, strSenderIp);
        s_send(publisher, strTargetMac);
        s_send(publisher, strTargetIp);

        free(strSenderMac);
        free(strSenderIp);
        free(strTargetMac);
        free(strTargetIp);
      }
    } else {
      fprintf(stderr, "Failed to get a packet: %s\n", errbuf);
    }
  }

  zmq_close(publisher);
  zmq_term(context);

  return 0;
}

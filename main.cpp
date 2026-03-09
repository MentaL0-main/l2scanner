#include <asm-generic/socket.h>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <net/ethernet.h>
#include <net/if.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

#include <sys/socket.h>
#include <unistd.h>

constexpr short PACKET_SIZE = 1024;
uint8_t buffer[PACKET_SIZE];

struct ethhdr* eth = (struct ethhdr*)buffer;
struct iphdr* ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
struct udphdr* udp = (struct udphdr*)(buffer + sizeof(struct ethhdr)
                                             + sizeof(struct iphdr));
char* data = (char*)(buffer + sizeof(struct ethhdr)
                            + sizeof(struct iphdr)
                            + sizeof(struct udphdr));

uint16_t checksum(void* vdata, int len);
void parse_mac(uint8_t* out, const std::string& mac_str);

int main(int argc, char* argv[])
{
  std::cout << "[*] Starting...\n";

  if (argc < 7)
  {
    std::cerr << "[!] Usage: sudo ./l2_scanner mac1 mac2 ip1 ip2 if_name timeout\n";
    return 1;
  }

  int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

  if (raw_sock < 0)
  {
    std::cerr << "[!] Failed to create socket! Maybe try with root?\n";
    return 1;
  }

  std::string mac;

  // std::cout << "[>] Write reciver MAC: ";
  // std::cin >> mac;
  
  mac = argv[1];
  
  parse_mac(eth->h_dest, mac);
  mac.clear();

  // std::cout << "[>] Write sender MAC: ";
  // std::cin >> mac;
  
  mac = argv[2];

  parse_mac(eth->h_source, mac);
  mac.clear();

  std::string reciver_ip, sender_ip;

  // std::cout << "[>] Write reciver IP: ";
  // std::cin >> reciver_ip;
  // std::cout << "[>] Write sender IP: ";
  // std::cin >> sender_ip;

  reciver_ip = argv[3];
  sender_ip = argv[4];

  std::cout << "[*] Reciver MAC: ";
  for (int i = 0; i < 6; ++i) std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)eth->h_dest[i] << ':';
  std::cout << std::endl;

  std::cout << "[*] Sender MAC: ";
  for (int i = 0; i < 6; ++i) std::cout << std::setw(2) << std::setfill('0') <<  std::hex << (int)eth->h_source[i] << ':';
  std::cout << std::oct << std::endl << std::flush;

  std::cout << "[*] Sender IP: " << sender_ip << '\n'
            << "[*] Reciver IP: " << reciver_ip << std::endl;

  eth->h_proto = htons(ETH_P_IP);

  const char* if_name = argv[5];
  unsigned int if_index = if_nametoindex(if_name);
  if (if_index == 0)
  {
    std::cerr << "[!] Failed find interface '"
              << if_name
              << "'!\n";
    close(raw_sock);
    return 1;
  }

  struct sockaddr_ll sll;
  std::memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = if_index;
  sll.sll_protocol = htons(ETH_P_IP);

  strcpy(data, "\n\n\nBro, you is open?\n\n\n");

  ip->version = 4;
  ip->ihl = 5;
  ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(data));
  ip->ttl = 255;
  ip->protocol = IPPROTO_UDP;
  ip->saddr = inet_addr(sender_ip.c_str());
  ip->daddr = inet_addr(reciver_ip.c_str());
  ip->check = 0;

  udp->source = htons(5000);
  udp->dest = htons(5000);
  udp->len = htons(sizeof(struct udphdr) + strlen(data));
  udp->check = 0;

  ip->check = checksum(ip, sizeof(struct iphdr));

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 100000;
  setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  char recv_data[1024];
  
  int timeout = std::stoi(argv[6]);

  for (int port = 80; port < 9999; ++port)
  {
    udp->dest = htons(port);
    udp->check = 0;
    ip->check = 0;
    ip->check = checksum(ip, sizeof(struct iphdr));

    sendto(raw_sock,
           buffer,
           sizeof(ethhdr) + ntohs(ip->tot_len),
           0,
           (struct sockaddr*)&sll,
           sizeof(sll));

    while (true)
    {
      int rec_len = recv(raw_sock, recv_data, sizeof(recv_data), 0);
    
      if (rec_len < 0)
      {
        std::cout << "[?] Port: " << port << " is OPEN or FILTERED\n";
        break;
      }

      struct iphdr* rect_ip = (struct iphdr*)(recv_data + sizeof(struct ethhdr));
  
      if (rect_ip->protocol == IPPROTO_UDP)
        continue;

      if (rect_ip->protocol == IPPROTO_ICMP)
      {
        uint8_t* icmp_ptr = (uint8_t*)rect_ip + (rect_ip->ihl * 4);
        
        if (icmp_ptr[0] == 3 && icmp_ptr[1] == 3) {
          std::cout << "[X] Port: " << port << " CLOSED\n";
          break;
        }
      }
    }

    usleep(timeout);
  }

  close(raw_sock);
  return 0;
}

uint16_t checksum(void* vdata, int len)
{
  uint16_t* data = reinterpret_cast<uint16_t*>(vdata);
  uint32_t sum = 0;

  while (len > 1)
  {
    sum += *data++;
    len -= 2;
  }

  if (len > 0)
    sum += *reinterpret_cast<uint8_t*>(data);

  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return static_cast<uint16_t>(~sum); // ~invert
}

void parse_mac(uint8_t* out, const std::string& mac)
{
  struct ether_addr* decoded = ether_aton(mac.c_str());

  if (decoded)
    std::memcpy(out, decoded, 6);
  else
    std::cout << "[!] Failed to pasrse MAC\n";
}

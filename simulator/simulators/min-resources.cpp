#include <arpa/inet.h>
#include <assert.h>
#include <math.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>

#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define MAX_PORTS 65535
#define THROUGHPUT_GIGABIT_PER_SEC 100  // Gbps
#define EXPIRATION_TIME_NS 9'000'000
#define BILLION 1'000'000'000

typedef uint64_t nanoseconds_t;

struct pkt_hdr_t {
  ether_header eth_hdr;
  iphdr ip_hdr;
  udphdr udp_hdr;
} __attribute__((packed));

struct flow_t {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;

  flow_t() : src_ip(0), dst_ip(0), src_port(0), dst_port(0) {}

  flow_t(const flow_t &flow)
      : src_ip(flow.src_ip),
        dst_ip(flow.dst_ip),
        src_port(flow.src_port),
        dst_port(flow.dst_port) {}

  flow_t(uint32_t _src_ip, uint32_t _dst_ip, uint16_t _src_port,
         uint16_t _dst_port)
      : src_ip(_src_ip),
        dst_ip(_dst_ip),
        src_port(_src_port),
        dst_port(_dst_port) {}

  bool operator==(const flow_t &other) const {
    return other.src_ip == src_ip && dst_ip == other.dst_ip &&
           src_port == other.src_port && dst_port == other.dst_port;
  }

  struct flow_hash_t {
    std::size_t operator()(const flow_t &flow) const {
      return std::hash<in_addr_t>()(flow.src_ip) ^
             std::hash<in_addr_t>()(flow.dst_ip) ^
             std::hash<uint16_t>()(flow.src_port) ^
             std::hash<uint16_t>()(flow.dst_port);
    }
  };
};

struct pkt_t {
  flow_t flow;
  nanoseconds_t ts;
};

struct OlderPkt {
  bool operator()(const pkt_t &lhs, const pkt_t &rhs) const {
    return lhs.ts < rhs.ts;
  }
};

struct pkt_data_t {
  std::vector<pkt_t> pkts;
  std::unordered_set<flow_t, flow_t::flow_hash_t> unique_flows;

  void add(const pkt_hdr_t *pkt_hdr, uint16_t sz) {
    nanoseconds_t prev = pkts.size() ? pkts.back().ts : 0;

    // conversion from Gbps to bits per nanosecond
    auto time_to_tx = (nanoseconds_t)(((double)(sz * 8)) /
                                      (double)THROUGHPUT_GIGABIT_PER_SEC);
    auto now = prev + time_to_tx;

    auto flow = flow_t(pkt_hdr->ip_hdr.saddr, pkt_hdr->ip_hdr.daddr,
                       pkt_hdr->udp_hdr.uh_sport, pkt_hdr->udp_hdr.uh_dport);

    pkts.push_back(pkt_t{flow, now});
  }
};

long get_size(const char *fname) {
  assert(fname);
  FILE *fp = fopen(fname, "r");

  // checking if the file exist or not
  if (fp == NULL) {
    fprintf(stderr, "File %s not found\n", fname);
    exit(1);
  }

  fseek(fp, 0L, SEEK_END);
  auto res = ftell(fp);
  fclose(fp);

  return res;
}

pkt_data_t get_pkts(const char *pcap_fname) {
  char errbuff[PCAP_ERRBUF_SIZE];
  pcap_t *pcap = pcap_open_offline(pcap_fname, errbuff);

  if (pcap == nullptr) {
    fprintf(stderr, "%s\n", errbuff);
    exit(1);
  }

  pcap_pkthdr *header;
  const u_char *data;

  pkt_data_t pkt_data;

  auto file_size = get_size(pcap_fname);
  file_size - 24;  // ignore header

  while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0) {
    auto pkt_hdr = reinterpret_cast<const pkt_hdr_t *>(data);
    pkt_data.add(pkt_hdr, header->len);
  }

  return pkt_data;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Usage: %s [pcap]\n", argv[0]);
    return 1;
  }

  auto pkt_data = get_pkts(argv[1]);

  std::multiset<pkt_t, OlderPkt> pkt_expirator;
  std::unordered_map<flow_t, uint64_t, flow_t::flow_hash_t> flows;

  uint64_t sent_to_controller = 0;
  uint64_t expirations = 0;
  uint64_t num_flows = 0;
  uint64_t pkt_i = 0;

  auto num_pkts = (uint64_t)pkt_data.pkts.size();
  auto start = pkt_data.pkts[0].ts;
  auto end = pkt_data.pkts.back().ts;
  auto elapsed = end - start;

  for (auto &pkt : pkt_data.pkts) {
    pkt_i++;

    for (auto it = pkt_expirator.begin(); it != pkt_expirator.end();) {
      assert(pkt.ts >= it->ts);
      auto diff = pkt.ts - it->ts;

      if (diff > EXPIRATION_TIME_NS) {
        flows.erase(it->flow);
        it = pkt_expirator.erase(it);
        expirations++;
      } else {
        break;
      }
    }

    auto flow_found = flows.find(pkt.flow);
    if (flow_found == flows.end()) {
      if (flows.size() >= MAX_PORTS) {
        fprintf(stderr, "\nError: no more available ports.\n");
        exit(1);
      }

      pkt_expirator.insert(pkt);
      flows[pkt.flow] = pkt.ts;

      sent_to_controller++;
      continue;
    }

    auto removed = false;
    auto found = pkt_expirator.find(pkt_t{pkt.flow, flows[pkt.flow]});
    while (found != pkt_expirator.end()) {
      if (pkt.flow == found->flow) {
        pkt_expirator.erase(found);
        removed = true;
        break;
      }
      found++;
    }

    if (!removed) {
      fprintf(stderr, "\nShould have removed...\n");
      exit(1);
    }

    pkt_expirator.insert(pkt);
    flows[pkt.flow] = pkt.ts;
  }
  
  printf("Time               %lu.%lu seconds\n", elapsed / BILLION,
         elapsed % BILLION);
  printf("Packets            %lu\n", num_pkts);
  printf("Sent to controller %lu (%.5f%%)\n", sent_to_controller,
         100 * (((double)sent_to_controller) / num_pkts));
  printf(
      "Expirations        %lu (%lu fpm) \n", expirations,
      (uint64_t)(60 * (((double)expirations) / ((double)(elapsed) / BILLION))));
}
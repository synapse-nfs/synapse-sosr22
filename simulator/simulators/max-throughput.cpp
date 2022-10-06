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
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define MAX_PORTS 65535
#define CONTROL_PLANE_REGISTER_WRITE_DELAY 300'000  // 300 us
#define MAX_REGISTER_ENTRIES (1 << 16)
#define THROUGHPUT_GIGABIT_PER_SEC 100  // Gbps
#define EXPIRATION_TIME_NS 9'000'000
#define BILLION 1'000'000'000

typedef uint64_t nanoseconds_t;

// CRC algorithm source:
// https://barrgroup.com/embedded-systems/how-to/crc-calculation-c-code

typedef uint16_t crc;

#define WIDTH (8 * sizeof(crc))
#define TOPBIT (1 << (WIDTH - 1))
#define CRC_POLYNOMIAL 0x18005
#define CRC_INIT 0x0
#define CRC_XOR 0x0

struct pkt_hdr_t {
  ether_header eth_hdr;
  iphdr ip_hdr;
  udphdr udp_hdr;
} __attribute__((packed));

struct crc16_t {
  crc crcTable[256];

  crc16_t() {
    crc remainder;

    // Compute the remainder of each possible dividend.
    for (int dividend = 0; dividend < 256; ++dividend) {
      // Start with the dividend followed by zeros.
      remainder = dividend << (WIDTH - 8);

      // Perform modulo-2 division, a bit at a time.
      for (uint8_t bit = 8; bit > 0; --bit) {
        // Try to divide the current data bit.
        if (remainder & TOPBIT) {
          remainder = (remainder << 1) ^ CRC_POLYNOMIAL;
        } else {
          remainder = (remainder << 1);
        }
      }

      // Store the result into the table.
      crcTable[dividend] = remainder;
    }
  }

  crc calculate(uint8_t const message[], uint16_t sz) const {
    uint8_t data;
    crc remainder = CRC_INIT;

    // Divide the message by the polynomial, a byte at a time.
    for (auto byte = 0U; byte < sz; ++byte) {
      data = message[byte] ^ (remainder >> (WIDTH - 8));
      remainder = crcTable[data] ^ (remainder << 8);
    }

    return remainder ^ CRC_XOR;
  }
};

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

  bool operator!=(const flow_t &other) const {
    return !(*this == other);
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

struct ite_key_t {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;

  ite_key_t(const flow_t &flow)
      : src_ip(flow.src_ip),
        dst_ip(flow.dst_ip),
        src_port(flow.src_port),
        dst_port(flow.dst_port) {}

  crc calculate_crc(const crc16_t &crc16) const {
    return crc16.calculate((const uint8_t *)this, sizeof(ite_key_t));
  }
};

struct eti_key_t {
  uint32_t dst_ip;
  uint16_t dst_port;
  uint16_t allocated_port;

  eti_key_t(const flow_t &flow, uint16_t _allocated_port)
      : dst_ip(flow.dst_ip),
        dst_port(flow.dst_port),
        allocated_port(_allocated_port) {}

  crc calculate_crc(const crc16_t &crc16) const {
    return crc16.calculate((const uint8_t *)this, sizeof(eti_key_t));
  }
};

struct pending_t {
  pkt_t pkt;
  crc ite_crc16;
  crc eti_crc16;

  pending_t(const pkt_t& _pkt, const crc& _ite_crc16, const crc& _eti_crc16) :
    pkt(_pkt), ite_crc16(_ite_crc16), eti_crc16(_eti_crc16) {}
};

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Usage: %s [pcap]\n", argv[0]);
    return 1;
  }

  auto pkt_data = get_pkts(argv[1]);

  uint64_t port_allocator_reg = 0;
  std::unordered_map<crc, flow_t> ite_reg;
  std::unordered_set<crc> eti_reg;
  crc16_t crc16;

  std::multiset<pkt_t, OlderPkt> pkt_expirator;
  std::unordered_map<flow_t, uint64_t, flow_t::flow_hash_t> flows;

  std::vector<pending_t> register_pending_flows;

  uint64_t sent_to_controller = 0;
  uint64_t flows_in_registers = 0;
  uint64_t collision_ite = 0;
  uint64_t collision_eti = 0;
  uint64_t max_port_dataplane = 0;
  uint64_t expirations = 0;
  uint64_t pkt_i = 0;
  uint64_t max_concurrent_flows_in_registers = 0;
  uint64_t digests_sent = 0;

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

    for (auto pending = register_pending_flows.begin();
         pending != register_pending_flows.end();) {
      auto diff = pkt.ts - pending->pkt.ts;

      if (diff >= CONTROL_PLANE_REGISTER_WRITE_DELAY) {
        pkt_expirator.insert(pkt_t{pending->pkt.flow, pkt.ts});
        flows[pending->pkt.flow] = pkt.ts;

        auto ite_erased = ite_reg.erase(pending->ite_crc16);
        auto eti_erased = eti_reg.erase(pending->eti_crc16);

        if (ite_erased != 1) {
          fprintf(stderr,
                  "\nShould have removed exactly 1 from ite, removed %lu...\n",
                  ite_erased);
          exit(1);
        }

        if (eti_erased != 1) {
          fprintf(stderr,
                  "\nShould have removed exactly 1 from ite, removed %lu...\n",
                  eti_erased);
          exit(1);
        }

        pending = register_pending_flows.erase(pending);

        flows_in_registers--;
      } else {
        pending++;
      }
    }

    auto flow_found = flows.find(pkt.flow);
    if (flow_found != flows.end()) {
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
      continue;
    }

    auto ite_key = ite_key_t(pkt.flow);
    auto ite_key_crc = ite_key.calculate_crc(crc16);

    auto ite_key_crc_found = ite_reg.find(ite_key_crc);
    if (ite_key_crc_found != ite_reg.end()) {
      auto &stored_flow = ite_reg[ite_key_crc];

      if (stored_flow != pkt.flow) {
        if (flows.size() >= MAX_PORTS) {
          fprintf(stderr, "\nError: no more available ports.\n");
          exit(1);
        }

        pkt_expirator.insert(pkt);
        flows[pkt.flow] = pkt.ts;

        collision_ite++;
        sent_to_controller++;
      }

      continue;
    }

    auto allocated_port = (port_allocator_reg++);

    auto eti_key = eti_key_t(pkt.flow, allocated_port);
    auto eti_key_crc = eti_key.calculate_crc(crc16);

    auto eti_key_crc_found = eti_reg.find(eti_key_crc);
    if (eti_key_crc_found != eti_reg.end()) {
      pkt_expirator.insert(pkt);
      flows[pkt.flow] = pkt.ts;

      port_allocator_reg--;
      sent_to_controller++;
      collision_eti++;
      continue;
    }

    register_pending_flows.emplace_back(pkt, ite_key_crc, eti_key_crc);
    ite_reg[ite_key_crc] = pkt.flow;
    eti_reg.insert(eti_key_crc);

    if (flows_in_registers == MAX_REGISTER_ENTRIES) {
      fprintf(stderr, "\nNo more space in registers.\n");
      exit(1);
    }

    digests_sent++;
    flows_in_registers++;
    max_concurrent_flows_in_registers =
        std::max(max_concurrent_flows_in_registers, flows_in_registers);
  }
  
  printf("Time                   %lu.%lu seconds\n", elapsed / BILLION,
         elapsed % BILLION);
  printf("Packets                %lu\n", num_pkts);
  printf("Sent to controller     %lu (%.5f%%)\n", sent_to_controller,
         100 * (((double)sent_to_controller) / num_pkts));
  printf("Digests sent           %lu (%.5f%%)\n", digests_sent,
         100 * (((double)digests_sent) / num_pkts));
  printf(
      "Expirations            %lu (%lu fpm) \n", expirations,
      (uint64_t)(60 * (((double)expirations) / ((double)elapsed / BILLION))));
  printf("Flows in registers     %lu (%.5f%%)\n", ite_reg.size(),
         100 * (((double)ite_reg.size()) / num_pkts));
  printf("Flows in controller    %lu (%.5f%%)\n", flows.size(),
         100 * (((double)flows.size()) / num_pkts));
  printf("Total flows            %lu (%.5f%%)\n", flows.size() + ite_reg.size(),
         100 * (((double)flows.size() + ite_reg.size()) / num_pkts));
  printf("Max Flows in registers %lu (%.5f%% capacity)\n",
         max_concurrent_flows_in_registers,
         100 * (((double)max_concurrent_flows_in_registers) /
                MAX_REGISTER_ENTRIES));
  printf("Collisions ite         %lu (%.5f%%)\n", collision_ite,
         100 * (((double)collision_ite) / num_pkts));
  printf("Collisions eti         %lu (%.5f%%)\n", collision_eti,
         100 * (((double)collision_eti) / num_pkts));

  return 0;
}
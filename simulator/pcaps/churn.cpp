#include <arpa/inet.h>
#include <assert.h>
#include <math.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>

#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define MIN_THROUGHPUT_GIGABIT_PER_SEC 1    // Gbps
#define MAX_THROUGHPUT_GIGABIT_PER_SEC 100  // Gbps

#define MIN_PACKET_SIZE_BYTES 8
#define MAX_PACKET_SIZE_BYTES 1500

#define BILLION 1'000'000'000LLU

struct pkt_hdr_t {
  ether_header eth_hdr;
  iphdr ip_hdr;
  udphdr udp_hdr;

  void pretty_print() const {
    printf("###[ Ethernet ]###\n");
    printf("  dst  %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr.ether_dhost[0],
           eth_hdr.ether_dhost[1], eth_hdr.ether_dhost[2],
           eth_hdr.ether_dhost[3], eth_hdr.ether_dhost[4],
           eth_hdr.ether_dhost[5]);
    printf("  src  %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr.ether_shost[0],
           eth_hdr.ether_shost[1], eth_hdr.ether_shost[2],
           eth_hdr.ether_shost[3], eth_hdr.ether_shost[4],
           eth_hdr.ether_shost[5]);
    printf("  type 0x%x\n", ntohs(eth_hdr.ether_type));

    printf("###[ IP ]###\n");
    printf("  ihl     %u\n", (ip_hdr.ihl & 0x0f));
    printf("  version %u\n", (ip_hdr.version & 0xf0) >> 4);
    printf("  tos     %u\n", ip_hdr.tos);
    printf("  len     %u\n", ntohs(ip_hdr.tot_len));
    printf("  id      %u\n", ntohs(ip_hdr.id));
    printf("  off     %u\n", ntohs(ip_hdr.frag_off));
    printf("  ttl     %u\n", ip_hdr.ttl);
    printf("  proto   %u\n", ip_hdr.protocol);
    printf("  chksum  0x%x\n", ntohs(ip_hdr.check));
    printf("  src     %u.%u.%u.%u\n", (ip_hdr.saddr >> 0) & 0xff,
           (ip_hdr.saddr >> 8) & 0xff, (ip_hdr.saddr >> 16) & 0xff,
           (ip_hdr.saddr >> 24) & 0xff);
    printf("  dst     %u.%u.%u.%u\n", (ip_hdr.daddr >> 0) & 0xff,
           (ip_hdr.daddr >> 8) & 0xff, (ip_hdr.daddr >> 16) & 0xff,
           (ip_hdr.daddr >> 24) & 0xff);

    printf("###[ TCP/UDP ]###\n");
    printf("  sport   %u\n", ntohs(udp_hdr.uh_sport));
    printf("  dport   %u\n", ntohs(udp_hdr.uh_dport));
    printf("\n\n");
  }
} __attribute__((packed));

/* Compute checksum for count bytes starting at addr, using one's complement of
 * one's complement sum*/
static unsigned short compute_checksum(unsigned short *addr,
                                       unsigned int count) {
  unsigned long sum = 0;
  while (count > 1) {
    sum += *addr++;
    count -= 2;
  }
  // if any bytes left, pad the bytes and add
  if (count > 0) {
    sum += ((*addr) & htons(0xFF00));
  }
  // Fold sum to 16 bits: add carrier to result
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  // one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

/* set ip checksum of a given ip header*/
void compute_ip_checksum(iphdr *iphdrp) {
  iphdrp->check = 0;
  iphdrp->check = compute_checksum((unsigned short *)iphdrp, iphdrp->ihl << 2);
}

/* set tcp checksum: given IP header and UDP datagram */
void compute_udp_checksum(iphdr *pIph, unsigned short *ipPayload) {
  unsigned long sum = 0;
  udphdr *udphdrp = (udphdr *)(ipPayload);
  unsigned short udpLen = htons(udphdrp->len);
  // printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~udp len=%dn", udpLen);
  // add the pseudo header
  // printf("add pseudo headern");
  // the source ip
  sum += (pIph->saddr >> 16) & 0xFFFF;
  sum += (pIph->saddr) & 0xFFFF;
  // the dest ip
  sum += (pIph->daddr >> 16) & 0xFFFF;
  sum += (pIph->daddr) & 0xFFFF;
  // protocol and reserved: 17
  sum += htons(IPPROTO_UDP);
  // the length
  sum += udphdrp->len;

  // add the IP payload
  // printf("add ip payloadn");
  // initialize checksum to 0
  udphdrp->check = 0;
  while (udpLen > 1) {
    sum += *ipPayload++;
    udpLen -= 2;
  }
  // if any bytes left, pad the bytes and add
  if (udpLen > 0) {
    // printf("+++++++++++++++padding: %dn", udpLen);
    sum += ((*ipPayload) & htons(0xFF00));
  }
  // Fold sum to 16 bits: add carrier to result
  // printf("add carriern");
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  // printf("one's complementn");
  sum = ~sum;
  // set computation result
  udphdrp->check =
      ((unsigned short)sum == 0x0000) ? 0xFFFF : (unsigned short)sum;
}

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

  pkt_hdr_t build_packet(uint32_t len) const {
    pkt_hdr_t pkt_hdr;

    pkt_hdr.eth_hdr.ether_dhost[0] = 0xba;
    pkt_hdr.eth_hdr.ether_dhost[1] = 0xba;
    pkt_hdr.eth_hdr.ether_dhost[2] = 0xba;
    pkt_hdr.eth_hdr.ether_dhost[3] = 0xba;
    pkt_hdr.eth_hdr.ether_dhost[4] = 0xba;
    pkt_hdr.eth_hdr.ether_dhost[5] = 0xba;

    pkt_hdr.eth_hdr.ether_shost[0] = 0xba;
    pkt_hdr.eth_hdr.ether_shost[1] = 0xba;
    pkt_hdr.eth_hdr.ether_shost[2] = 0xba;
    pkt_hdr.eth_hdr.ether_shost[3] = 0xba;
    pkt_hdr.eth_hdr.ether_shost[4] = 0xba;
    pkt_hdr.eth_hdr.ether_shost[5] = 0xba;

    pkt_hdr.eth_hdr.ether_type = htons(ETHERTYPE_IP);

    pkt_hdr.ip_hdr.version = 4;
    pkt_hdr.ip_hdr.ihl = 5;
    pkt_hdr.ip_hdr.tos = 0;
    pkt_hdr.ip_hdr.tot_len = htons(len - sizeof(ether_header));
    pkt_hdr.ip_hdr.id = 1;
    pkt_hdr.ip_hdr.frag_off = 0;
    pkt_hdr.ip_hdr.ttl = 64;
    pkt_hdr.ip_hdr.protocol = IPPROTO_UDP;
    pkt_hdr.ip_hdr.check = 0;
    pkt_hdr.ip_hdr.saddr = src_ip;
    pkt_hdr.ip_hdr.daddr = dst_ip;
    compute_ip_checksum(&pkt_hdr.ip_hdr);

    pkt_hdr.udp_hdr.uh_sport = src_port;
    pkt_hdr.udp_hdr.uh_dport = dst_port;
    pkt_hdr.udp_hdr.uh_ulen =
        htons(len - (sizeof(ether_header) + sizeof(iphdr)));

    return pkt_hdr;
  }
};

flow_t random_flow() {
  static const uint32_t u16_min = 0;
  static const uint32_t u16_max = std::numeric_limits<uint16_t>::max();

  static const uint32_t u32_min = 0;
  static const uint32_t u32_max = std::numeric_limits<uint32_t>::max();

  static std::random_device rand_dev;
  static std::mt19937 generator(rand_dev());

  static std::uniform_int_distribution<uint32_t> distr_u16(u16_min, u16_max);
  static std::uniform_int_distribution<uint32_t> distr_u32(u32_min, u32_max);

  return flow_t{distr_u32(generator), distr_u32(generator),
                static_cast<uint16_t>(distr_u16(generator)),
                static_cast<uint16_t>(distr_u16(generator))};
}

struct pkt_data_t {
  std::unordered_set<flow_t, flow_t::flow_hash_t> flows;
  std::vector<flow_t> flows_iteratable;
  std::vector<uint16_t> pkt_sizes;
  uint64_t total_sz;
  uint64_t n_pkts;

  pkt_data_t() : total_sz(0), n_pkts(0) {}

  void add(const pkt_hdr_t *pkt_hdr, uint16_t sz) {
    auto flow = flow_t(pkt_hdr->ip_hdr.saddr, pkt_hdr->ip_hdr.daddr,
                       pkt_hdr->udp_hdr.uh_sport, pkt_hdr->udp_hdr.uh_dport);
    if (flows.count(flow) == 0) {
      flows.insert(flow);
      flows_iteratable.push_back(flow);
    }

    pkt_sizes.push_back(sz);
    total_sz += sz;
    n_pkts++;
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

  fprintf(stderr, "Reading pcap... ");
  fflush(stderr);
  while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0) {
    auto pkt_hdr = reinterpret_cast<const pkt_hdr_t *>(data);
    pkt_data.add(pkt_hdr, header->len);
  }
  fprintf(stderr, "done\n");
  fflush(stderr);

  return pkt_data;
}

struct cfg_t {
  uint32_t n_slices;
  uint32_t churn_per_slice;
  uint32_t remainder;
};

cfg_t get_slices_config(const pkt_data_t &pkt_data, uint32_t churn,
                        const char *output) {
  auto churn_per_sec = (double)churn / 60.0;
  auto n_flows = pkt_data.flows.size();
  auto n_slices = (uint32_t)floor((double)pkt_data.n_pkts / (double)n_flows);
  auto active_slices = n_slices % 2 == 0 ? (uint32_t)((n_slices - 2) / 2)
                                         : (uint32_t)((n_slices - 1) / 2);

  auto min_rate_bps = MIN_THROUGHPUT_GIGABIT_PER_SEC * BILLION;
  auto max_rate_bps = MAX_THROUGHPUT_GIGABIT_PER_SEC * BILLION;

  auto max_exp_time =
      n_slices * n_flows * MIN_PACKET_SIZE_BYTES * 8 / (double)max_rate_bps;
  auto min_exp_time_at_min_rate =
      n_flows * MAX_PACKET_SIZE_BYTES * 8 / (double)min_rate_bps;

  while (max_exp_time < min_exp_time_at_min_rate) {
    // increase in steps of minimum throughput
    min_rate_bps += MIN_THROUGHPUT_GIGABIT_PER_SEC * BILLION;
    min_exp_time_at_min_rate =
        n_flows * MAX_PACKET_SIZE_BYTES * 8 / (double)min_rate_bps;
  }

  auto min_tx_time = (pkt_data.total_sz * 8.0) / (double)max_rate_bps;
  auto total_delta_flows = (uint32_t)ceil(churn_per_sec * min_tx_time / 2);
  auto churn_per_slice =
      (uint32_t)floor((double)total_delta_flows / (double)active_slices);
  auto remainder = (uint32_t)ceil(total_delta_flows % active_slices);

  auto output_report_fname = std::string(output);
  auto last_index = output_report_fname.find_last_of(".");
  if (last_index != std::string::npos) {
    output_report_fname = output_report_fname.substr(0, last_index);
  }
  output_report_fname += ".dat";

  auto output_report_file = fopen(output_report_fname.c_str(), "w");

  if (output_report_file == nullptr) {
    fprintf(stderr, "Unable to open file %s\n", output_report_fname.c_str());
  }

  fprintf(output_report_file, "Metadata\n");
  fprintf(output_report_file, "  Input\n");
  fprintf(output_report_file, "    Packets       %lu\n", pkt_data.n_pkts);
  fprintf(output_report_file, "    Size          %.3f GB\n",
          ((double)pkt_data.total_sz) * 1e-9);
  fprintf(output_report_file, "    Flows         %lu\n", n_flows);
  fprintf(output_report_file, "    Max rate      %d Gbps\n",
          MAX_THROUGHPUT_GIGABIT_PER_SEC);
  fprintf(output_report_file, "    Churn         %u fpm\n", churn);
  fprintf(output_report_file, "  Calculated\n");
  fprintf(output_report_file, "    Slices        %u\n", n_slices);
  fprintf(output_report_file, "    Active slices %u\n", active_slices);
  fprintf(output_report_file, "    Min tx time   %.2f\n", min_tx_time);
  fprintf(output_report_file, "    New flows     %u\n", total_delta_flows);
  fprintf(output_report_file, "    Churn/slice   %u\n", churn_per_slice);
  fprintf(output_report_file, "    Remaining     %u\n", remainder);
  fprintf(output_report_file, "    Min rate      %d Gbps\n",
          (int)ceil(min_rate_bps * 1e-9));
  fprintf(output_report_file, "    Min exp time  %u us\n",
          (int)ceil(min_exp_time_at_min_rate * 1e6));
  fprintf(output_report_file, "    Max exp time  %u us\n",
          (int)ceil(max_exp_time * 1e6));

  fclose(output_report_file);

  return cfg_t{n_slices, churn_per_slice, remainder};
}

std::pair<flow_t, flow_t> translate(const pkt_data_t &pkt_data,
                                    uint32_t next_flow_to_be_translated) {
  assert(next_flow_to_be_translated < pkt_data.flows.size());
  auto old_flow = pkt_data.flows_iteratable[next_flow_to_be_translated];
  auto new_flow = random_flow();
  return std::pair<flow_t, flow_t>{old_flow, new_flow};
}

typedef std::vector<std::unordered_map<flow_t, flow_t, flow_t::flow_hash_t>>
    slices_t;

slices_t build_slices(const pkt_data_t &pkt_data, const cfg_t &cfg) {
  auto n_flows = pkt_data.flows.size();
  auto n_pkts = pkt_data.n_pkts;
  auto n_slices = cfg.n_slices;
  auto churn_per_slice = cfg.churn_per_slice;
  auto remainder = cfg.remainder;

  slices_t slices = slices_t(n_slices);
  auto start = n_slices % 2 == 0 ? 2U : 1U;
  auto end = (uint32_t)(1 + (n_slices / 2));

  std::vector<uint32_t> fwd_translation_slices_i;
  std::vector<uint32_t> rev_translation_slices_i;

  for (auto i = start; i < end; i++) {
    fwd_translation_slices_i.push_back(i);
  }

  for (auto i = end; i < n_slices; i++) {
    rev_translation_slices_i.push_back(i);
  }

  assert(fwd_translation_slices_i.size() == rev_translation_slices_i.size());
  auto next_flow_to_be_translated = 0U;

  for (auto i = 0U; i < fwd_translation_slices_i.size(); i++) {
    printf("\rBuilding active slices %d/%lu", i + 1,
           fwd_translation_slices_i.size());
    fflush(stdout);

    auto fwd_slice_i = fwd_translation_slices_i[i];
    auto rev_slice_i = rev_translation_slices_i[i];

    for (auto j = 0U; j < churn_per_slice; j++) {
      auto translation_pair = translate(pkt_data, next_flow_to_be_translated);
      auto old_flow = translation_pair.first;
      auto new_flow = translation_pair.second;

      for (auto k = fwd_slice_i; k < rev_slice_i; k++) {
        slices[k][old_flow] = new_flow;
      }

      next_flow_to_be_translated = (next_flow_to_be_translated + 1) % n_flows;
    }

    if (remainder > 0) {
      auto translation_pair = translate(pkt_data, next_flow_to_be_translated);
      auto old_flow = translation_pair.first;
      auto new_flow = translation_pair.second;

      for (auto k = fwd_slice_i; k < rev_slice_i; k++) {
        slices[k][old_flow] = new_flow;
      }

      remainder--;
      next_flow_to_be_translated = (next_flow_to_be_translated + 1) % n_flows;
    }
  }

  printf("\n");

  return slices;
}

void generate_output(const char *output_fname, const pkt_data_t &pkt_data,
                     const cfg_t &cfg, const slices_t &slices) {
  assert(output_fname);

  auto n_flows = pkt_data.flows.size();
  auto n_pkts = pkt_data.n_pkts;
  auto n_slices = slices.size();

  pcap_t *pd = pcap_open_dead(DLT_EN10MB, 65535 /* snaplen */);
  pcap_dumper_t *pdumper = pcap_dump_open(pd, output_fname);

  if (pdumper == nullptr) {
    fprintf(stderr, "Unable to write to file %s\n", output_fname);
    exit(1);
  }

  auto pkt_sz_i = 0U;
  for (auto slice_i = 0UL; slice_i < n_slices; slice_i++) {
    const auto &slice = slices[slice_i];

    for (auto flow_i = 0U; flow_i < n_flows; flow_i++) {
      printf("\rBuilding pcap (slice %4lu/%4lu %3d%%)", slice_i + 1, n_slices,
             (int)(100.0 * ((float)(flow_i + 1)) / (float)n_flows));
      fflush(stdout);

      auto flow = pkt_data.flows_iteratable[flow_i];

      if (slice.count(flow) > 0) {
        flow = slice.at(flow);
      }

      auto pkt_sz = pkt_data.pkt_sizes[pkt_sz_i];
      auto hdr = flow.build_packet(pkt_sz);

      // hdr.pretty_print();

      pcap_pkthdr pcap_hdr{timeval{0, 0}, pkt_sz, pkt_sz};

      pcap_dump((u_char *)pdumper, &pcap_hdr, (u_char *)&hdr);

      pkt_sz_i = (pkt_sz_i + 1) % n_pkts;
    }
  }

  printf("\n");
  pcap_close(pd);
  pcap_dump_close(pdumper);
}

int main(int argc, char *argv[]) {
  if (argc < 4) {
    printf("Usage: %s [input pcap] [output pcap] [churn] \n", argv[0]);
    return 1;
  }

  auto input = argv[1];
  auto output = argv[2];

  uint32_t churn;

  if (sscanf(argv[3], "%u", &churn) != 1) {
    fprintf(stderr, "Churn must be a positive number (given %s)\n", argv[3]);
    exit(1);
  }

  auto pkt_data = get_pkts(input);
  auto slices_config = get_slices_config(pkt_data, churn, output);
  auto slices = build_slices(pkt_data, slices_config);
  generate_output(output, pkt_data, slices_config, slices);

  return 0;
}
#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>
using std::vector;

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern void rip_update(RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern RipPacket constructResponseRip(const uint32_t &ip, const uint& if_index);
extern void printRoutingTable();
extern vector<RoutingTableEntry> routingTable;

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0101a8c0, 0x0103a8c0, 0x0102000a, 0x0103000a};

const uint32_t multicast_addr = 0x090000e0; // 组播地址224.0.0.9

void Response(const uint32_t &addr);

uint32_t len2mask(const uint16_t &len) { // big endian
  return htonl(0xffffffff << (32 - len));
}

uint16_t mask2len(uint32_t mask) {
  mask = ntohl(mask);
  for (uint16_t i = 0; i < 32; i++) {
    if (mask << i == 0)
      return i;
  }
  return 32;
}

// 0-1, 4-11, 20-23, 26-27
void constructCommonHeader() {
  output[0] = 0x45;
  output[1] = 0;
  output[4] = output[5] = 0;
  output[6] = output[7] = 0;
  output[8] = 1; // TTL
  output[9] = 0x11; // UDP protocol
  output[10] = output[11] = 0;

  // UDP header
  *(uint16_t*)(output + 20) = htons(520);
  *(uint16_t*)(output + 22) = htons(520);

  output[26] = output[27] = 0;
}

void calcChecksum() {
  output[10] = output[11] = 0;
  uint32_t sum = 0;
  for (size_t i = 0; i < 20; i += 2) {
    sum += (output[i] << 8) | (output[i+1]);
  }
  while (sum >> 16 > 0) {
    sum = (sum >> 16) + (sum & 0xffff);
  }
  *(uint16_t*)(output + 10) = htons(~sum & 0xffff);
}

int main(int argc, char *argv[]) {
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }
  
  // Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD;i++) {
    RoutingTableEntry entry = {
      .addr = addrs[i] & len2mask(24), // big endian
      .len = 24, // small endian
      .if_index = i, // small endian
      .nexthop = 0, // big endian, means direct
      .metric = 1
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      printRoutingTable();
      // What to do? --Send Response
      constructCommonHeader();
      *(uint32_t*)(output + 16) = multicast_addr;
      output[26] = output[27] = 0;

      RipPacket res;
      for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
        *(uint32_t*)(output + 12) = addrs[i];
        // RipPacket res = constructResponseRip(addrs[i], i);
        res.numEntries = 0;
        res.command = 2;
        for (int j = 0; j < routingTable.size(); j++) {
            uint32_t mask = htonl(0xffffffff << (32 - routingTable[j].len));
            if (i == routingTable[j].if_index)
                continue;
            res.entries[res.numEntries].addr = routingTable[j].addr;
            res.entries[res.numEntries].mask = mask;
            res.entries[res.numEntries].nexthop = addrs[i];
            res.entries[res.numEntries].metric = routingTable[j].metric;
            res.numEntries++;

            if (res.numEntries == 25) {
                uint16_t rip_len = assemble(&res, output + 28);
                *(uint16_t*)(output + 2) = htons(rip_len + 28);
                *(uint16_t*)(output + 24) = htons(rip_len + 8);
                calcChecksum();

                macaddr_t dst_mac;
                HAL_ArpGetMacAddress(i, multicast_addr, dst_mac);
                HAL_SendIPPacket(i, output, 20 + 8 + rip_len, dst_mac);

                res.numEntries = 0;
            }
        }
        if (res.numEntries == 0) {
            continue;
        }
        uint16_t rip_len = assemble(&res, output + 28);
        *(uint16_t*)(output + 2) = htons(rip_len + 28);
        *(uint16_t*)(output + 24) = htons(rip_len + 8);
        calcChecksum();

        macaddr_t dst_mac;
        HAL_ArpGetMacAddress(i, multicast_addr, dst_mac);
        HAL_SendIPPacket(i, output, 20 + 8 + rip_len, dst_mac);
      }

      last_time = time;
      printf("Timer\n");
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
                                  dst_mac, 1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    src_addr = *(uint32_t*)(packet + 12);
    dst_addr = *(uint32_t*)(packet + 16);

    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address?
    if (memcmp(&dst_addr, &multicast_addr, sizeof(in_addr_t)) == 0) {
      dst_is_me = true;
    }

    if (dst_is_me) {
      // TODO: RIP?
      if ( ntohs(*(uint16_t*)(packet + 20)) != 520 || ntohs(*(uint16_t*)(packet + 22)) != 520) {
        continue;
      }
      
      RipPacket rip;
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // request
          if (rip.entries[0].metric != 16) {
            continue;
          }
          constructCommonHeader();
          *(uint32_t*)(output + 12) = addrs[if_index];
          *(uint32_t*)(output + 16) = src_addr;

          RipPacket res;
          res.numEntries = 0;
          res.command = 2;
          for (int i = 0; i < routingTable.size(); i++) {
              uint32_t mask = htonl(0xffffffff << (32 - routingTable[i].len));
              if (if_index == routingTable[i].if_index)
                  continue;
              res.entries[res.numEntries].addr = routingTable[i].addr;
              res.entries[res.numEntries].mask = mask;
              res.entries[res.numEntries].nexthop = addrs[if_index];
              res.entries[res.numEntries].metric = routingTable[i].metric;
              res.numEntries++;

              if (res.numEntries == 25) {
                  uint16_t rip_len = assemble(&res, output + 28);
                  *(uint16_t*)(output + 2) = htons(rip_len + 28);
                  *(uint16_t*)(output + 24) = htons(rip_len + 8);
                  calcChecksum();

                  macaddr_t dst_mac;
                  HAL_ArpGetMacAddress(if_index, multicast_addr, dst_mac);
                  HAL_SendIPPacket(if_index, output, 20 + 8 + rip_len, dst_mac);

                  res.numEntries = 0;
              }
          }
          if (res.numEntries == 0) {
              continue;
          }
          uint32_t rip_len = assemble(&res, &output[20 + 8]);
          *(uint16_t*)(output + 2) = htonl(rip_len + 28);
          *(uint16_t*)(output + 24) = htonl(rip_len + 8);
          // checksum calculation for ip and udp
          calcChecksum();
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          // response
          // TODO: use query and update
          RipPacket resp;
          resp.numEntries = 0;
          resp.command = 2;
          for (uint32_t i = 0; i < rip.numEntries; i++) {
            RoutingTableEntry entry = {
              .addr = rip.entries[i].addr,
              .len = mask2len(rip.entries[i].mask),
              .if_index = if_index,
              .nexthop = src_addr,
              .metric = rip.entries[i].metric
            };
            if (rip.entries[i].metric > 15) {
              // update(false, entry);
              // resp.entries[resp.numEntries++] = rip.entries[i];
            }
            else {
              rip_update(entry);
            }
          }
/*
          if (resp.numEntries > 0) {
            constructCommonHeader();
            *(uint32_t*)(output + 16) = multicast_addr;
            uint32_t rip_len = assemble(&resp, &output[20 + 8]);
            *(uint16_t*)(output + 2) = htonl(rip_len + 28);
            *(uint16_t*)(output + 24) = htonl(rip_len + 8);

            for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
              if (i == if_index) {
                continue;
              }

              *(uint32_t*)(output + 12) = addrs[i];
              calcChecksum();

              macaddr_t dst_mac;
              HAL_ArpGetMacAddress(i, multicast_addr, dst_mac);
              HAL_SendIPPacket(i, output, 20 + 8 + rip_len, dst_mac);
            }
          }
          */
        }
      }
    } else {
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);
          // TODO: you might want to check ttl=0 case
          if (output[8] == 0) {
            continue;
          }
          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        } else {
          // not found
        }
      } else {
        // not found
      }
    }
  }
  return 0;
}

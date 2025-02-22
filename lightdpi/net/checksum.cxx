#include <lightdpi/net/checksum.hpp>
#include <stdio.h>
#include <winsock2.h>

// Source from DPITunnel (Modified for our needs)

namespace ldpi
{
    struct PseudoHead{
      uint8_t zero;
      uint8_t type;
      uint16_t len;
      uint32_t src_ip;
      uint32_t dst_ip;
    };

    static uint32_t CalSum(const uint8_t* buf, int len) {
      uint32_t sum = 0;
      const uint8_t* p = buf;
      for(; len > 1; len -= 2) {
        sum += (*p << 8)+ *(p + 1);
        p += 2;
      }
      if (len == 1)
        sum += *p << 8;  //
        //sum += *p;  //
      return sum;
    }

    static uint32_t CalPseudoHeadSum(const IPHeader* pIpHead, uint8_t type) {
      PseudoHead head;
      head.zero = 0;
      head.type = type;
      head.len = htons(static_cast<uint16_t>(ntohs(pIpHead->length) - pIpHead->header_len * 4));
      head.src_ip = pIpHead->source.s_addr;
      head.dst_ip = pIpHead->destination.s_addr;
      return CalSum((uint8_t*)&head, sizeof(PseudoHead));
    }

    uint16_t calculate_ip_checksum(IPHeader* pIpHead) {
      pIpHead->checksum = 0;
      uint32_t ckSum = CalSum((uint8_t*)pIpHead, pIpHead->header_len * 4);
      ckSum = (ckSum >> 16) + (ckSum & 0xffff);
      ckSum += ckSum >> 16;
      return htons((uint16_t)~ckSum);
    }

    uint16_t calculate_tcp_checksum(IPHeader* pIpHead, TCPHeader* pTcpHead) {
      pTcpHead->checksum = 0;
      uint32_t ckSum = CalPseudoHeadSum(pIpHead, 0x06);
      ckSum += CalSum((uint8_t*)pTcpHead,
          ntohs(pIpHead->length) - pIpHead->header_len * 4);
      ckSum = (ckSum >> 16) + (ckSum & 0xffff);
      ckSum += ckSum >> 16;
      return htons((uint16_t)~ckSum);
    }

    uint16_t calculate_udp_checksum(IPHeader* pIpHead, UDPHeader* pUdpHead) {
      pUdpHead->checksum = 0;
      uint32_t ckSum = CalPseudoHeadSum(pIpHead, 0x11);
      ckSum += CalSum((uint8_t*)pUdpHead,
          ntohs(pIpHead->length) - pIpHead->header_len * 4);
      ckSum = (ckSum >> 16) + (ckSum & 0xffff);
      ckSum += ckSum >> 16;
      uint16_t cksum16 = htons((uint16_t)~ckSum);
      return (cksum16 == 0 ? 0xFFFF : cksum16);
    }
}
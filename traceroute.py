#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
#           Copyright 2018 Dept. CSE SUSTech
#           Copyright 2018 Suraj Singh Bisht
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#
# --------------------------------------------------------------------------
#                         Don't Remove Authors Info                        |
# --------------------------------------------------------------------------


__author__ = 'Suraj Singh Bisht, HHQ. ZHANG, YoungWilliam'
__credit__ = '["Suraj Singh Bisht",]'
__contact__ = 'contact@jinlab.cn'
__copyright__ = 'Copyright 2018 Dept. CSE SUSTech'
__license__ = 'Apache 2.0'
__Update__ = '2018-12-02 12:33:09.399381'
__version__ = '0.1'
__maintainer__ = 'HHQ. ZHANG'
__status__ = 'Production'

import random
import select
# import module
import socket
import time
import struct

from raw_python import ICMPPacket, parse_icmp_header, parse_eth_header, parse_ip_header, IPPacket


def calc_rtt(time_sent):
    return time.time() - time_sent


def catch_traceroute_reply(s, ID, time_sent, timeout=5):
    # create while loop
    while True:
        starting_time = time.time()  # Record Starting Time

        # to handle timeout function of socket
        process = select.select([s], [], [], timeout)

        # check if timeout
        if not process[0]:
            return calc_rtt(time_sent), None, None

        # receive packet
        rec_packet, addr = s.recvfrom(1024)

        ip = parse_ip_header(rec_packet[:20])
        # print(ip)
        # extract icmp packet from received packet 
        icmp = parse_icmp_header(rec_packet[20:28])
        print(icmp)
        # check identification
        if icmp['id'] == ID:
            return calc_rtt(time_sent), parse_ip_header(rec_packet[:20]), icmp


def single_traceroute_request(s, addr=None, ttl=64, seq=1):
    # Random Packet Id
    pkt_id = random.randrange(10000, 65000)
    ip_pkt_id = random.randrange(10000, 65000)

    # Create ICMP Packet
    icmp = ICMPPacket(_id=pkt_id, _seq=seq).raw
    packet = IPPacket(dst=socket.gethostbyname(addr), idf=ip_pkt_id, ttl=ttl, proto=socket.IPPROTO_ICMP, tol=72).raw + icmp
    print(parse_ip_header(packet[:20]))
    print(parse_icmp_header(icmp))
    # Send ICMP Packet
    while packet:
        sent = s.sendto(packet, (addr, 1))
        # sent = s.sendall(packet)
        packet = packet[sent:]

    return pkt_id


def main():

    # take Input
    addr = input("[+] Enter Domain Name : ") or "www.sustc.edu.cn"
    print('traceroute to {0} ({1}), 64 hops max,1 52 byte packets'.format(addr, socket.gethostbyname(addr)))

    # create socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        # s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # s.connect((socket.gethostbyname(addr), 1))
    except Exception as e:
        print("Socket counldn't be created. Error : {0}".format(e))


    ttl = 60

    # ttl_bin = struct.pack('@i', ttl)
    # s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)

    
    while(ttl <= 64):
        # Request sent
        ID = single_traceroute_request(s, addr, ttl)

        # Catch Reply
        rtt, reply, icmp_reply = catch_traceroute_reply(s, ID, time.time())
        print("rtt: %f" % rtt)
        if reply:
            reply['length'] = reply['Total Length'] - 20  # sub header
            print('{0[length]} bytes reply from {0[Source Address]} ({0[Source Address]}): '
                'icmp_seq={1[seq]} ttl={0[TTL]} time={2:.2f} ms'
                .format(reply, icmp_reply, rtt*1000))
        
        ttl = ttl + 1
        break

    # close socket
    s.close()
    return


if __name__ == '__main__':
    main()

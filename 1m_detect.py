import pydivert
import re

host_pattern = re.compile("Host:\s([a-zA-Z0-9.]+)")

fd = open("D:\\CCIT\\1m_detect\\sorted_data.txt", "r", encoding="utf-8")
sites = fd.readlines()
block_sites = []

for site in sites:
    block_sites.append(site.splitlines()[0])

with pydivert.WinDivert() as w_handle:
    for packet in w_handle:
        isBlock = False
        if packet.ipv4:
            if packet.tcp:
                if packet.tcp.dst_port == 80 or packet.tcp.src_port == 80:
                    payload = str(packet.payload)
                    site = host_pattern.search(payload)
                    if site:
                        try:
                            if block_sites.index(site.group(1)) >= 0:
                                print('block - {0}'.format(site.group(1)))
                                isBlock = True
                        except:
                            print('pass')
        if isBlock == False:
            w_handle.send(packet)

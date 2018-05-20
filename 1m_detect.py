import pydivert
import re

host_pattern = re.compile("Host:\s([a-zA-Z0-9.-]+)")
fd = open("sorted_data_ansi.txt", "r") # type cp949(Ansi)
sites = fd.readlines()
block_sites = []

def bin_search(data, cmp_text):
    low, high = 0, len(data)-1
    while low<=high:
        middle = int((low+high)/2)
        if data[middle] < cmp_text:
            low = middle + 1
        elif data[middle] > cmp_text:
            high = middle - 1
        else:
            return True
    return False

for site in sites:
    block_sites.append(site.splitlines()[0])

block_sites.sort() # bin search need sorting

with pydivert.WinDivert() as w_handle:
    for packet in w_handle:
        isBlock = False
        if packet.ipv4:
            if packet.tcp:
                if packet.tcp.dst_port == 80 or packet.tcp.src_port == 80:
                    payload = str(packet.payload)
                    site = host_pattern.search(payload)
                    if site:
                        if bin_search(block_sites,site.group(1)):
                            isBlock = True
        if isBlock == False:
            w_handle.send(packet)
            
fd.close()

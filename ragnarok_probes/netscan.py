from scapy import all as scapy
import requests
class Netscan:
    """ Scans a range of IPs """
    def scan(self, ip):
        arp_req_frame = scapy.ARP(pdst = ip)

        broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")

        broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

        answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0]
        result = []
        for i in range(0,len(answered_list)):
            client_dict = {"ip" : answered_list[i][1].psrc, "mac" : answered_list[i][1].hwsrc, "vendor" : mac_vendor(answered_list[i][1].hwsrc)}
            result.append(client_dict)
        return result

    def mac_vendor(mac):
        url = "https://api.macvendors.com/"
        response = requests.get(url+mac)
        return response.content.decode()

    def display_result(self, result):
        print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
        for i in result:
            print("{}\t{},{}".format(i["ip"], i["mac"], i["vendor"]))

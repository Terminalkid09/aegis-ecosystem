import socket
import uuid
import requests
import psutil

class NetworkService:
    def get(self):
        iface = psutil.net_if_addrs()
        gws = psutil.net_if_stats()

        local_ip = socket.gethostbyname(socket.gethostname())
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                        for ele in range(0,8*6,8)][::-1])

        try:
            public_ip = requests.get("https://api.ipify.org").text
        except:
            public_ip = None

        return {
            "local_ip": local_ip,
            "public_ip": public_ip,
            "mac": mac,
            "gateway": None,
            "dns": None,
            "iface": list(iface.keys())[0] if iface else None
        }
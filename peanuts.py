#!/usr/bin/python

# 11/01/2020 - NOTES

# Updated to Python3
# disabled BT scanning as it was being shitty
# Json logging will cause a exception if no 200 ok responce is given from endpoint
# gps lat long needs to be a value, if no GPS location can be found, then have exception but still send data

from logging.handlers import RotatingFileHandler
import threading
import argparse
import sys
from gps import *
# import bluetooth
import manuf
from scapy.all import *
conf.verb = 0
import datetime
import logging
import collections
import requests
import base64
import json
import binascii
from os import system, path, getuid, uname

PROBE_REQUEST_TYPE=0
PROBE_REQUEST_SUBTYPE=4
AP_BROADCAST_SUBTYPE=8

accessPoints = []
macAP = []

clients = []
btclients = []
macClient = []
uni = 0

Numclients = 0
Numap = 0
Currentloc = 0

NAME = 'Peanuts'
DESCRIPTION = "A New Version of Snoopy-NG, a command line tool for logging 802.11 probe request frames"
whmp = manuf.MacParser()

gpsd = None #seting the global variable

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange<
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

class GpsPoller(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        global gpsd #bring it in scope
        gpsd = gps(mode=WATCH_ENABLE) #starting the stream of info
        self.current_value = None
        self.running = True #setting the thread running to true
     
    def run(self):
        global gpsd
        while gpsp.running:
            try:
                if gpsd.waiting(): #only True if data is available
                    gpsd.next()
            except (RuntimeError, TypeError, NameError):
                print('GPSD Failed!')
                gpsd.close()
                sys.exit()

def LoggingOfData(output):
    # setup our rotating logger
    if os.path.isfile(output) == False:
        f = open(output,'w')
        f.write('Time, Device, MAC Address, Manufacture, SSID, Crypto, Latitude, Longitude, Location, RSSI\n')
        f.close()
    global logger 
    logger = logging.getLogger(NAME)
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(output, maxBytes=10000000, backupCount=99999)
    logger.addHandler(handler)

def parse_args():
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument('-i', '--interface', help="capture interface")
    parser.add_argument('-o', '--output', default='out.log', help="logging output location")
    parser.add_argument('-d', '--delimiter', default=',', help="output field delimiter")
    parser.add_argument('-g', '--gpstrack', default=False, help="Enable/Disable GPS Tracking")
    parser.add_argument('-l', '--location', default='None', help="Location of survey")
    parser.add_argument('-a', '--access', default=False, help="Include AP's into the survey")
    parser.add_argument('-m', '--maps', default='', help="Send Map data to JSON endpoint")
   # parser.add_argument('-b', '--bt', default=False, help="Scans BT Devices too (will need a BT dongle)")

    return parser.parse_args()

def CryptoInfo(pkt):
    p = pkt[Dot11Elt]
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                      "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
    crypto = ""
    while isinstance(p, Dot11Elt):
        if p.ID == 48:
            crypto = "WPA2"
        elif p.ID == 221 and p.info.startswith(b'\x00P\xf2\x01\x01\x00'):
            crypto = "WPA"
        p = p.payload
    if not crypto:
        if 'privacy' in cap:
            crypto = "WEP"
        else:
            crypto = "OPN"

    if "0050f204104a000110104400010210" in str(pkt):
        crypto = crypto + R + " WPS"

    return crypto

def getmac(intf):
    mac_addr = open('/sys/class/net/%s/address' % intf).read().rstrip()
    return mac_addr

def PacketHandler(pkt):
    global intf
    mymac = getmac(intf)
    noise = {
        'ff:ff:ff:ff:ff:ff',      # broadcast
        '00:00:00:00:00:00',      # broadcast
        '33:33:00:',              # ipv6 multicast
        '33:33:ff:',              # spanning tree
        '01:80:c2:00:00:00',      # multicast
        '01:00:5e:',			# broadcast
        'None',
        mymac              
    }

    if pkt.haslayer(Dot11):
        if pkt.addr2 not in noise:
            if pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE:
                PrintPacketClient(pkt)
        if args.access:
            if pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == AP_BROADCAST_SUBTYPE:
                PrintPacketAP(pkt)
       # if pkt.addr1 and pkt.addr2:
        #    PrintClientAP(pkt)

'''  DISABLED BT FOR NOW
    if args.bt:
        try:
            btscanning()
        except (RuntimeError, TypeError, NameError):
            print('Caught exception while running BT Sniffing')
'''

def PrintClientAP(pkt):
    global intf
    mymac = getmac(intf)
    noise = {
        'ff:ff:ff:ff:ff:ff',      # broadcast
        '00:00:00:00:00:00',      # broadcast
        '33:33:00:',              # ipv6 multicast
        '33:33:ff:',              # spanning tree
        '01:80:c2:00:00:00',      # multicast
        '01:00:5e:',            # broadcast
        'None',
        mymac              
    }

    if pkt.addr2 in macAP:
        if pkt.addr1 not in noise:
            if pkt.type in [1, 2]:
                print('Client: ' + pkt.addr1.upper() + ' -> ' + pkt.addr2)

def PrintPacketAP(pkt):
    global Numap, Currentloc
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')

    ssid_probe = pkt.info.decode('utf-8')
    
    if not ssid_probe or ssid_probe == '\x00\x00\x00\x00\x00\x00\x00\x00\x00':
        ssid_probe = 'Null SSID'

    manufacture = str(whmp.get_manuf(pkt.addr2))
    mac = pkt.addr2

    crypto = CryptoInfo(pkt)
    rssi = pkt[RadioTap]. dBm_AntSignal

    if args.gpstrack:
        gpslat = str(gpsd.fix.latitude)
        gpslong = str(gpsd.fix.longitude)
    else:
        gpslat = 'nil'
        gpslong = 'nil'

    # Logging info
    fields = []
    fields.append(st) # Log Time
    fields.append('AP') # Log Client or AP
    fields.append(mac) # Log Mac Address
    fields.append(manufacture) # Log Device Manufacture
    fields.append(ssid_probe) # Log SSID
    fields.append(crypto) # Log Crypto
    fields.append(gpslat) # Log GPS data
    fields.append(gpslong) # Log GPS data
    fields.append(args.location) # Log Location data
    fields.append(str(rssi)) # RSSI
    
    # if AP ssid is not in clients and its not empty then print out, add  AP ssid and mac to lists
    if ssid_probe not in accessPoints and ssid_probe != "":
        accessPoints.append(ssid_probe)
        macAP.append(mac)
        print(W+ '[' +R+ 'AP' +W+ ':' +C+ manufacture +W+ '/' +B+ mac +W+ '] [' +T+ crypto +W+ '] [' +G+ 'SSID' +W+ ': ' +O+ ssid_probe +W+ '] [' +P+ 'RSSI' +W+ ':' +T+ str(rssi) +W+ ']')
        Numap += 1
    # if ssid is in clients but mac isnt seen before then print out and add the mac to the list
    elif ssid_probe in accessPoints and mac not in macAP:
        macAP.append(mac)
        print(W+ '[' +R+ 'AP' +W+ ':' +C+ manufacture +W+ '/' +B+ mac +W+ '] [' +T+ crypto +W+ '] [' +G+ 'SSID' +W+ ': ' +O+ ssid_probe +W+ '] [' +P+ 'RSSI' +W+ ':' +T+ str(rssi) +W+ ']')
        Numap += 1

    logger.info(args.delimiter.join(fields))

    if args.maps:
        # MAPPING SYSTEM
        jsondata = {"time": st, "device": "AP", "macaddress": mac, "manuf": manufacture, "ssid": ssid_probe, "crypto": crypto, "longlat": [-0.0, 0.0], "location": args.location, "rssi": rssi}
        data_json = json.dumps(jsondata)

        s = requests.Session()
        headers = {'Content-Type': 'application/json', 'Accept':'application/json'}
        s.post(args.maps, data=data_json, headers=headers)
        
        # MAPPING SYSTEM


def PrintPacketClient(pkt):    
    global Numclients, Currentloc
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')

    ssid_probe = pkt.getlayer(Dot11ProbeReq).info.decode('utf-8')

    manufacture = str(whmp.get_manuf(pkt.addr2))
    mac = pkt.addr2
    crypto = 'None' #instead of being blank, client has none for crypto probe request
    rssi = pkt[RadioTap]. dBm_AntSignal

    if args.gpstrack:
        gpslat = str(gpsd.fix.latitude)
        gpslong = str(gpsd.fix.longitude)
    else:
        gpslat = 'nil'
        gpslong = 'nil'

    # Logging info
    fields = []
    fields.append(st) # Log Time
    fields.append('Client') # Log Client or AP
    fields.append(mac) # Log Mac Address
    fields.append(manufacture) # Log Device Manufacture
    fields.append(ssid_probe) # Log SSID
    fields.append(crypto) # Log Crypto
    fields.append(gpslat) # Log GPS data
    fields.append(gpslong) # Log GPS data
    fields.append(args.location) # Log Location data
    fields.append(str(rssi)) # RSSI

    # if ssid is not in clients and its not empty then print out, add ssid and mac to lists
    if ssid_probe not in clients and ssid_probe != "":
        clients.append(ssid_probe)
        macClient.append(mac)
        print(W+ '[' +R+ 'Client' +W+ ':' +C+ manufacture +W+ '/' +B+ mac +W+ '] [' +G+ 'SSID' +W+ ': ' +O+ ssid_probe +W+ '] [' +P+ 'RSSI' +W+ ':' +T+ str(rssi) +W+ ']')
    # if ssid is in clients but mac isnt seen before then print out and add the mac to the list
    elif ssid_probe in clients and mac not in macClient:
        macClient.append(mac)
        print(W+ '[' +R+ 'Client' +W+ ':' +C+ manufacture +W+ '/' +B+ mac +W+ '] [' +G+ 'SSID' +W+ ': ' +O+ ssid_probe +W+ '] [' +P+ 'RSSI' +W+ ':' +T+ str(rssi) +W+ ']')
        Numclients += 1
    # if mac is not in the list and the probe has a broadcast (empty) then add mac to list
    elif mac not in macClient and ssid_probe == "":
        macClient.append(mac)
        print(W+ '[' +R+ 'Client' +W+ ':' +C+ manufacture +W+ '/' +B+ mac +W+ '] [' +GR+ '*New Client*' +W+ '] [' +P+ 'RSSI' +W+ ':' +T+ str(rssi) +W+ ']')
        Numclients += 1
    
    
    logger.info(args.delimiter.join(fields))

    if args.maps:
        # MAPPING SYSTEM
        jsondata = {"time": st, "device": "CLIENT", "macaddress": mac, "manuf": manufacture, "ssid": ssid_probe, "crypto": "N/A", "longlat": [-0.0, 0.0], "location": args.location, "rssi": rssi}
        data_json = json.dumps(jsondata)

        s = requests.Session()
        headers = {'Content-Type': 'application/json', 'Accept':'application/json'}
        s.post(args.maps, data=data_json, headers=headers)
        # MAPPING SYSTEM


def getWirelessInterfacesList():
    networkInterfaces=[]        
    command = ["iwconfig"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.wait()
    (stdoutdata, stderrdata) = process.communicate();
    output = stdoutdata
    lines = output.splitlines()
    for line in lines:
            if(line.find("IEEE 802.11")!=-1):
                    networkInterfaces.append(line.split()[0])
    return networkInterfaces

def startup_checks():
    if getuid() != 0:
        print(R + 'User is not Root!')
        sys.exit()

    if uname()[0].startswith("Linux") and not "Darwin" not in uname():
        print(R + 'Wrong OS!')
        sys.exit()

    return

def logo():
    print(O + '''
    %s______                      _       
    | ___ \                    | |      
    | |_/ /__  __ _ _ __  _   _| |_ ___ 
    |  __/ _ \/ _` | '_ \| | | | __/ __|
    | | |  __/ (_| | | | | |_| | |_\__ \

    \_|  \___|\__,_|_| |_|\__,_|\__|___/
    %s
    %sRelease Date%s: 11/01/2021
    %sRelease Version%s: V.3.9
    %sCode%s: Twitter: @NoobieDog
    ''' %(B,C,R,W,R,W,R,W))        
    print('['+G+'*'+W+'] Wifi Probe Investigator')
    print('['+G+'-----------------------------------------------------'+W+']')

def main(intf):
    try:
        sniff(iface=intf, prn=PacketHandler, store=0)
    except (RuntimeError, TypeError, NameError):
        print('Caught exception while running sniff()')
        raise

''' DISABLED BT FOR NOW
def btscanning():
    devices = bluetooth.discover_devices(duration=1, lookup_names = True)

    for addr, name in devices:
        if addr not in btclients:
            print(W+ '[' +R+ 'Bluetooth Client' +W+ ':' +B+ addr +W+ '] [' +G+ 'Name' +W+ ': ' +O+ name +W+ ']')
            btclients.append(addr)
'''

if __name__=="__main__":
    args = parse_args()
    
    start = time.time()

    startup_checks()

    LoggingOfData(args.output)

    if not args.interface:
        intf = raw_input('['+G+'*'+W+'] Enter the Name of the interface to sniff: ')
        print("\n")
    else:
        intf = args.interface

    if "mon" not in intf: # yes i know this doesnt work with ubuntu/mint at the mo...
        print('['+G+'*'+W+'] Setting Wireless card into Monitor Mode')
        if 'mon' not in getWirelessInterfacesList():
            #call(['airmon-ng', 'check', 'kill'], stdout=DN, stderr=DN)
            cmd = ['airmon-ng', 'start' ,intf]
            p = subprocess.Popen(cmd)
            p.wait()
        intf = intf + 'mon'

    os.system('clear')

    logo()

    if args.gpstrack:
        try:    
            gpsp = GpsPoller() # create the thread
        except (RuntimeError, TypeError, NameError):
            print('Caught exception while running GPS')

        try:
            gpsp.start() # start it up
        except (RuntimeError, TypeError, NameError):
            print('Caught exception while running GPS')
            gpsp.running = False
            gpsp.join() # wait for the thread to finish what it's doing
            sys.exit()
    try:
        main(intf)
    except (KeyboardInterrupt, SystemExit):
        raise


# Finish off with Tidy up of CSV. 

print('\n \033[31m%d \033[0mClients | \033[33m%d \033[0mAPs' % (Numclients, Numap))

outfile = args.output + '.csv'

print(G + '\n Creating CSV' +W+ ': ' + outfile)
try:
    with open(args.output, 'rb') as inf, open(outfile, 'wb') as outf:
        outf.writelines(collections.OrderedDict.fromkeys(inf))
except (RuntimeError, TypeError, NameError):
            print(R + 'Caught exception while creating CSV File')

# Print Program Time

print(G + '\n Elapsed Time' +W+ ': %s' % (time.time() - start))

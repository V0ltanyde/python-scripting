#Craig Suhrke
#PCAP tool

# Python Standard Library Module Imports

import sys               # System specifics
import platform          # Platform specifics
import os                # Operating/Filesystem Module
import pickle            # Object serialization
import time              # Basic Time Module
import re                # regular expression library
from binascii import unhexlify

# 3rd Party Libraries

from prettytable import PrettyTable   # pip install prettytable

'''


Simple PCAP File 3rd Party Library 
to process pcap file contents

To install the Library
pip install pypcapfile 

'''

from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network   import ip
from pcapfile.protocols.transport import tcp
from pcapfile.protocols.transport import udp


# Script Constants

NAME    = "PYTHON PCAP PROCESSOR"
VERSION = "VERSION 1.0 October 2024"
DEBUG   = True

# Script Constants

DEBUG = True

# Script Local Functions


class ETH:
    '''LOOKUP ETH TYPE'''
    def __init__(self):
    
        self.ethTypes = {}
        
        self.ethTypes[2048]   = "IPv4"
        self.ethTypes[2054]   = "ARP"
        self.ethTypes[34525]  = "IPv6"
            
    def lookup(self, ethType):
        
        try:
            result = self.ethTypes[ethType]
        except:
            result = "not-supported"
            
        return result

# MAC Address Lookup Class
class MAC:
    ''' OUI TRANSLATION MAC TO MFG'''
    def __init__(self):
        
        # Open the MAC Address OUI Dictionary
        with open('oui.pickle', 'rb') as pickleFile:
            self.macDict = pickle.load(pickleFile)
            
    def lookup(self, macAddress):
        try:
            result = self.macDict[macAddress]
            cc  = result[0]
            oui = result[1]
            return cc+","+oui
        except:
            return "Unknown"
        
# Transport Lookup Class

class TRANSPORT:
    ''' PROTOCOL TO NAME LOOKUP'''
    def __init__(self):
        
        # Open the transport protocol Address OUI Dictionary
        with open('protocol.pickle', 'rb') as pickleFile:
            self.proDict = pickle.load(pickleFile)
    def lookup(self, protocol):
        try:
            result = self.proDict[protocol]
            return result
        except:
            return ["unknown", "unknown", "unknown"]

#PORTS Lookup Class

class PORTS:
    ''' PORT NUMBER TO PORT NAME LOOKUP'''
    def __init__(self):
        
        # Open the MAC Address OUI Dictionary
        with open('ports.pickle', 'rb') as pickleFile:
            self.portDict = pickle.load(pickleFile)
            
    def lookup(self, port, portType):
        try:
            result = self.portDict[(port,portType)]
            return result
        except:
            return "EPH"
        
class IPObservations:

    # Constructor

    def __init__(self):

        #Attributes of the Object

        self.Dictionary = {}            # Dictionary to Hold IP Observations
        self.portObservations = {}

    # Method to Add an observation

    def AddOb(self, key, value, hr):

        # Check to see if key is already in the dictionary

        try:
            curValue = self.Dictionary[key]
            hourList = curValue[0]
            hourList[hr] += 1

            # Update the value associated with this key
            self.Dictionary[key] = [hourList, value]

        except:
            # if the key doesn't yet exist
            # Create one

            hourList = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            hourList[hr] += 1

            self.Dictionary[key] = [hourList, value]


    def AddPortOb(self, key, desc):

        # Check to see if key is already in the dictionary

        if key not in self.portObservations:

            self.portObservations[key] = desc


    def PrintIPObservations(self):
        #tbl = PrettyTable(['SRC-IP', 'DST-IP', 'SRC-MAC', 'DST-MAC', 'SRC-MFG', 'DST-MFG', 'SRC-PORT', 'DST-PORT', 'TTL', 'HR-0', 'HR-1','HR-2','HR-3','HR-4','HR-5','HR-6','HR-7','HR-8','HR-9','HR-10','HR-11','HR-12','HR-13','HR-14','HR-15','HR-16','HR-17','HR-18','HR-19','HR-20','HR-21','HR-22','HR-23'])
        '''
                    key   = (srcMAC, dstMAC, srcPort, dstPort, "TCP")
                    value = [srcIP, dstIP, srcPortDesc, dstPortDesc, protocol, srcCC+","+srcOU, dstCC+","+dstOU, ttl]

        '''
        kx = {
            'sMac': 0,
            'dMac': 1,            
            'sPrt': 2,
            'dPrt': 3,
            'prot': 4
        }

        vx = {
            'sIP': 0,
            'dIP': 1,
            'sPrtDesc': 2,            
            'dPrtDesc': 3,
            'sMFG': 4,
            'dMFG': 5,
            'ttl':  6
        }               

        print("\nIP Observations")
        tbl = PrettyTable(['SRC-IP', 'DST-IP', 'PROTOCOL', 'SRC-MAC', 'DST-MAC', 'SRC-MFG', 'DST-MFG', 'SRC-PORT', 'DST-PORT', 'SRC-PORT-NAME', 'DST-PORT-NAME', 'TTL', 'HR-00','HR-01','HR-02','HR-03','HR-04','HR-05','HR-06','HR-07','HR-08','HR-09','HR-10','HR-11','HR-12','HR-13','HR-14','HR-15','HR-16','HR-17','HR-18','HR-19','HR-20','HR-21','HR-22','HR-23'])

        for k, v in self.Dictionary.items():
            row = []
            hourList = v[0]
            ob  = v[1]
            row.append(ob[vx['sIP']])
            row.append(ob[vx['dIP']])
            row.append(k[kx['prot']])
            row.append(k[kx['sMac']])
            row.append(k[kx['dMac']])
            row.append(ob[vx['sMFG']])
            row.append(ob[vx['dMFG']])
            row.append(k[kx['sPrt']])
            row.append(k[kx['dPrt']])
            row.append(ob[vx['sPrtDesc']])
            row.append(ob[vx['dPrtDesc']])
            row.append(ob[vx['ttl']])

            for eachHr in hourList:
                row.append(eachHr)

            tbl.add_row(row)

        tbl.align = 'l'
        print(tbl.get_string(sortby="PROTOCOL"))

    def PrintPortObservations(self):
        tbl = PrettyTable(["IP", "PORT", "PORT-DESCRIPTION"])
        print("\nPORT Observations")
        for key, value in self.portObservations.items():
            tbl.add_row([key[0], key[1], value])

        tbl.align='l'
        print(tbl.get_string(sortby="IP"))

    # Destructor Delete the Object

    def __del__(self):
        if DEBUG:
            print ("Closed")
            

if __name__ == '__main__':

        print("PCAP PROCESSOR v1.0")
        
        # Create Lookup Objects
        macOBJ  = MAC()
        traOBJ  = TRANSPORT()
        portOBJ = PORTS()
        ethOBJ  = ETH()     
        ipOBJ   = IPObservations()
        
        ''' Attempt to open a PCAP '''
        while True:
            targetPCAP = input("Target PCAP File: ")
            if not os.path.isfile(targetPCAP):
                print("Invalid File: Please enter valid path\n")
                continue      
            try:
                pcapCapture = open(targetPCAP, 'rb')
                capture = savefile.load_savefile(pcapCapture, layers=0, verbose=False)
                print("PCAP Ready for Processing")
                break
            except:
                # Unable to ingest pcap       
                print("!! Unsupported PCAP File Format !! ")
                continue

        totPackets      = 0
        pktCnt          = 0
        
        # Now process each packet
        for pkt in capture.packets:
            pktCnt += 1

            # extract the hour the packet was captured
            timeStruct  = time.gmtime(pkt.timestamp)
            capHour     = timeStruct.tm_hour - 1     
            
            # Get the raw ethernet frame
            ethFrame = ethernet.Ethernet(pkt.raw())
            
            '''
            Ethernet Header
            0                   1                   2                   3                   4              
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                      Destination Address                                      |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                         Source Address                                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           EtherType           |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                               +
            |                                                                                               |
            +                                            Payload                                            +
            |                                                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        
            '''
                
            ''' ---- Extract the source mac address ---- '''
            srcMAC          = "".join(map(chr, ethFrame.src))
            srcMACLookup    = srcMAC[0:8].upper()
            # remove the colon seperators
            # note the variable names starting with fld, we will use these later
            srcMACLookup  = re.sub(':','',srcMACLookup) 
            
            # Attempt to lookup the mfg in our lookup table 
            # Country Code and Organization
            srcMFG  = macOBJ.lookup(srcMACLookup)    
            
            ''' Extract the destination mac address ---'''
            dstMAC          = "".join(map(chr, ethFrame.dst))
            dstMACLookup    = dstMAC[0:8].upper()
            # remove the colon seperators
            # note the variable names starting with fld, we will use these later
            dstMACLookup  = re.sub(':','',dstMACLookup) 
            
            # Attempt to lookup the mfg in our lookup table 
            # Country Code and Organization
            dstMFG = macOBJ.lookup(dstMACLookup)     
        
            ''' Lookup the Frame Type '''
            frameType = ethOBJ.lookup(ethFrame.type)
            
            print("====== ETHERNET LAYER =====\n")
            print("TIMESTAMP:", timeStruct)
            print("SRC MAC:  ", srcMAC)
            print("DST MAC:  ", dstMAC)
            print("SRC MFG:  ", srcMFG)
            print("DST MFG:  ", dstMFG)
            print("FRAME TYP:", frameType)
            print("="*40,"\n")
            
            ''' Process any IPv4 Frames '''
            
            if frameType == "IPv4":
                '''
                ipV4 Header
                0                   1                   2                   3  
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |Version|  IHL  |Type of Service|          Total Length         |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |         Identification        |Flags|     Fragment Offset     |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |  Time to Live |    Protocol   |        Header Checksum        |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |                         Source Address                        |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |                      Destination Address                      |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |                    Options                    |    Padding    |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   
                '''
                
                ''' Extract the payload '''
                ipPacket = ip.IP(unhexlify(ethFrame.payload))
                ttl = ipPacket.ttl
                    
                ''' Extract the source and destination ip addresses '''
                srcIP = "".join(map(chr,ipPacket.src))
                dstIP = "".join(map(chr,ipPacket.dst))
                
                ''' Extract the protocol in use '''
                protocol = str(ipPacket.p)
                
                ''' Lookup the transport protocol in use '''
                transport = traOBJ.lookup(protocol)[0]
                
                print("====== IPv4 Transport LAYER =====\n")
                print("TTL:   ",   ttl)
                print("SRC-IP:",   srcIP)
                print("DST-IP:",   dstIP)
                print("Protocol:", protocol)
                print("="*40,"\n")
                
                if transport == "TCP":
                    
                    '''
                    TCP HEADER
                    0                   1                   2                   3  
                    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |          Source Port          |        Destination Port       |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |                        Sequence Number                        |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |                     Acknowledgment Number                     |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    | Offset|  Res. |     Flags     |             Window            |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |            Checksum           |         Urgent Pointer        |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |                    Options                    |    Padding    |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    '''
                    
                    tcpPacket = tcp.TCP(unhexlify(ipPacket.payload))
                    srcPort = tcpPacket.src_port
                    dstPort =tcpPacket.dst_port
                    
                    srcPortDesc = portOBJ.lookup(str(srcPort), "TCP")
                    if srcPortDesc == "EPH":
                        srcPort = "EPH"
                    else:
                        srcPort = str(srcPort)

                    dstPortDesc = portOBJ.lookup(str(dstPort), "TCP")
                    if dstPortDesc == "EPH":
                        dstPort = "EPH"
                    else:
                        dstPort = str(dstPort)

                    key = (srcMAC, dstMAC, srcPort, dstPort, "TCP")
                    value = [srcIP, dstIP, srcPortDesc, dstPortDesc, srcMFG, dstMFG, ttl]

                    ipOBJ.AddOb(key, value, capHour)
                    
                    if srcPort != "EPH":
                        ipOBJ.AddPortOb((srcIP, srcPort), srcPortDesc)
                    if dstPort != "EPH":
                        ipOBJ.AddPortOb((dstIP, dstPort), dstPortDesc)
                     
                elif transport == "UDP":
                    '''
                     0                   1                   2                   3  
                     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     |          Source Port          |        Destination Port       |
                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     |             Length            |            Checksum           |
                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     '''
                    
                    ''' 
                    **** YOUR CODE HERE ****
                
                    '''                                       
                    udpPacket = udp.UDP(unhexlify(ipPacket.payload))
                    srcPort = udpPacket.src_port
                    dstPort =udpPacket.dst_port
                    
                    srcPortDesc = portOBJ.lookup(str(srcPort), "UDP")
                    if srcPortDesc == "EPH":
                        srcPort = "EPH"
                    else:
                        srcPort = str(srcPort)

                    dstPortDesc = portOBJ.lookup(str(dstPort), "UDP")
                    if dstPortDesc == "EPH":
                        dstPort = "EPH"
                    else:
                        dstPort = str(dstPort)

                    key = (srcMAC, dstMAC, srcPort, dstPort, "UDP")
                    value = [srcIP, dstIP, srcPortDesc, dstPortDesc, srcMFG, dstMFG, ttl]

                    ipOBJ.AddOb(key, value, capHour)
                    
                    if srcPort != "EPH":
                        ipOBJ.AddPortOb((srcIP, srcPort), srcPortDesc)
                    if dstPort != "EPH":
                        ipOBJ.AddPortOb((dstIP, dstPort), dstPortDesc)
                elif transport == "ICMP":
                    '''
                     0                   1                   2                   3  
                     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     |      Type     |      Code     |            Checksum           |
                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     |                                                               |
                     +                          Message Body                         +
                     |                                                               |
                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     '''
                    ''' 
                    **** YOUR CODE HERE ****
                
                    '''            
                    key = (srcMAC, dstMAC, "", "", "ICMP")
                    value = [srcIP, dstIP, "", "", srcMFG, dstMFG, ttl]

                    ipOBJ.AddOb(key, value, capHour)

            elif frameType == "ARP":
                '''
                0                   1      
                0 1 2 3 4 5 6 7 8 9 0 1 2 3
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |  Dst-MAC  |  Src-MAC  |TYP|
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |                           |
                +       Request-Reply       +
                |                           |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |        PAD        |  CRC  |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                '''
                
                ''' 
                **** YOUR CODE HERE ****
            
                '''                
                key = (srcMAC, dstMAC, "", "", "ARP")
                value = ["", "", "", "", srcMFG, dstMFG, ttl]

                ipOBJ.AddOb(key, value, capHour)
            
            else:
                continue
            
        ipOBJ.PrintIPObservations()
        ipOBJ.PrintPortObservations()

        
        print("\n\nScript End")
        
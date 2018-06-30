import sys # Python 3.6 NOTE: We need this for the getsizeof method to replace "sizeof" in Py 2 code
if sys.hexversion < 50725360:
    print("ERROR: Please utilize following 3.6.1 version of Python:\r\n\r\n >>>sys.hexversion\r\n50725360\r\n\r\n")
    sys.exit(0)
import socket
import os
import struct
from ctypes import *
from scapy.all import *

# host to listen on
host = "10.8.0.14" # listen on all interfaces, instead

# our IP header
class IP(Structure):
	_fields_ = [
            ("ihl",          c_ubyte, 4),
            ("version",      c_ubyte, 4),
            ("tos",          c_ubyte),
            ("len",          c_ushort),
            ("id",           c_ushort),
            ("offset",       c_ushort),
            ("ttl",          c_ubyte),
            ("protocol_num", c_ubyte),
            ("sum",          c_ushort),
            ("src",          c_ulong),
            ("dst",          c_ulong),
            ]

	def __new__(self, socket_buffer=None):
        	return self.from_buffer_copy(socket_buffer)

	def __init__(self, socket_buffer=None):

		# map protocol constants to their names
		self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

		# human readable IP addresses
		self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
		self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))

		# human readable protocol
		try: 
		    self.protocol = self.protocol_map[self.protocol_num]
		except:
		    self.protocol = str(self.protocol_num)

# debug class to figure out why binary data is not packed correctly
class debugIP(Structure):
	_fields_ = [
		("bunchof4bytes1",	c_ulong),
		("bunchof4bytes2",	c_ulong)
		]
	def __new__(self, socket_buffer=None):
		return self.from_buffer_copy(socket_buffer)

	def __init__(self, socket_buffer=None):
		# map protocol constants to their names
		#self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

		# human readable IP addresses
		self.bytestream1 = socket.inet_ntoa(struct.pack("!L",self.bunchof4bytes1))
		#self.bytestream2 = socket.inet_ntoa(struct.pack("<L",self.bunchof4bytes2))
		#self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))

		# human readable protocol
		#try: 
		#    self.protocol = self.protocol_map[self.protocol_num]
		#except:
		#    self.protocol = str(self.protocol_num)
		
class ICMP(Structure):

    _fields_ = [
            ("type",         c_ubyte),
            ("code",         c_ubyte),
            ("checksum",     c_ushort),
            ("unused",       c_ushort),
            ("next_hop_mtu", c_ushort)
            ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

# Debug scapy code
def packet_callback(packet):
	print (packet.show())


# Debug code.  I want to know the size of the network format and endianess on this machine AARCH64 Chromebook
print ("The size of the packed bytes is -> {}".format(struct.calcsize("<L")))

# this should look familiar from the previous example
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else: 
    socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:

	while True:
		# read in a packet
		raw_buffer = sniffer.recvfrom(65565)[0]

		# Debug code.  Print out the initial bytes of the raw buffer
		print ("The raw buffer contents is -> {}".format(raw_buffer[0:160]))     
		print ("The length of the buffer is -> {}".format(len(raw_buffer[0:160])))
		#print ("The decoded buffer contents in UTF-8 is -> {}".format(raw_buffer[0:20].decode()))
		#sniff(prn=packet_callback, count=1)

		# create an IP header from the first 32(!) bytes of the buffer
		ip_header = debugIP(raw_buffer[0:32]) # Python 3.6 NOTE: 20-bytes might break < Python 3.6

		# print out the protocol that was detected and the hosts 
		#print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)) # Python 3.6 NOTE: Print statement replacement per Python 3. 
		print ("The first four byte group was {}".format(ip_header.bytestream1))
		#print ("The second four byte group was {}".format(ip_header.bytestream2))

		# if it's ICMP, we want it
		#if ip_header.protocol == "ICMP":

		    # calculate where our ICMP packet starts # Py 3.6 NOTE: sys.getsizeof method used for buf 
		    #offset = ip_header.ihl * 4
		    #buf = raw_buffer[offset:offset + sys.getsizeof(ICMP)] 
		    
		    # create our ICMP structure
		    #icmp_header = ICMP(buf)

		    #print("ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code))
		print ("Iterating again......")
		
# handle CTRL - C
except KeyboardInterrupt: 
    
    # if we're using Windows turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF) 
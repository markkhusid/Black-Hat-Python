import socket

target_host = "127.0.0.1"
target_port = 80

# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# send some data
client.sendto("AAABBBCCC", (target_host, target_port))

# receive some data
data, addr = client.recvfrom(4096)

print data

# Create UDP listener by using netcat like so:
# sudo nc -lu -p 80 127.0.0.1
# AAABBBCCC will show up on listener, and typing text into listener and 
# pressing enter will cause that text to appear at executing python
# script window.  It will also cause execution to complete with exit code 0.


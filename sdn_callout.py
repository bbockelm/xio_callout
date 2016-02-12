#!/usr/bin/python

import sys
import socket
import htcondor

# preprocess the command line arguments
event_name = sys.argv[1]
ip_and_port = sys.argv[2]
username = sys.argv[3]
filename = sys.argv[4]
transfer_type = sys.argv[5]

# seperate the ip and port
index = ip_and_port.find(':')
ip = ip_and_port[:index]
port = ip_and_port[index+1:]

# check the htcondor module host and port
HOST = htcondor.param["HTCONDOR_MODULE_HOST"]
PORT = int(htcondor.param["HTCONDOR_MODULE_PORT"])

send_data = "GRIDFTP" + "\n" + event_name + "\n" + ip + "\n" + port + \
            "\n" + username + "\n" + filename + "\n" + transfer_type

#file = open("/tmp/gridftp_callout", 'w')
#file.write(send_data)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    sock.connect((HOST, PORT))
    sock.sendall(send_data)
finally:
    sock.close()



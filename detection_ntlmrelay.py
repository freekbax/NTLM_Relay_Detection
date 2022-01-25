#!/usr/bin/env python3

from ast import List
from itertools import count
from queue import PriorityQueue
import re
import subprocess
import time
import os
import os.path
import pyshark
from pyfiglet import Figlet
from clint.textui import colored

GLOBAL_computers = {'10.0.0.20' : 'WIN10-CLIENT', '10.0.0.5' : 'NTLMserver' , '10.0.0.10' : 'DC1'}
GLOBAL_challenges = {}

def welcome(text):
    result = Figlet()
    return colored.cyan(result.renderText(text))

def get_network_interfaces() -> List:
    # source:https://www.programcreek.com/python/?CodeExample=get+network+interfaces
    # find the network interfaces present on the system
    interfaces = []
    interfaces_details = []

    interfaces = subprocess.check_output("ls /sys/class/net", shell=True)
    interfaceString = str(interfaces)
    interfaceString = interfaceString[2:-3]
    interfaces = interfaceString.split('\\n')

    for interface in interfaces:
        interface_out = subprocess.check_output(["ip", "addr", "show", interface])
        interfaces_output = str(interface_out)
        ip_addr_out = interfaces_output[interfaces_output.find("inet") + 5:]
        ip_addr = ip_addr_out[:ip_addr_out.find(" ")]

        interfaces_output = interfaces_output[5:interfaces_output.find(">") + 1]
        interfaces_output = interfaces_output.replace(":", "").replace("<", "").replace(">", "")

        interface_output_list = interfaces_output.split(" ")
        if ip_addr != "":
            interface_output_list.append(ip_addr)
        interfaces_details.append(interface_output_list)
    return interfaces_details

def get_src_dst_ip(packet):
    source = packet.ip.src
    destination = packet.ip.dst
    return source, destination

def get_challengeinfo(layer):
    challenge = layer.ntlmssp_ntlmserverchallenge
    return challenge

def get_authinfo(layer):
    hostname = layer.ntlmssp_auth_hostname
    ntresponse = layer.ntlmssp_auth_ntresponse
    return hostname, ntresponse

def determ_ntlmtype(layer):
    if layer.ntlmssp_messagetype == '0x00000001':
        return 'negotiate'
    elif layer.ntlmssp_messagetype == '0x00000002':
        return 'challenge'
    elif layer.ntlmssp_messagetype == '0x00000003':
        return 'auth'

def locate_ntlmssp_layer(packet):
    for layer in packet.layers:
            if 'ntlmssp_identifier'in layer.field_names:
                return layer

def validate_hostname_ip(hostname, ip):
    if hostname == 'NULL' or ip == 'NULL':
        return 0
    else:
        if GLOBAL_computers.get(ip)==hostname:
            return True
        else:
            return False

def detect_double_challenge(challenge, ip):
    if challenge in GLOBAL_challenges:
        if GLOBAL_challenges.get(challenge)==ip:
            return True
        else:
            return False
    else:
        GLOBAL_challenges[challenge]=ip
        return True
        

def dectection_ntlm_traffic(packet):
    layer = locate_ntlmssp_layer(packet)
    ntlmtype = determ_ntlmtype(layer)

    if ntlmtype == 'negotiate':
        print("negatiate detected")
        source, dest = get_src_dst_ip(packet)
    elif ntlmtype == 'challenge':
        print('challenge detected')
        source, dest = get_src_dst_ip(packet)
        challenge = get_challengeinfo(layer)
        if not detect_double_challenge(challenge, source):
            print("DOUBLE TROUBLE, de relay aanvaller zit op ip:", source)
    elif ntlmtype == 'auth':
        print('authentication detected')
        source, dest = get_src_dst_ip(packet)
        hostname, ntresponse = get_authinfo(layer)
        valid_computer = validate_hostname_ip(hostname, source)
        if not valid_computer:
            print("DIKKEE MUDDD, de eikel die aanvalt zit op ip:", source)

def file_analysis(filepath):
    capture = pyshark.FileCapture(filepath, display_filter="ntlmssp")
    for packet in capture:
        dectection_ntlm_traffic(packet)
    print("File analysed")

def capture_live_analysis(chosen_interface):
    os.system("clear")
    print(welcome("NTLM Relay Detector"))
    print("Starting the live capture for NTLM traffic on {}:".format(chosen_interface))
    try: 
        capture = pyshark.LiveCapture(interface=chosen_interface, display_filter='ntlmssp')
        for packet in capture.sniff_continuously(packet_count=200):
            dectection_ntlm_traffic(packet)
    except Exception as err:
            print("Capturing of live traffic went wrong - {}".format(err))
            time.sleep(5)
            exit()
    print("End of the capture")


def main():
    while True:
        os.system("clear")
        print(welcome("NTLM Relay Detector"))
        print("Detection tool specialized in NTLM relay attacks\n")
        print("Please select an option ")
        print("""\t1 : File capture analysis
        2 : Live analysis
        0 : Exit""")
        c = input("\nEnter your choice : ")

        if c == '1':
            try:
                os.system("clear")
                print(welcome("NTLM Relay Detector"))
                filepath = input("Enter file path:")
                file_analysis(filepath)
                time.sleep(5)
            except Exception as err:
                print("File analysis failed - {}".format(err))
                time.sleep(5)
        elif c == '2':
            try:
                os.system("clear")
                print(welcome("NTLM Relay Detector"))
                interfaces = get_network_interfaces()
                count = 0
                print("Please select an interfaces ")
                for interface in interfaces:
                    print(str(count) + " : "+ str(interface[0]))
                    count += 1
                c_interface = input("\nEnter your choice : ")


                capture_live_analysis(str(interfaces[int(c_interface)][0]))
                
            except Exception as err:
                print("Live analysis failed - {}".format(err))
                time.sleep(5)
                exit()
        elif c == '0':
            print("Bye!")
            exit()
        os.system("clear")

if __name__ == "__main__":
    main()

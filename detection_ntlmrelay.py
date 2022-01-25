#!/usr/bin/env python3

from ast import List
from itertools import count
from queue import PriorityQueue
import subprocess
import time
import os
import os.path
import pyshark
from pyfiglet import Figlet
from clint.textui import colored

def welcome(text):
    result = Figlet()
    return colored.cyan(result.renderText(text))

def get_network_interfaces() -> List:
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

def file_analysis(filepath):
    capture = pyshark.FileCapture(filepath, display_filter="ntlmssp.ntlmserverchallenge and http")
    packet = capture[0]
    print(get_challengeinfo(packet.http))
    test = packet.http.ntlmssp_ntlmserverchallenge
    print(test)
    time.sleep(30)

def determ_ntlmtype(layer):
    if layer.ntlmssp_messagetype == '0x00000001':
        return 'negotiate'
    elif layer.ntlmssp_messagetype == '0x00000002':
        return 'challenge'
    elif layer.ntlmssp_messagetype == '0x00000003':
        return 'auth'

def locate_ntlmssp(packet):
    for layer in packet.layers:
            if 'ntlmssp_identifier'in layer.field_names:
                return layer

def capture_live_analysis(chosen_interface):
    os.system("clear")
    print(welcome("NTLM Relay Detector"))
    print("Starting the live capture for NTLM traffic on {}:".format(chosen_interface))
    try: 
        capture = pyshark.LiveCapture(interface=chosen_interface, display_filter='ntlmssp')
        for packet in capture.sniff_continuously(packet_count=200):
            ntlmssp_layer = locate_ntlmssp(packet)
            print(determ_ntlmtype(ntlmssp_layer))
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
                time.sleep(30)
            except Exception as err:
                print("File analysis failed - {}".format(err))
                time.sleep(20)
        elif c == '2':
            try:
                os.system("clear")
                print(welcome("NTLM Relay Detector"))
                interfaces = get_network_interfaces()
                count = 0
                print(interfaces[0][0])
                print("Please select an interfaces ")
                for interface in interfaces:
                    print(str(count) + " : "+ str(interface[0]))
                    count += 1
                c_interface = input("\nEnter your choice : ")


                capture_live_analysis(str(interfaces[int(c_interface)][0]))
                print("do not come here")
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

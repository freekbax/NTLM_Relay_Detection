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


def file_analysis(filepath):
    capture = pyshark.FileCapture(filepath, display_filter="ntlmssp.ntlmserverchallenge and http")
    packet = capture[0]
    print(packet.highest_layer)
    test = packet.http.ntlmssp_ntlmserverchallenge
    print(test)
    time.sleep(30)

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
                c = input("\nEnter your choice : ")

                # print("Starting the live capture on eno2:")
                # capture = pyshark.LiveCapture(interface='eno2', display_filter='ntlmssp.ntlmserverchallenge' )
                # for packet in capture.sniff_continuously(packet_count=80):
                #     print(packet)
                time.sleep(5)
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

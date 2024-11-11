# Subnet Calculator

## Overview
The Subnet Calculator is a Python program with a graphical user interface (GUI) built using the `tkinter` library. It allows users to enter an IP address and optionally specify a CIDR prefix. Based on this information, the program calculates subnetting details such as the number of hosts, subnets, network address, broadcast address, and even the first and last subnets.

## Features
- **IP Address Validation**: The program validates the entered IP address to ensure it is a valid IPv4 address.
- **CIDR Calculation**: If no CIDR is provided, the program automatically calculates the default CIDR based on the class of the entered IP address.
- **Subnetting by Hosts/Subnets**: You can specify the number of hosts or subnets, and the program will calculate the corresponding subnet mask and other related details.
- **Network and Broadcast Addresses**: It calculates and displays the network and broadcast addresses for the given IP and CIDR.
- **First and Last Subnets**: The program calculates and displays the first and last subnets within the network.

## Requirements
- Python 3.x
- `tkinter` library (usually included with Python)

## How to Use
1. **Enter IP**: In the "Enter IP" field, input the IPv4 address you wish to use.
2. **Enter CIDR (Optional)**: Optionally, provide a CIDR prefix (e.g., `/24`). If left empty, the program will calculate it based on the entered IP address.
3. **Partition Type**: Choose whether you want to partition by **hosts** or **subnets** using the radio buttons.
4. **Enter Number of Hosts/Subnets**: Based on the selected partition type, input the number of hosts or subnets you wish to calculate.
5. **Click Calculate**: Press the "Calculate" button to view the subnetting details.

## Example
- **IP**: `192.168.1.1`
- **CIDR**: `24` (Optional)
- **Partition by**: Hosts
- **Number of Hosts**: `50`

## Explanation
The program provides detailed calculations such as:
- Number of usable hosts and subnets
- Network and broadcast addresses
- First and last subnets in the network

It helps network administrators and students learn and visualize subnetting concepts effectively.

# rust-ipmi

IPMI through LAN rust client with support for IPMI V2/RMCP+. 

###  Preface: 
This is a hobby project to learn some rust, and is NOT a library meant for production use. If you would like a stable, well featured IPMI LAN client, look into ipmi-tool - a CLI tool which has been maintained for over a decade.


### ⚠️ Security WARNING ⚠️

IPMI through LAN has multiple relatively well-documented security vulnerabilities. Here are a few suggestions to harden your security:
- Change the default IPMI username
- Keep port 623/UDP to the servers under a restrictive firewall
- Do not directly expose your servers to the WAN

<!-- ## Design documentation for rust-ipmi -->

## Background

rust-ipmi is a native rust client for remotely managing/monitoring systems with hardware support for IPMI. IPMI is a specification which allows software to interact and communicate with systems through the BMC (Baseboard Management Controller). BMC is a hardware component which enables interaction with a computer's chassis, motherboard, and storage through LAN and serial.

<!-- ![IPMI Block diagram](/images/ipmi.png) -->

This library is focusing on the IPMI LAN protocol. Some general information on IPMI through LAN:
1. This is a network-based implementation of IPMI so network packets will be sent to and received from the BMC LAN controller on port 623 through UDP.
2. The packet structure generally looks like Ethernet frame -> IP/UDP -> RMCP header -> IPMI header -> IPMI payload
3. Intel came out with a IPMI v2 and RMCP+ which introduced encrypted payloads

<!-- ## Requirements for this library

- Support IPMI v1.5/2 RMCP/RMCP+
- Support most common APP and CHASSIS commands -->

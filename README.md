# TORsessionSniffer
## Sniffer detects TOR (The Onion Router) Traffic from your Network. IPv4 &amp; IPv6

PLEASE DONATE [paypal.me/retoPay](https://paypal.me/retoPay)

Use a managed switch, and mirror the Internet Port to your Sniffer PC.
## Installation on Windows:
Install Python3
In the command shell execute: 
```
pip install -r requirements.txt (in the TORsessionSniffer Folder)
```
## Installation on Ubuntu-Linux: 
```
sudo apt-get update
sudo apt-get install python3
pip3 install -r requirements.txt
```
## Run the application, set with -i the Network Interface
```
$ sudo python3 torSniffer.py -i enp0s8
***************************************
* TOR-Sniffer V.3.0 by Reto Schaedler *
* PLEASE DONATE   paypal.me/retoPay   *
***************************************
start loop
TOR-IP-File age in seconds: 810
TOR-IP-File is up to date.
Read TOR-IP-File
.Start Sniffer
Sniffer Started.
***************************************
IPv4 TOR-Session-Detected:
192.168.88.250 -> 135.148.100.89
Time: 2022-12-06_23:26:50

```

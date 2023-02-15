import os
import netifaces as ni

ipaddress = input("Please enter IP Address and Subnet Mask (e.g 192.168.10.100/24: ")

print('-' * 128)
print(f'You entered IP address: {ipaddress}')
print('-' * 128)

cmd = "sudo nmcli connection modify ens33 IPv4.address %s" % (ipaddress)
os.system(cmd)

os.system("sudo systemctl stop jarvis")

os.system('sudo nmcli connection down  ens33')
os.system('sudo nmcli connection up ens33')

os.system("sudo systemctl start jarvis")
os.system("sudo systemctl enable jarvis")

ip = ni.ifaddresses('ens33')[ni.AF_INET][0]['addr']
print(f"Open browser from any another system in the same LAN and access Jarvis with admin created IP http://{ip}:8080")


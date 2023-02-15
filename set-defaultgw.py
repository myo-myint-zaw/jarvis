import os
import netifaces as ni

defaultgwip = input("Please enter Default Gateway: ")
defaultgwint = input("Please enter Default Gateway Interface: ")
defaultmetric = input("Please enter Default Route Metric: ")

print("-" * 128)
print(f'You entered Default Gateway: {defaultgwip}')
print(f'You entered Default Gateway Interface: {defaultgwint}')
print(f'You entered Default Route Metric: {defaultmetric}')
print("-" * 128)

cmd = "sudo nmcli connection modify %s IPv4.gateway %s IPv4.route-metric %s" % (defaultgwint,defaultgwip,defaultmetric)
os.system(cmd)

os.system("sudo systemctl stop jarvis")

os.system('sudo nmcli connection down %s' % defaultgwint)
os.system('sudo nmcli connection up %s' % defaultgwint)

os.system("sudo systemctl start jarvis")
os.system("sudo systemctl enable jarvis")

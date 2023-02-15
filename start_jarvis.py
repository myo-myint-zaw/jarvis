import os
import netifaces as ni

ip = ni.ifaddresses('ens33')[ni.AF_INET][0]['addr']
os.system(f"python3 /var/www/jarvis/manage.py runserver {ip}:8080 --insecure")

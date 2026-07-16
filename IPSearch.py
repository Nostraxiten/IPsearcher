import socket
import random
import time
import threading
import ipaddress
import subprocess
import os
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

class IPScannerAdvanced:
    def __init__(self):
        self.running = True
        self.found_ips = []
        self.scanned = 0
        self.alive = 0
        self.threads = 80
        self.timeout = 1
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.folder = os.path.join(script_dir, "IPs")
        self.file_counter = 1
        self.pings_per_ip = 2
        self.max_hosts_scan_ipv4 = 1000
        self.max_hosts_scan_ipv6 = 256
        self.create_folder()
        self.setup_signal_handler()
        self.ip_classes = {
            'A': {'min': 1, 'max': 126, 'desc': 'Grandes redes (1.0.0.0 - 126.255.255.255)'},
            'B': {'min': 128, 'max': 191, 'desc': 'Redes medianas (128.0.0.0 - 191.255.255.255)'},
            'C': {'min': 192, 'max': 223, 'desc': 'Redes pequenas (192.0.0.0 - 223.255.255.255)'}
        }
        self.get_next_file_number()
        
    def setup_signal_handler(self):
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        print("\n[+] Deteniendo escaneo...")
        self.running = False
        self.show_results()
        sys.exit(0)
    
    def create_folder(self):
        if not os.path.exists(self.folder):
            os.makedirs(self.folder)
            print(f"[+] Carpeta '{self.folder}' creada")
    
    def get_next_file_number(self):
        existing = [f for f in os.listdir(self.folder) if f.startswith("ips_vivas_") and f.endswith(".txt")]
        if existing:
            numbers = []
            for f in existing:
                try:
                    num = int(f.split("_")[2].split(".")[0])
                    numbers.append(num)
                except:
                    pass
            if numbers:
                self.file_counter = max(numbers) + 1
        self.output_file = os.path.join(self.folder, f"ips_vivas_{self.file_counter}.txt")
    
    def generate_ip_by_class(self, ip_class):
        first = random.randint(self.ip_classes[ip_class]['min'], self.ip_classes[ip_class]['max'])
        second = random.randint(1, 255)
        third = random.randint(1, 255)
        fourth = random.randint(1, 255)
        return f"{first}.{second}.{third}.{fourth}"
    
    def generate_network_by_class(self, ip_class):
        first = random.randint(self.ip_classes[ip_class]['min'], self.ip_classes[ip_class]['max'])
        second = random.randint(1, 255)
        third = random.randint(1, 255)
        return f"{first}.{second}.{third}.0/24"
    
    def ping_ip_once(self, ip):
        try:
            is_ipv6 = ':' in ip
            if os.name == 'nt':
              
                cmd = ['ping']
                if is_ipv6:
                    cmd += ['-6']
                cmd += ['-n', '1', '-w', str(self.timeout*1000), ip]
                result = subprocess.run(cmd, capture_output=True, timeout=self.timeout+1)
            else:
               
                cmd = ['ping']
                if is_ipv6:
                    cmd += ['-6']
                cmd += ['-c', '1', '-W', str(self.timeout), ip]
                result = subprocess.run(cmd, capture_output=True, timeout=self.timeout+1)
            return result.returncode == 0
        except:
            return False
    
    def ping_ip(self, ip):
        for attempt in range(self.pings_per_ip):
            if self.ping_ip_once(ip):
                return True
            time.sleep(0.03)
        return False
    
    def scan_ip(self, ip, ip_type="v4"):
        if not self.running:
            return
        self.scanned += 1
        
        if self.ping_ip(ip):
            self.alive += 1
            self.found_ips.append(ip)
            print(f"[{ip_type}] IP VIVA: {ip} - ({self.alive} encontradas)")
        
        time.sleep(0.005)
    
    def scan_range(self, network, ip_type="v4"):
        try:
            net = ipaddress.ip_network(network, strict=False)
            
            if net.version == 4:
                hosts = list(net.hosts())
                if len(hosts) > self.max_hosts_scan_ipv4:
                    ips = random.sample(hosts, self.max_hosts_scan_ipv4)
                else:
                    ips = hosts
            else:
                
                total = net.num_addresses
                sample_count = min(self.max_hosts_scan_ipv6, total)
                if total <= sample_count:
                    ips = list(net.hosts())
                else:
                    ips = []
                    base = int(net.network_address)
                    for _ in range(sample_count):
                        rand = random.randint(0, int(net.num_addresses) - 1)
                        ips.append(ipaddress.ip_address(base + rand))

            random.shuffle(ips)

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for ip in ips:
                    if not self.running:
                        break
                    ip_str = str(ip)
                    futures.append(executor.submit(self.scan_ip, ip_str, ip_type))

                for future in as_completed(futures):
                    future.result()
        except Exception as e:
            pass
    
    def scan_class_a(self):
        print("\n[+] Escaneando Clase A (1.0.0.0 - 126.255.255.255)")
        while self.running:
            network = self.generate_network_by_class('A')
            print(f"[*] Red: {network}")
            self.scan_range(network, "A")
    
    def scan_class_b(self):
        print("\n[+] Escaneando Clase B (128.0.0.0 - 191.255.255.255)")
        while self.running:
            network = self.generate_network_by_class('B')
            print(f"[*] Red: {network}")
            self.scan_range(network, "B")
    
    def scan_class_c(self):
        print("\n[+] Escaneando Clase C (192.0.0.0 - 223.255.255.255)")
        while self.running:
            network = self.generate_network_by_class('C')
            print(f"[*] Red: {network}")
            self.scan_range(network, "C")
    
    def scan_all_classes(self):
        print("\n[+] Escaneando TODAS las clases indefinidamente")
        while self.running:
            for _ in range(3):
                network = self.generate_network_by_class('A')
                print(f"[*] Red Clase A: {network}")
                self.scan_range(network, "A")
                if not self.running:
                    break
            
            for _ in range(5):
                network = self.generate_network_by_class('B')
                print(f"[*] Red Clase B: {network}")
                self.scan_range(network, "B")
                if not self.running:
                    break
            
            for _ in range(8):
                network = self.generate_network_by_class('C')
                print(f"[*] Red Clase C: {network}")
                self.scan_range(network, "C")
                if not self.running:
                    break
    
    def scan_random_ips(self):
        print("\n[+] Escaneando IPs aleatorias...")
        while self.running:
            classes = ['A', 'B', 'C']
            random.shuffle(classes)
            
            for ip_class in classes:
                if not self.running:
                    break
                ip = self.generate_ip_by_class(ip_class)
                self.scan_ip(ip, ip_class)
                time.sleep(0.005)

    def scan_random_ipv6(self, count=None):
        print("[+] Escaneando IPs aleatorias IPv6...")
        scanned = 0
        while self.running:
            # generate random global unicast-ish addresses (2000::/3)
            first = random.randint(0x2000, 0x3fff)
            rest = random.getrandbits(112)
            addr_int = (first << 112) | rest
            ip = str(ipaddress.IPv6Address(addr_int))
            self.scan_ip(ip, "IPv6")
            scanned += 1
            if count and scanned >= count:
                break
            time.sleep(0.01)

    def scan_network_custom(self, network_str):
        try:
            net = ipaddress.ip_network(network_str, strict=False)
            print(f"[*] Escaneando red: {net} (version {net.version})")
            self.scan_range(str(net), ip_type=f"v{net.version}")
        except Exception as e:
            print(f"[!] Error parseando la red: {e}")
    
    def show_results(self):
        print("\n" + "=" * 60)
        print("RESUMEN")
        print("=" * 60)
        print(f"  IPs escaneadas: {self.scanned}")
        print(f"  IPs vivas: {self.alive}")
        print(f"  IPs encontradas: {len(self.found_ips)}")
        
        if self.found_ips:
            class_a = []
            class_b = []
            class_c = []
            ipv6_list = []

            for ip in self.found_ips:
                if ':' in ip:
                    ipv6_list.append(ip)
                    continue
                try:
                    first = int(ip.split('.')[0])
                except:
                    continue
                if 1 <= first <= 126:
                    class_a.append(ip)
                elif 128 <= first <= 191:
                    class_b.append(ip)
                elif 192 <= first <= 223:
                    class_c.append(ip)

            print("\n[+] IPs encontradas por clase:")
            print(f"    Clase A: {len(class_a)}")
            print(f"    Clase B: {len(class_b)}")
            print(f"    Clase C: {len(class_c)}")
            print(f"    IPv6: {len(ipv6_list)}")

            print("\n[+] IPs encontradas:")
            for ip in self.found_ips[:30]:
                print(f"    {ip}")
            if len(self.found_ips) > 30:
                print(f"    ... y {len(self.found_ips)-30} mas")
        
        self.save_ips()
    
    def save_ips(self):
        if not self.found_ips:
            print("[!] No se encontraron IPs para guardar")
            return
        
        class_a = []
        class_b = []
        class_c = []
        ipv6_list = []

        for ip in self.found_ips:
            if ':' in ip:
                ipv6_list.append(ip)
                continue
            try:
                first = int(ip.split('.')[0])
            except:
                continue
            if 1 <= first <= 126:
                class_a.append(ip)
            elif 128 <= first <= 191:
                class_b.append(ip)
            elif 192 <= first <= 223:
                class_c.append(ip)
        
        with open(self.output_file, 'w') as f:
            f.write("# IPs VIVAS ENCONTRADAS\n")
            f.write(f"# Archivo: {self.file_counter}\n")
            f.write(f"# Total: {len(self.found_ips)}\n")
            f.write("# Fecha: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
            f.write("# " + "="*50 + "\n\n")
            
            if class_a:
                f.write("# CLASE A (1.0.0.0 - 126.255.255.255)\n")
                for ip in class_a:
                    f.write(ip + "\n")
                f.write("\n")
            
            if class_b:
                f.write("# CLASE B (128.0.0.0 - 191.255.255.255)\n")
                for ip in class_b:
                    f.write(ip + "\n")
                f.write("\n")
            
            if class_c:
                f.write("# CLASE C (192.0.0.0 - 223.255.255.255)\n")
                for ip in class_c:
                    f.write(ip + "\n")
                f.write("\n")
            if ipv6_list:
                f.write("# IPV6 VIVAS\n")
                for ip in ipv6_list:
                    f.write(ip + "\n")
                f.write("\n")
        
        print(f"\n[+] IPs guardadas en: {self.output_file}")
        print(f"[+] Total: {len(self.found_ips)} IPs")
    
    def menu(self):
        print("=" * 60)
        print("IP SCANNER ADVANCED - CLASES A, B, C")
        print("=" * 60)
        print("\nClases de IP publicas:")
        print("  [1] Clase A (1.0.0.0 - 126.255.255.255) - Grandes redes")
        print("  [2] Clase B (128.0.0.0 - 191.255.255.255) - Redes medianas")
        print("  [3] Clase C (192.0.0.0 - 223.255.255.255) - Redes pequenas")
        print("  [4] Todas las clases (A + B + C)")
        print("  [5] Salir")
        print("  [6] Escanear red personalizada (IPv4 o IPv6) - introducir CIDR")
        print("  [7] Escanear IPs aleatorias IPv6")
        print("-" * 60)
        
        while True:
            choice = input("\n[+] Selecciona una opcion: ").strip()
            
            if choice == '1':
                self.scan_class_a()
                break
            elif choice == '2':
                self.scan_class_b()
                break
            elif choice == '3':
                self.scan_class_c()
                break
            elif choice == '4':
                self.scan_all_classes()
                break
            elif choice == '5':
                return False
            elif choice == '6':
                network = input("[+] Introduce la red/CIDR (ej: 192.168.1.0/24 o 2001:db8::/64): ").strip()
                if network:
                    self.scan_network_custom(network)
                break
            elif choice == '7':
                try:
                    c = int(input("[+] Cuantas IPs IPv6 aleatorias escanear? (por defecto 100): ").strip() or 100)
                except:
                    c = 100
                self.scan_random_ipv6(count=c)
                break
            else:
                print("[!] Opcion invalida")
        
        return True
    
    def run(self):
        scan_type = None
        network_custom = None
        ipv6_count = None
        
        print("=" * 60)
        print("IP SCANNER ADVANCED - CLASES A, B, C")
        print("=" * 60)
        print("\nClases de IP publicas:")
        print("  [1] Clase A (1.0.0.0 - 126.255.255.255) - Grandes redes")
        print("  [2] Clase B (128.0.0.0 - 191.255.255.255) - Redes medianas")
        print("  [3] Clase C (192.0.0.0 - 223.255.255.255) - Redes pequenas")
        print("  [4] Todas las clases (A + B + C)")
        print("  [5] Salir")
        print("  [6] Escanear red personalizada (IPv4 o IPv6) - introducir CIDR")
        print("  [7] Escanear IPs aleatorias IPv6")
        print("-" * 60)
        
        while True:
            choice = input("\n[+] Selecciona una opcion: ").strip()
            
            if choice == '1':
                scan_type = 'class_a'
                break
            elif choice == '2':
                scan_type = 'class_b'
                break
            elif choice == '3':
                scan_type = 'class_c'
                break
            elif choice == '4':
                scan_type = 'all_classes'
                break
            elif choice == '5':
                return
            elif choice == '6':
                network_custom = input("[+] Introduce la red/CIDR (ej: 192.168.1.0/24 o 2001:db8::/64): ").strip()
                if network_custom:
                    scan_type = 'custom'
                break
            elif choice == '7':
                try:
                    ipv6_count = int(input("[+] Cuantas IPs IPv6 aleatorias escanear por ronda? (0=indefinido, defecto 100): ").strip() or 100)
                except:
                    ipv6_count = 100
                scan_type = 'random_ipv6'
                break
            else:
                print("[!] Opcion invalida")
        
        print("\n[+] Iniciando escaneo continuo...")
        print("[+] 2 intentos por IP (si falla, segundo intento)")
        print("[+] Presiona CTRL+C para detener")
        print("-" * 60)
        
        try:
            while self.running:
                if scan_type == 'class_a':
                    self.scan_class_a()
                elif scan_type == 'class_b':
                    self.scan_class_b()
                elif scan_type == 'class_c':
                    self.scan_class_c()
                elif scan_type == 'all_classes':
                    self.scan_all_classes()
                elif scan_type == 'custom':
                    self.scan_network_custom(network_custom)
                elif scan_type == 'random_ipv6':
                    self.scan_random_ipv6(count=ipv6_count if ipv6_count != 0 else None)
        except KeyboardInterrupt:
            pass
        
        self.show_results()

if __name__ == "__main__":
    scanner = IPScannerAdvanced()
    scanner.run()

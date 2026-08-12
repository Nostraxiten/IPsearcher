import socket
import random
import time
import threading
import ipaddress
import subprocess
import os
import signal
import sys
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed


# ----------------------------------------------------------------------------
# Colores ANSI (se desactivan solos si la salida no es una terminal)
# ----------------------------------------------------------------------------
class C:
    enabled = sys.stdout.isatty()

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    @classmethod
    def paint(cls, text, color):
        if not cls.enabled:
            return text
        return f"{color}{text}{cls.RESET}"


# Puertos comunes: numero -> nombre de servicio
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1723: "PPTP", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elastic", 27017: "MongoDB",
}


class IPScannerAdvanced:
    def __init__(self):
        self.running = True
        self.found_ips = []          # solo IPs (para resumen por clase)
        self.found_details = []      # (ip, [puertos_abiertos])
        self.scanned = 0
        self.alive = 0

        # Rendimiento (valores seguros para Termux/moviles)
        self.threads = 100           # hilos concurrentes (sockets, muy ligeros)
        self.timeout = 1             # timeout ping ICMP (s)
        self.port_timeout = 1.2      # timeout conexion TCP por puerto (s)
        self.pings_per_ip = 2
        self.max_hosts_scan_ipv4 = 1000
        self.max_hosts_scan_ipv6 = 256

        # Filtro de puertos (deteccion rapida)
        self.ports_filter = []       # lista de 1-3 puertos de interes
        self.match_mode = "all"      # "all" = todos abiertos, "any" = al menos uno

        # Sincronizacion / cola de trabajo (evita crashes por saturacion)
        self.lock = threading.Lock()
        self.work_queue = queue.Queue(maxsize=3000)
        self.workers = []

        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.folder = os.path.join(script_dir, "IPs")
        self.file_counter = 1

        self.ip_classes = {
            'A': {'min': 1, 'max': 126, 'desc': 'Grandes redes (1.0.0.0 - 126.255.255.255)'},
            'B': {'min': 128, 'max': 191, 'desc': 'Redes medianas (128.0.0.0 - 191.255.255.255)'},
            'C': {'min': 192, 'max': 223, 'desc': 'Redes pequenas (192.0.0.0 - 223.255.255.255)'}
        }

        self.create_folder()
        self.setup_signal_handler()
        self.get_next_file_number()

    # ------------------------------------------------------------------
    # Infraestructura basica
    # ------------------------------------------------------------------
    def setup_signal_handler(self):
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        # Solo marcamos la parada; el hilo principal se encarga del cierre
        # ordenado (mostrar resultados / guardar). Hacerlo aqui con hilos
        # activos era una de las causas de cierres inesperados.
        if self.running:
            print(C.paint("\n[!] Deteniendo escaneo... (espera unos segundos)", C.YELLOW))
        self.running = False

    def create_folder(self):
        if not os.path.exists(self.folder):
            os.makedirs(self.folder)
            print(C.paint(f"[+] Carpeta '{self.folder}' creada", C.GREEN))

    def get_next_file_number(self):
        existing = [f for f in os.listdir(self.folder)
                    if f.startswith("ips_vivas_") and f.endswith(".txt")]
        if existing:
            numbers = []
            for f in existing:
                try:
                    numbers.append(int(f.split("_")[2].split(".")[0]))
                except Exception:
                    pass
            if numbers:
                self.file_counter = max(numbers) + 1
        self.output_file = os.path.join(self.folder, f"ips_vivas_{self.file_counter}.txt")

    # ------------------------------------------------------------------
    # Generadores de IP
    # ------------------------------------------------------------------
    def generate_ip_by_class(self, ip_class):
        first = random.randint(self.ip_classes[ip_class]['min'], self.ip_classes[ip_class]['max'])
        return f"{first}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

    def generate_network_by_class(self, ip_class):
        first = random.randint(self.ip_classes[ip_class]['min'], self.ip_classes[ip_class]['max'])
        return f"{first}.{random.randint(1,255)}.{random.randint(1,255)}.0/24"

    # ------------------------------------------------------------------
    # Deteccion: TCP (puertos) e ICMP (ping)
    # ------------------------------------------------------------------
    def port_name(self, port):
        return COMMON_PORTS.get(port, "TCP")

    def check_port(self, ip, port):
        """Conexion TCP ligera (sin lanzar procesos). Devuelve True si el
        puerto esta OPEN. Esto sustituye al ping por subprocess, que es lo
        que saturaba Termux tras varias busquedas."""
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(self.port_timeout)
        try:
            return s.connect_ex((ip, port)) == 0
        except OSError:
            return False
        finally:
            try:
                s.close()
            except OSError:
                pass

    def detect_ports(self, ip):
        """Deteccion rapida con corto-circuito.

        - modo 'all': el primer puerto cerrado descarta la IP al instante
          (asi la gran mayoria de IPs se descartan con 1 sola conexion).
        - modo 'any': devuelve los puertos que esten abiertos.

        Devuelve la lista de puertos abiertos que cumplen el filtro, o None
        si la IP no cumple (no se muestra)."""
        ports = self.ports_filter

        if self.match_mode == "all":
            open_ports = []
            for p in ports:
                if not self.running:
                    return None
                if self.check_port(ip, p):
                    open_ports.append(p)
                else:
                    return None  # necesitamos TODOS abiertos
            return open_ports
        else:  # any
            open_ports = []
            for p in ports:
                if not self.running:
                    break
                if self.check_port(ip, p):
                    open_ports.append(p)
            return open_ports if open_ports else None

    def ping_ip_once(self, ip):
        try:
            is_ipv6 = ':' in ip
            if os.name == 'nt':
                cmd = ['ping']
                if is_ipv6:
                    cmd += ['-6']
                cmd += ['-n', '1', '-w', str(self.timeout * 1000), ip]
            else:
                cmd = ['ping']
                if is_ipv6:
                    cmd += ['-6']
                cmd += ['-c', '1', '-W', str(self.timeout), ip]
            result = subprocess.run(cmd, capture_output=True, timeout=self.timeout + 1)
            return result.returncode == 0
        except Exception:
            return False

    def ping_ip(self, ip):
        for _ in range(self.pings_per_ip):
            if not self.running:
                return False
            if self.ping_ip_once(ip):
                return True
            time.sleep(0.03)
        return False

    # ------------------------------------------------------------------
    # Escaneo de una IP (llamado por los workers)
    # ------------------------------------------------------------------
    def scan_ip(self, ip, ip_type="v4"):
        if not self.running:
            return
        with self.lock:
            self.scanned += 1

        if self.ports_filter:
            open_ports = self.detect_ports(ip)
            if open_ports is not None:
                self.record_found(ip, ip_type, open_ports)
        else:
            if self.ping_ip(ip):
                self.record_found(ip, ip_type, [])

    def record_found(self, ip, ip_type, open_ports):
        with self.lock:
            self.alive += 1
            self.found_ips.append(ip)
            self.found_details.append((ip, list(open_ports)))
            count = self.alive
            self.append_to_file(ip, open_ports)  # guardado incremental

        if open_ports:
            plist = ", ".join(f"{p}/{self.port_name(p)}" for p in open_ports)
            tag = C.paint(f"[{plist}]", C.CYAN)
            line = f"{C.paint('[+]', C.GREEN)} {C.paint(ip, C.WHITE)} {tag}  {C.paint(f'({count})', C.GRAY)}"
        else:
            line = (f"{C.paint('[+]', C.GREEN)} [{ip_type}] "
                    f"{C.paint('VIVA', C.GREEN)} {C.paint(ip, C.WHITE)}  {C.paint(f'({count})', C.GRAY)}")
        print(line)

    # ------------------------------------------------------------------
    # Modelo cola + workers (memoria acotada, sin churn de pools)
    # ------------------------------------------------------------------
    def worker(self):
        while self.running:
            try:
                ip, ip_type = self.work_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.scan_ip(ip, ip_type)
            except Exception:
                pass
            finally:
                self.work_queue.task_done()

    def start_workers(self):
        self.workers = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            self.workers.append(t)

    def enqueue(self, ip, ip_type):
        """Encola una IP respetando el limite de la cola (backpressure)."""
        while self.running:
            try:
                self.work_queue.put((ip, ip_type), timeout=0.5)
                return
            except queue.Full:
                continue

    def enqueue_network(self, network, ip_type):
        try:
            net = ipaddress.ip_network(network, strict=False)
        except Exception:
            return

        if net.version == 4:
            hosts = list(net.hosts())
            if len(hosts) > self.max_hosts_scan_ipv4:
                hosts = random.sample(hosts, self.max_hosts_scan_ipv4)
        else:
            total = int(net.num_addresses)
            sample_count = min(self.max_hosts_scan_ipv6, total)
            if total <= sample_count:
                hosts = list(net.hosts())
            else:
                base = int(net.network_address)
                hosts = [ipaddress.ip_address(base + random.randint(0, total - 1))
                         for _ in range(sample_count)]

        random.shuffle(hosts)
        for ip in hosts:
            if not self.running:
                break
            self.enqueue(str(ip), ip_type)

    def wait_drain(self):
        """Espera a que la cola se vacie (modos finitos)."""
        while self.running and not self.work_queue.empty():
            time.sleep(0.2)

    # ------------------------------------------------------------------
    # Productores (generan trabajo segun el modo elegido)
    # ------------------------------------------------------------------
    def produce(self, scan_type, network_custom=None, ipv6_count=None):
        if scan_type in ('class_a', 'class_b', 'class_c'):
            cls = scan_type[-1].upper()
            print(C.paint(f"\n[+] Escaneando Clase {cls} indefinidamente...", C.BLUE))
            while self.running:
                network = self.generate_network_by_class(cls)
                print(C.paint(f"[*] Red: {network}", C.GRAY))
                self.enqueue_network(network, cls)

        elif scan_type == 'all_classes':
            print(C.paint("\n[+] Escaneando TODAS las clases (A+B+C)...", C.BLUE))
            while self.running:
                for cls, repeat in (('A', 3), ('B', 5), ('C', 8)):
                    for _ in range(repeat):
                        if not self.running:
                            break
                        network = self.generate_network_by_class(cls)
                        print(C.paint(f"[*] Red Clase {cls}: {network}", C.GRAY))
                        self.enqueue_network(network, cls)

        elif scan_type == 'random_ipv4':
            print(C.paint("\n[+] Escaneando IPs aleatorias IPv4...", C.BLUE))
            while self.running:
                for cls in random.sample(['A', 'B', 'C'], 3):
                    if not self.running:
                        break
                    self.enqueue(self.generate_ip_by_class(cls), cls)

        elif scan_type == 'random_ipv6':
            print(C.paint("\n[+] Escaneando IPs aleatorias IPv6...", C.BLUE))
            produced = 0
            while self.running:
                first = random.randint(0x2000, 0x3fff)
                rest = random.getrandbits(112)
                ip = str(ipaddress.IPv6Address((first << 112) | rest))
                self.enqueue(ip, "IPv6")
                produced += 1
                if ipv6_count and produced >= ipv6_count:
                    self.wait_drain()
                    break

        elif scan_type == 'custom':
            try:
                net = ipaddress.ip_network(network_custom, strict=False)
            except Exception as e:
                print(C.paint(f"[!] Error parseando la red: {e}", C.RED))
                return
            print(C.paint(f"[*] Escaneando red: {net} (v{net.version})", C.BLUE))
            self.enqueue_network(str(net), f"v{net.version}")
            self.wait_drain()

    # ------------------------------------------------------------------
    # Resultados / persistencia
    # ------------------------------------------------------------------
    def append_to_file(self, ip, open_ports):
        """Guardado incremental: si el proceso muere, los hallazgos ya estan
        en disco. Debe llamarse con self.lock adquirido."""
        try:
            new = not os.path.exists(self.output_file)
            with open(self.output_file, 'a') as f:
                if new:
                    f.write("# IPs VIVAS ENCONTRADAS (guardado incremental)\n")
                    f.write(f"# Archivo: {self.file_counter}\n")
                    f.write("# Fecha inicio: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
                    if self.ports_filter:
                        pl = ", ".join(f"{p}/{self.port_name(p)}" for p in self.ports_filter)
                        f.write(f"# Filtro de puertos ({self.match_mode}): {pl}\n")
                    f.write("# " + "=" * 50 + "\n\n")
                if open_ports:
                    pl = ",".join(str(p) for p in open_ports)
                    f.write(f"{ip}\t{pl}\n")
                else:
                    f.write(f"{ip}\n")
        except Exception:
            pass

    def classify(self, ip):
        if ':' in ip:
            return 'IPv6'
        try:
            first = int(ip.split('.')[0])
        except Exception:
            return None
        if 1 <= first <= 126:
            return 'A'
        if 128 <= first <= 191:
            return 'B'
        if 192 <= first <= 223:
            return 'C'
        return None

    def show_results(self):
        print("\n" + C.paint("=" * 60, C.CYAN))
        print(C.paint("RESUMEN", C.BOLD + C.CYAN))
        print(C.paint("=" * 60, C.CYAN))
        print(f"  IPs escaneadas : {C.paint(str(self.scanned), C.WHITE)}")
        print(f"  IPs encontradas: {C.paint(str(len(self.found_ips)), C.GREEN)}")
        if self.ports_filter:
            pl = ", ".join(f"{p}/{self.port_name(p)}" for p in self.ports_filter)
            print(f"  Filtro puertos : {C.paint(pl, C.CYAN)} ({self.match_mode})")

        if self.found_ips:
            buckets = {'A': [], 'B': [], 'C': [], 'IPv6': []}
            for ip in self.found_ips:
                k = self.classify(ip)
                if k in buckets:
                    buckets[k].append(ip)
            print(C.paint("\n[+] Por clase:", C.BLUE))
            print(f"    Clase A: {len(buckets['A'])}   Clase B: {len(buckets['B'])}"
                  f"   Clase C: {len(buckets['C'])}   IPv6: {len(buckets['IPv6'])}")

            print(C.paint("\n[+] Primeras coincidencias:", C.BLUE))
            for ip, ports in self.found_details[:30]:
                if ports:
                    pl = ", ".join(f"{p}/{self.port_name(p)}" for p in ports)
                    print(f"    {ip}  {C.paint('[' + pl + ']', C.CYAN)}")
                else:
                    print(f"    {ip}")
            if len(self.found_details) > 30:
                print(C.paint(f"    ... y {len(self.found_details) - 30} mas", C.GRAY))

        self.finalize_file()

    def finalize_file(self):
        if not self.found_ips:
            print(C.paint("[!] No se encontraron IPs para guardar", C.YELLOW))
            return
        buckets = {'A': [], 'B': [], 'C': [], 'IPv6': []}
        detail_map = {ip: ports for ip, ports in self.found_details}
        for ip in self.found_ips:
            k = self.classify(ip)
            if k in buckets:
                buckets[k].append(ip)

        titles = {
            'A': "# CLASE A (1.0.0.0 - 126.255.255.255)",
            'B': "# CLASE B (128.0.0.0 - 191.255.255.255)",
            'C': "# CLASE C (192.0.0.0 - 223.255.255.255)",
            'IPv6': "# IPV6 VIVAS",
        }
        try:
            with open(self.output_file, 'w') as f:
                f.write("# IPs VIVAS ENCONTRADAS\n")
                f.write(f"# Archivo: {self.file_counter}\n")
                f.write(f"# Total: {len(self.found_ips)}\n")
                f.write("# Fecha: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
                if self.ports_filter:
                    pl = ", ".join(f"{p}/{self.port_name(p)}" for p in self.ports_filter)
                    f.write(f"# Filtro de puertos ({self.match_mode}): {pl}\n")
                f.write("# " + "=" * 50 + "\n\n")
                for k in ('A', 'B', 'C', 'IPv6'):
                    if buckets[k]:
                        f.write(titles[k] + "\n")
                        for ip in buckets[k]:
                            ports = detail_map.get(ip, [])
                            if ports:
                                f.write(f"{ip}\t{','.join(str(p) for p in ports)}\n")
                            else:
                                f.write(ip + "\n")
                        f.write("\n")
            print(C.paint(f"\n[+] IPs guardadas en: {self.output_file}", C.GREEN))
            print(C.paint(f"[+] Total: {len(self.found_ips)} IPs", C.GREEN))
        except Exception as e:
            print(C.paint(f"[!] Error guardando: {e}", C.RED))

    # ------------------------------------------------------------------
    # Interfaz (menu + configuracion de puertos)
    # ------------------------------------------------------------------
    def banner(self):
        b = r"""
   ___ ____    ____                      _
  |_ _|  _ \  / ___|  ___ __ _ _ __ _ __ ___ _ __
   | || |_) | \___ \ / __/ _` | '__| '_ ` _ \ '__|
   | ||  __/   ___) | (_| (_| | |  | | | | | | |
  |___|_|     |____/ \___\__,_|_|  |_| |_| |_|_|
"""
        print(C.paint(b, C.CYAN))
        print(C.paint("        IP SCANNER ADVANCED  ·  deteccion rapida por puertos", C.BOLD + C.WHITE))
        print(C.paint("        Clases A/B/C · IPv6 · CIDR · filtro de puertos", C.GRAY))

    def print_menu(self):
        print(C.paint("\n" + "─" * 60, C.CYAN))
        print(C.paint("  MODOS DE ESCANEO", C.BOLD + C.YELLOW))
        print(C.paint("─" * 60, C.CYAN))
        opts = [
            ("1", "Clase A", "1.0.0.0 - 126.255.255.255  (grandes redes)"),
            ("2", "Clase B", "128.0.0.0 - 191.255.255.255  (redes medianas)"),
            ("3", "Clase C", "192.0.0.0 - 223.255.255.255  (redes pequenas)"),
            ("4", "Todas las clases", "A + B + C balanceado"),
            ("6", "Red personalizada", "introducir CIDR (IPv4 o IPv6)"),
            ("7", "IPs aleatorias IPv6", "espacio global 2000::/3"),
            ("8", "IPs aleatorias IPv4", "muestreo A/B/C al azar"),
        ]
        for num, name, desc in opts:
            print(f"  {C.paint('[' + num + ']', C.GREEN)} {C.paint(name.ljust(20), C.WHITE)} "
                  f"{C.paint(desc, C.GRAY)}")
        print(f"  {C.paint('[5]', C.RED)} {C.paint('Salir', C.WHITE)}")
        print(C.paint("─" * 60, C.CYAN))

    def show_port_presets(self):
        print(C.paint("\n  Puertos comunes:", C.BOLD + C.YELLOW))
        items = list(COMMON_PORTS.items())
        for i in range(0, len(items), 4):
            row = items[i:i + 4]
            cells = [f"{C.paint(str(p).rjust(5), C.CYAN)} {name.ljust(10)}" for p, name in row]
            print("   " + "".join(cells))

    def ask_port_filter(self):
        """Configura el filtro de 1-3 puertos (deteccion rapida)."""
        print(C.paint("\n" + "─" * 60, C.CYAN))
        print(C.paint("  DETECCION RAPIDA POR PUERTOS", C.BOLD + C.YELLOW))
        print(C.paint("─" * 60, C.CYAN))
        print("  Filtra por puertos OPEN. Ej: escribe " + C.paint("22", C.CYAN) +
              " para ver SOLO IPs con SSH abierto.")
        print("  Puedes indicar hasta " + C.paint("3", C.CYAN) + " puertos (separados por coma).")
        print("  Deja vacio para usar deteccion por " + C.paint("ping ICMP", C.CYAN) + " (modo clasico).")
        self.show_port_presets()

        raw = input(C.paint("\n  [?] Puertos de interes (max 3) o Enter: ", C.GREEN)).strip()
        if not raw:
            self.ports_filter = []
            print(C.paint("  [i] Modo ping ICMP activado.", C.GRAY))
            return

        ports = []
        for tok in raw.replace(";", ",").split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                p = int(tok)
            except ValueError:
                print(C.paint(f"  [!] '{tok}' no es un puerto valido, ignorado.", C.YELLOW))
                continue
            if 1 <= p <= 65535:
                if p not in ports:
                    ports.append(p)
            else:
                print(C.paint(f"  [!] {p} fuera de rango (1-65535), ignorado.", C.YELLOW))

        if not ports:
            self.ports_filter = []
            print(C.paint("  [i] Sin puertos validos -> modo ping ICMP.", C.GRAY))
            return

        if len(ports) > 3:
            ports = ports[:3]
            print(C.paint("  [!] Solo se admiten 3 puertos. Uso los 3 primeros.", C.YELLOW))

        self.ports_filter = ports

        if len(ports) > 1:
            print("\n  Modo de coincidencia:")
            print(f"    {C.paint('[1]', C.GREEN)} TODOS abiertos (AND)  · mas estricto  [por defecto]")
            print(f"    {C.paint('[2]', C.GREEN)} AL MENOS uno abierto (OR)")
            m = input(C.paint("  [?] Elige (1/2): ", C.GREEN)).strip()
            self.match_mode = "any" if m == "2" else "all"
        else:
            self.match_mode = "all"

        pl = ", ".join(f"{p}/{self.port_name(p)}" for p in self.ports_filter)
        print(C.paint(f"  [+] Filtro activo: {pl}  ({self.match_mode})", C.GREEN))

    def ask_performance(self):
        """Permite bajar hilos/timeout (util en moviles/Termux)."""
        print(C.paint("\n  Rendimiento (Enter = valores por defecto):", C.GRAY))
        try:
            t = input(C.paint(f"  [?] Hilos [{self.threads}]: ", C.GREEN)).strip()
            if t:
                self.threads = max(1, min(500, int(t)))
        except ValueError:
            pass
        try:
            to = input(C.paint(f"  [?] Timeout por conexion en s [{self.port_timeout}]: ", C.GREEN)).strip()
            if to:
                self.port_timeout = max(0.2, min(10.0, float(to)))
                self.timeout = max(1, int(round(self.port_timeout)))
        except ValueError:
            pass

    # ------------------------------------------------------------------
    # Bucle principal (todo integrado aqui)
    # ------------------------------------------------------------------
    def run(self):
        self.banner()

        scan_type = None
        network_custom = None
        ipv6_count = None

        while True:
            self.print_menu()
            choice = input(C.paint("\n[+] Selecciona una opcion: ", C.GREEN)).strip()

            if choice == '1':
                scan_type = 'class_a'; break
            elif choice == '2':
                scan_type = 'class_b'; break
            elif choice == '3':
                scan_type = 'class_c'; break
            elif choice == '4':
                scan_type = 'all_classes'; break
            elif choice == '5':
                print(C.paint("[*] Saliendo.", C.GRAY)); return
            elif choice == '6':
                network_custom = input(C.paint(
                    "[+] Red/CIDR (ej: 192.168.1.0/24 o 2001:db8::/64): ", C.GREEN)).strip()
                if network_custom:
                    scan_type = 'custom'; break
                print(C.paint("[!] CIDR vacio.", C.YELLOW))
            elif choice == '7':
                try:
                    ipv6_count = int(input(C.paint(
                        "[+] Cuantas IPs IPv6 escanear? (0=indefinido, def 100): ", C.GREEN)).strip() or 100)
                except ValueError:
                    ipv6_count = 100
                scan_type = 'random_ipv6'; break
            elif choice == '8':
                scan_type = 'random_ipv4'; break
            else:
                print(C.paint("[!] Opcion invalida", C.YELLOW))

        # Configuracion comun a TODOS los modos (deteccion rapida por puertos)
        self.ask_port_filter()
        self.ask_performance()

        print(C.paint("\n" + "─" * 60, C.CYAN))
        if self.ports_filter:
            pl = ", ".join(f"{p}/{self.port_name(p)}" for p in self.ports_filter)
            print(C.paint(f"[+] Iniciando deteccion por puertos: {pl} ({self.match_mode})", C.BOLD + C.GREEN))
        else:
            print(C.paint("[+] Iniciando deteccion por ping ICMP (2 intentos/IP)", C.BOLD + C.GREEN))
        print(C.paint(f"[+] Hilos: {self.threads} · Timeout: {self.port_timeout}s", C.GRAY))
        print(C.paint("[+] Pulsa CTRL+C para detener y guardar", C.GRAY))
        print(C.paint("─" * 60, C.CYAN))

        self.start_workers()
        try:
            self.produce(scan_type, network_custom, ipv6_count)
        except KeyboardInterrupt:
            pass

        # Cierre ordenado
        self.running = False
        for t in self.workers:
            t.join(timeout=1.0)
        self.show_results()


if __name__ == "__main__":
    scanner = IPScannerAdvanced()
    scanner.run()

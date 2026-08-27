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
import errno
import ssl
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

        # Filtro de firewall (requiere ports_filter activo)
        # "any" = sin filtrar, "no_firewall" = solo IPs que responden claro
        # (abierto/rechazado), "with_firewall" = solo IPs que filtran/callan
        self.firewall_mode = "any"
        self.verify_delay = 0.15     # pausa entre el 1er y 2o intento al verificar "open"

        # Validacion de host (anti-middlebox / anti-IDS)
        self.validate_hosts = True
        self.skipped_middlebox = 0   # descartadas por canary ports (middlebox/CPE)
        self.skipped_no_banner = 0   # descartadas por no tener servicio real
        self.skipped_dead = 0        # descartadas por conexion muerta post-probe

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
        """Conexion TCP ligera (sin lanzar procesos). Devuelve el estado real:
        'open' (handshake completado), 'closed' (rechazo activo/RST -> no hay
        nada filtrando esa conexion) o 'filtered' (timeout, sin respuesta,
        tipico de un firewall descartando el paquete en silencio)."""
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(self.port_timeout)
        try:
            result = s.connect_ex((ip, port))
            if result == 0:
                return 'open'
            if result == errno.ECONNREFUSED:
                return 'closed'
            return 'filtered'
        except socket.timeout:
            return 'filtered'
        except OSError:
            return 'filtered'
        finally:
            try:
                s.close()
            except OSError:
                pass

    def probe_port(self, ip, port):
        """Prueba un puerto y confirma los 'open' con una segunda conexion
        independiente antes de darlos por buenos. Esto es lo que evita los
        falsos positivos frente a Nmap: algunos firewalls/tarpits aceptan el
        handshake una unica vez (o de forma intermitente) para despistar al
        escaner, y una sola conexion no basta para distinguirlo de un
        servicio real."""
        state = self.check_port(ip, port)
        if state == 'open':
            if not self.running:
                return state
            time.sleep(self.verify_delay)
            if self.check_port(ip, port) != 'open':
                state = 'filtered'  # abrio una vez y no repite: no es fiable
        return state

    # ------------------------------------------------------------------
    # Validacion de host (B: canary, A: banner, C: post-probe)
    # ------------------------------------------------------------------
    def canary_check(self, ip):
        """B: Prueba 3 puertos aleatorios altos que un host real deberia
        rechazar (RST/closed). Si TODOS los acepta (open) sin rechazar
        ninguno, es un middlebox/CPE que acepta todo sin servir nada."""
        exclude = set(self.ports_filter)
        canary_ports = []
        while len(canary_ports) < 3:
            p = random.randint(40000, 59999)
            if p not in exclude and p not in canary_ports:
                canary_ports.append(p)

        has_closed = False
        has_open = False
        for port in canary_ports:
            if not self.running:
                return True
            state = self.check_port(ip, port)
            if state == 'closed':
                has_closed = True
                break
            if state == 'open':
                has_open = True

        if has_closed:
            return True
        if has_open:
            return False
        return True

    def grab_banner(self, ip, port):
        """A: Intenta leer datos reales de un puerto abierto. Un servicio
        real envia un banner (SSH, SMTP, FTP) o responde a un probe
        (HTTP). Un middlebox o puerto fantasma acepta la conexion pero
        no envia nada."""
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.port_timeout)
        try:
            sock.connect((ip, port))

            if port in (443, 465, 993, 995, 8443):
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ss = ctx.wrap_socket(sock)
                    ss.close()
                    return True
                except ssl.SSLError:
                    return True
                except Exception:
                    return False

            if port in (80, 8080, 8000, 8888):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: check\r\n\r\n")

            sock.settimeout(2.0)
            try:
                data = sock.recv(256)
                if data:
                    return True
            except socket.timeout:
                pass

            try:
                sock.sendall(b"\r\n")
                sock.settimeout(1.5)
                data = sock.recv(256)
                return bool(data)
            except Exception:
                return False
        except Exception:
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def banner_check(self, ip, open_ports):
        """A: Verifica que al menos un puerto abierto tiene un servicio
        real detras (responde con datos). Si ningun puerto envia nada,
        la IP probablemente no tiene servicios reales."""
        for port in open_ports:
            if not self.running:
                return True
            if self.grab_banner(ip, port):
                return True
        return False

    def post_probe_check(self, ip, open_ports):
        """C: Reconecta a un puerto abierto despues de todo el probing
        para verificar que el host no nos ha bloqueado (IDS/rate-limit).
        Si la conexion murio, este host 'morira' tambien en un scan."""
        if not open_ports:
            return True
        time.sleep(0.3)
        return self.check_port(ip, open_ports[0]) == 'open'

    def detect_ports(self, ip):
        """Deteccion rapida con corto-circuito.

        - modo 'all': el primer puerto que no queda confirmado como abierto
          descarta la IP al instante.
        - modo 'any': prueba todos los puertos y devuelve los que esten
          abiertos.

        Devuelve (puertos_abiertos, estados_por_puerto) si la IP cumple el
        filtro, o None si no cumple (no se muestra). 'estados_por_puerto' se
        usa despues para el veredicto de firewall (ver firewall_verdict)."""
        ports = self.ports_filter
        port_states = {}

        if self.match_mode == "all":
            for p in ports:
                if not self.running:
                    return None
                state = self.probe_port(ip, p)
                port_states[p] = state
                if state != 'open':
                    return None  # necesitamos TODOS abiertos
            return list(ports), port_states
        else:  # any
            for p in ports:
                if not self.running:
                    break
                port_states[p] = self.probe_port(ip, p)
            open_ports = [p for p in ports if port_states.get(p) == 'open']
            return (open_ports, port_states) if open_ports else None

    def firewall_verdict(self, port_states):
        """'con_firewall' si algun puerto probado se quedo sin respuesta
        (filtered); 'sin_firewall' si todos los puertos dieron una respuesta
        clara (abierto o rechazado), lo que indica que se puede escanear la
        IP directamente sin que nada intercepte los paquetes."""
        if any(s == 'filtered' for s in port_states.values()):
            return 'con_firewall'
        return 'sin_firewall'

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
            result = self.detect_ports(ip)
            if result is None:
                return
            open_ports, port_states = result
            verdict = self.firewall_verdict(port_states)
            if self.firewall_mode == "no_firewall" and verdict != "sin_firewall":
                return
            if self.firewall_mode == "with_firewall" and verdict != "con_firewall":
                return
            if self.validate_hosts and self.running:
                if not self.canary_check(ip):
                    with self.lock:
                        self.skipped_middlebox += 1
                    return
                if not self.banner_check(ip, open_ports):
                    with self.lock:
                        self.skipped_no_banner += 1
                    return
                if not self.post_probe_check(ip, open_ports):
                    with self.lock:
                        self.skipped_dead += 1
                    return
            self.record_found(ip, ip_type, open_ports, verdict)
        else:
            if self.ping_ip(ip):
                self.record_found(ip, ip_type, [], None)

    def record_found(self, ip, ip_type, open_ports, verdict=None):
        with self.lock:
            self.alive += 1
            self.found_ips.append(ip)
            self.found_details.append((ip, list(open_ports), verdict))
            count = self.alive
            self.append_to_file(ip, open_ports, verdict)  # guardado incremental

        if open_ports:
            plist = ", ".join(f"{p}/{self.port_name(p)}" for p in open_ports)
            tag = C.paint(f"[{plist}]", C.CYAN)
            fw_tag = ""
            if verdict == "con_firewall":
                fw_tag = "  " + C.paint("[con firewall]", C.YELLOW)
            elif verdict == "sin_firewall":
                fw_tag = "  " + C.paint("[sin firewall]", C.MAGENTA)
            line = f"{C.paint('[+]', C.GREEN)} {C.paint(ip, C.WHITE)} {tag}{fw_tag}  {C.paint(f'({count})', C.GRAY)}"
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
    def append_to_file(self, ip, open_ports, verdict=None):
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
                        if self.firewall_mode != "any":
                            f.write(f"# Filtro de firewall: {self.firewall_mode}\n")
                    f.write("# " + "=" * 50 + "\n\n")
                fw = f"\t{verdict}" if verdict else ""
                if open_ports:
                    pl = ",".join(str(p) for p in open_ports)
                    f.write(f"{ip}\t{pl}{fw}\n")
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
        if self.validate_hosts and self.ports_filter:
            skipped = self.skipped_middlebox + self.skipped_no_banner + self.skipped_dead
            if skipped:
                print(f"  IPs descartadas: {C.paint(str(skipped), C.YELLOW)} (validacion de host)")
                if self.skipped_middlebox:
                    print(C.paint(f"    · Middlebox/CPE detectado : {self.skipped_middlebox}", C.GRAY))
                if self.skipped_no_banner:
                    print(C.paint(f"    · Sin servicio real       : {self.skipped_no_banner}", C.GRAY))
                if self.skipped_dead:
                    print(C.paint(f"    · Conexion muerta (IDS)   : {self.skipped_dead}", C.GRAY))
        if self.ports_filter:
            pl = ", ".join(f"{p}/{self.port_name(p)}" for p in self.ports_filter)
            print(f"  Filtro puertos : {C.paint(pl, C.CYAN)} ({self.match_mode})")
            if self.firewall_mode != "any":
                print(f"  Filtro firewall: {C.paint(self.firewall_mode, C.YELLOW)}")

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
            for ip, ports, verdict in self.found_details[:30]:
                fw = ""
                if verdict == "con_firewall":
                    fw = "  " + C.paint("[con firewall]", C.YELLOW)
                elif verdict == "sin_firewall":
                    fw = "  " + C.paint("[sin firewall]", C.MAGENTA)
                if ports:
                    pl = ", ".join(f"{p}/{self.port_name(p)}" for p in ports)
                    print(f"    {ip}  {C.paint('[' + pl + ']', C.CYAN)}{fw}")
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
        detail_map = {ip: (ports, verdict) for ip, ports, verdict in self.found_details}
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
                    if self.firewall_mode != "any":
                        f.write(f"# Filtro de firewall: {self.firewall_mode}\n")
                f.write("# " + "=" * 50 + "\n\n")
                for k in ('A', 'B', 'C', 'IPv6'):
                    if buckets[k]:
                        f.write(titles[k] + "\n")
                        for ip in buckets[k]:
                            ports, verdict = detail_map.get(ip, ([], None))
                            fw = f"\t{verdict}" if verdict else ""
                            if ports:
                                f.write(f"{ip}\t{','.join(str(p) for p in ports)}{fw}\n")
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

    def ask_firewall_mode(self):
        """Filtro CON/SIN firewall. Solo tiene sentido con puertos activos,
        porque necesita el estado TCP real (open/closed/filtered) de cada
        puerto: un puerto que no responde nada (filtered) es indicio de un
        firewall descartando el paquete en silencio; un puerto que responde
        con RST (closed) o completa el handshake (open) indica que nada
        esta filtrando esa conexion, es decir, la IP admite escaneo directo."""
        if not self.ports_filter:
            self.firewall_mode = "any"
            return
        print(C.paint("\n" + "─" * 60, C.CYAN))
        print(C.paint("  DETECCION DE FIREWALL", C.BOLD + C.YELLOW))
        print(C.paint("─" * 60, C.CYAN))
        print("  Permite separar IPs que responden con claridad (aptas para")
        print("  escanear a fondo) de IPs detras de un firewall que filtra")
        print("  los paquetes en silencio.")
        print(f"    {C.paint('[1]', C.GREEN)} Cualquiera                [por defecto]")
        print(f"    {C.paint('[2]', C.GREEN)} Solo IPs SIN firewall     (permiten escaneo directo)")
        print(f"    {C.paint('[3]', C.GREEN)} Solo IPs CON firewall     (filtran/descartan paquetes)")
        m = input(C.paint("  [?] Elige (1/2/3): ", C.GREEN)).strip()
        self.firewall_mode = {"2": "no_firewall", "3": "with_firewall"}.get(m, "any")
        if self.firewall_mode != "any":
            print(C.paint(f"  [+] Filtro de firewall activo: {self.firewall_mode}", C.GREEN))

    def ask_validation(self):
        """Configurar la validacion anti-middlebox / anti-IDS."""
        if not self.ports_filter:
            self.validate_hosts = False
            return
        print(C.paint("\n" + "─" * 60, C.CYAN))
        print(C.paint("  VALIDACION DE HOST", C.BOLD + C.YELLOW))
        print(C.paint("─" * 60, C.CYAN))
        print("  Comprueba que la IP es un host real con servicios reales,")
        print("  no un middlebox/CPE que acepta todo sin servir nada.")
        print("  Tambien verifica que la conexion no muere tras el probe.")
        print()
        print(C.paint("  Checks:", C.WHITE))
        print(C.paint("    · Canary ports  ", C.CYAN) + "prueba puertos random que deberian estar cerrados")
        print(C.paint("    · Banner grab   ", C.CYAN) + "verifica que el servicio responde con datos reales")
        print(C.paint("    · Post-probe    ", C.CYAN) + "reconecta tras el probe para detectar IDS/bloqueo")
        print()
        print(f"    {C.paint('[1]', C.GREEN)} Activar validacion      [por defecto]")
        print(f"    {C.paint('[2]', C.GREEN)} Desactivar (mas rapido, menos fiable)")
        m = input(C.paint("  [?] Elige (1/2): ", C.GREEN)).strip()
        self.validate_hosts = m != "2"
        if self.validate_hosts:
            print(C.paint("  [+] Validacion de host activa", C.GREEN))
        else:
            print(C.paint("  [i] Validacion de host desactivada.", C.GRAY))

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
        self.ask_firewall_mode()
        self.ask_validation()
        self.ask_performance()

        print(C.paint("\n" + "─" * 60, C.CYAN))
        if self.ports_filter:
            pl = ", ".join(f"{p}/{self.port_name(p)}" for p in self.ports_filter)
            print(C.paint(f"[+] Iniciando deteccion por puertos: {pl} ({self.match_mode})", C.BOLD + C.GREEN))
            if self.firewall_mode != "any":
                print(C.paint(f"[+] Filtro de firewall: {self.firewall_mode}", C.BOLD + C.GREEN))
            if self.validate_hosts:
                print(C.paint("[+] Validacion: canary + banner + post-probe", C.BOLD + C.GREEN))
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

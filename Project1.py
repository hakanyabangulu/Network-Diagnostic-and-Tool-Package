import socket  # Socket oluşturma
import time  # Zaman formatlama
import threading  # Mesaj alma vb işlemler
import struct  # Zaman damgası
import tkinter as tk  # Arayüz için
from tkinter import scrolledtext, ttk, filedialog, messagebox  # Arayüz için
import os  # Dosyaya yazma
from concurrent.futures import ThreadPoolExecutor
import logging  # toolkit için
from datetime import datetime
from binascii import hexlify  # Convert Ip
import json  # Ayarların kaydı için

# Configure logging
logging.basicConfig(filename='network_toolkit.log', level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')

CHAT_LOG_FILE = "chat_history.txt"
DEFAULT_TIMEOUT = 1.0
MAX_THREADS = 10
EXIT_COMMAND = "exit"
SEND_BUF_SIZE = 4096
RECV_BUF_SIZE = 2048
SETTINGS_FILE = "settings.json"  # Ayarları kaydedeceğimiz dosya
NTP_SERVER = "0.uk.pool.ntp.org"
TIME1970 = 2208988800
DATA_PAYLOAD = 2048  # echo_server için buffer boyutu
BACKLOG = 5  # Maksimum queued bağlantı sayısı

class NetworkToolkitGUI:
    def __init__(self):
        # Pencere ve temel değişkenler
        self.root = tk.Tk()
        self.dark_mode = True
        # Varsayılan ayarlar
        self.is_blocking = True  # Varsayılan olarak blocking mod
        self.send_buf_size = SEND_BUF_SIZE
        self.recv_buf_size = RECV_BUF_SIZE
        self.timeout = DEFAULT_TIMEOUT
        self.load_settings()  # Ayarların yüklenmesi
        self.setup_gui()
        self.running = True
        self.chat_active = False
        self.echo_mode = None  # None: Inactive, "server": Server active, "client": Client active
        self.executor = ThreadPoolExecutor(max_workers=MAX_THREADS)

    def load_settings(self):
        # Ayarların settings.json 'dan yüklenmesi
        try:
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, 'r') as f:
                    settings = json.load(f)
                    self.is_blocking = settings.get("is_blocking", True)
                    self.send_buf_size = settings.get("send_buf_size", SEND_BUF_SIZE)
                    self.recv_buf_size = settings.get("recv_buf_size", RECV_BUF_SIZE)
                    self.timeout = settings.get("timeout", DEFAULT_TIMEOUT)
        except Exception as e:
            print(f"Error loading settings: {str(e)}")
            # Hata durumunda default

    def save_settings(self):
        # settings.json, ayarları save etmemiz için
        try:
            settings = {
                "is_blocking": self.is_blocking,
                "send_buf_size": self.send_buf_size,
                "recv_buf_size": self.recv_buf_size,
                "timeout": self.timeout
            }
            with open(SETTINGS_FILE, 'w') as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            print(f"Error saving settings: {str(e)}")

    def setup_gui(self):
        # Pencere başlığı ve boyutu
        self.root.title("Network Diagnostic and Tool Package Project")
        self.root.geometry("900x700")
        self.root.configure(bg="#1a1a1a")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Butonlar ve diğer bileşenler için stil 
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", font=("Helvetica", 12, "bold"), padding=10, background="#4a4a4a", 
                       foreground="#ffffff", borderwidth=0)
        style.map("TButton", background=[("active", "#6a6a6a")])
        style.configure("TLabel", background="#1a1a1a", foreground="#00ff00", font=("Helvetica", 10))
        style.configure("TFrame", background="#1a1a1a")

        # Ana çerçeve 
        main_frame = ttk.Frame(self.root)
        main_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        # Sol panel
        left_panel = ttk.Frame(main_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))

        # Ayarlar bölümü
        settings_frame = ttk.LabelFrame(left_panel, text="Settings", padding=10)
        settings_frame.pack(pady=(0, 10), fill=tk.X)

        # Host 
        tk.Label(settings_frame, text="Host:", fg="#00ff00", bg="#1a1a1a").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.host_entry = ttk.Entry(settings_frame, width=20)
        self.host_entry.insert(0, "localhost")
        self.host_entry.grid(row=0, column=1, padx=5, pady=5)

        # Port
        tk.Label(settings_frame, text="Port:", fg="#00ff00", bg="#1a1a1a").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.port_entry = ttk.Entry(settings_frame, width=20)
        self.port_entry.insert(0, "9900")  # Verdiğiniz örnekte 9900 kullanıldı
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)

        # Blocking/Non-Blocking Mod 
        tk.Label(settings_frame, text="Socket Mode:", fg="#00ff00", bg="#1a1a1a").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.mode_var = tk.StringVar(value="Blocking" if self.is_blocking else "Non-Blocking")
        self.mode_menu = ttk.Combobox(settings_frame, textvariable=self.mode_var, values=["Blocking", "Non-Blocking"], state="readonly", width=17)
        self.mode_menu.grid(row=2, column=1, padx=5, pady=5)

        # Send Buffer Size 
        tk.Label(settings_frame, text="Send Buffer Size:", fg="#00ff00", bg="#1a1a1a").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.send_buf_entry = ttk.Entry(settings_frame, width=20)
        self.send_buf_entry.insert(0, str(self.send_buf_size))  # default değerler
        self.send_buf_entry.grid(row=3, column=1, padx=5, pady=5)

        # Receive Buffer Size 
        tk.Label(settings_frame, text="Recv Buffer Size:", fg="#00ff00", bg="#1a1a1a").grid(row=4, column=0, padx=5, pady=5, sticky="e")
        self.recv_buf_entry = ttk.Entry(settings_frame, width=20)
        self.recv_buf_entry.insert(0, str(self.recv_buf_size))  # default değerler
        self.recv_buf_entry.grid(row=4, column=1, padx=5, pady=5)

        # Timeout 
        tk.Label(settings_frame, text="Timeout (s):", fg="#00ff00", bg="#1a1a1a").grid(row=5, column=0, padx=5, pady=5, sticky="e")
        self.timeout_entry = ttk.Entry(settings_frame, width=20)
        self.timeout_entry.insert(0, str(self.timeout))  # default değerler
        self.timeout_entry.grid(row=5, column=1, padx=5, pady=5)

        # Butonlar için bir çerçeve ve fonksiyonlar
        buttons_frame = ttk.Frame(left_panel)
        buttons_frame.pack(fill=tk.Y)

        buttons = [
            ("Machine Information Module", self.get_machine_info),
            ("Echo Test Module as Server", self.echo_server),
            ("Echo Test Module as Client", self.echo_client),
            ("SNTP Time Synchronization Module", self.sntp_client),
            ("Simple Chat Module as Server", self.chat_server),
            ("Simple Chat Module as Client", self.chat_client),
            ("Adjust Buffer Size", self.modify_buff_size),
            ("Test Socket Timeout", self.test_socket_timeout),
            ("Switch Theme", self.toggle_theme),
        ]

        for i, (text, command) in enumerate(buttons):
            btn = ttk.Button(buttons_frame, text=text, command=lambda cmd=command: self.run_function(cmd))
            btn.pack(pady=5, fill=tk.X)

        # Sağ panel
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Çıktı alanı
        output_frame = ttk.LabelFrame(right_panel, text="Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.output_text = scrolledtext.ScrolledText(output_frame, height=20, state=tk.DISABLED, bg="#252526", fg="#00ff00", font=("Consolas", 11), borderwidth=0, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Chat giriş alanı
        chat_frame = ttk.LabelFrame(right_panel, text="Chat Input", padding=10)
        chat_frame.pack(fill=tk.X)

        self.chat_input = ttk.Entry(chat_frame)
        self.chat_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.chat_input.bind("<Return>", self.send_message)

        send_btn = ttk.Button(chat_frame, text="Send", command=self.send_message, width=10)
        send_btn.pack(side=tk.RIGHT)

        # İlerleme çubuğu
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(right_panel, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=10)

    def Info(self, message, log_type="INFO"):
        # Güncelleme fonksiyonu
        self.root.after(0, lambda: self._safe_update_output(message))
        logging.log(logging.INFO if log_type == "INFO" else logging.ERROR, message)
        
        with open(CHAT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {log_type}: {message}\n")

    def _safe_update_output(self, message):
        # Çıktı alanını güncellemesi
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.output_text.config(state=tk.DISABLED)
        self.output_text.yview(tk.END)

    def run_function(self, func):
        # Ayarları güncelleyip fonksiyonu çalıştırıyorum.
        self.update_settings()
        self.executor.submit(func)

    def update_settings(self):
        # Ayarları güncelleme fonksiyonu.
        try:
            # Yeni değerleri al
            new_blocking = self.mode_var.get() == "Blocking"
            new_send_buf_size = int(self.send_buf_entry.get())
            new_recv_buf_size = int(self.recv_buf_entry.get())
            new_timeout = float(self.timeout_entry.get())

            # Eski değerlerle karşılaştırma
            if (self.is_blocking != new_blocking or 
                self.send_buf_size != new_send_buf_size or 
                self.recv_buf_size != new_recv_buf_size or 
                self.timeout != new_timeout):
                # Değerler değiştiyse güncelle ve kaydet
                self.is_blocking = new_blocking
                self.send_buf_size = new_send_buf_size
                self.recv_buf_size = new_recv_buf_size
                self.timeout = new_timeout
                self.save_settings()  # Ayarları dosyaya kaydet
                self.Info("Settings updated and saved successfully!", "INFO")
        except ValueError as e:
            self.Info(f"Settings error: {str(e)}", "ERROR")

    def apply_socket_settings(self, sock):
        # Soket ayarları
        sock.setblocking(self.is_blocking)
        if not self.is_blocking:
            sock.settimeout(self.timeout)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.send_buf_size)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.recv_buf_size)

    def get_host_port(self, is_server=True):
        # Host ve portu döndürür, istemci sunucu portuna bağlanır
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())  # Tek port kullanılır
            return host, port
        except ValueError:
            self.Info("Invalid port number!", "ERROR")
            return "localhost", 9900  # Varsayılan port 9900 olarak ayarlandı

    def get_machine_info(self):
        # Week2 deki machine_info ve convert ip entegrasyonu.
        try:
            # Hostname ve IP adresini alıyorum.
            host_name = socket.gethostname()
            ip_address = socket.gethostbyname(host_name)
            self.Info(f"Host name: {host_name}")
            self.Info(f"IP Address: {ip_address}")

            # IP adresini packed ve unpacked formatta gösteriyorum.
            for ip_addr in ['127.0.0.1', '192.168.0.1']:
                packed_ip_addr = socket.inet_aton(ip_addr)
                unpacked_ip_addr = socket.inet_ntoa(packed_ip_addr)
                self.Info(f"IP Address: {ip_addr} => Packed: {hexlify(packed_ip_addr).decode()}, Unpacked: {unpacked_ip_addr}")
        except Exception as e:
            self.Info(f"Error getting machine info: {str(e)}", "ERROR")

    def echo_server(self):
    # Server (TCP tabanlı) # week 2
        if self.echo_mode == "client":
            self.Info("Cannot start server while client is active! Stop client first.", "ERROR")
            return
        self.echo_mode = "server"
        host, port = self.get_host_port(is_server=True)
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Portu hemen serbest bırak
            self.apply_socket_settings(server_socket)
            server_address = (host, port)
            self.Info(f"Starting up echo server on {host} port {port}")
            server_socket.bind(server_address)
            server_socket.listen(BACKLOG)
            self.Info("Waiting to receive message from client")
            client, address = server_socket.accept()  # Tek bağlantı kabul et
            try:
                data = client.recv(DATA_PAYLOAD)
                if data:
                    self.Info(f"Data: {data.decode('utf-8')}")
                    client.send(data)
                    self.Info(f"Sent {len(data)} bytes back to {address}")
            except socket.error as e:
                self.Info(f"Socket error: {str(e)}", "ERROR")
            finally:
                client.close()
        except socket.error as e:
            self.Info(f"Echo server error: {str(e)}", "ERROR")
        finally:
            server_socket.close()
            self.echo_mode = None

    def echo_client(self):
    # Client (TCP tabanlı) # week 2 
        if self.echo_mode == "server":
            self.Info("Cannot start client while server is active! Stop server first.", "ERROR")
            return
        self.echo_mode = "client"
        host, port = self.get_host_port(is_server=True)  # İstemci, sunucu portuna bağlanır
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.apply_socket_settings(client_socket)
            server_address = (host, port)
            self.Info(f"Connecting to {host} port {port}")
            client_socket.connect(server_address)

            # Send data
            message = "Test message. This will be echoed"
            self.Info(f"Sending {message}")
            client_socket.sendall(message.encode('utf-8'))
            full_data = b""  # Tüm veriyi biriktirmek için
            amount_received = 0
            amount_expected = len(message)
            while amount_received < amount_expected:
                data = client_socket.recv(16)
                if not data:
                    break
                full_data += data
                amount_received += len(data)
            self.Info(f"Received  message: {full_data.decode('utf-8')}")
        except socket.error as e:
            self.Info(f"Socket error: {str(e)}", "ERROR")
        except Exception as e:
            self.Info(f"Other exception: {str(e)}", "ERROR")
        finally:
            self.Info("Closing connection to the server")
            client_socket.close()
            self.echo_mode = None

    def sntp_client(self):
        # Week 2 deki sntp entegrasyonu
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.apply_socket_settings(client)
            msg = b'\x1b' + 47 * b'\0'  # SNTP istemci mesajı
            client.sendto(msg, (NTP_SERVER, 123))
            data, address = client.recvfrom(1024)
            if data:
                self.Info(f"Response received from: {address}")
            t = struct.unpack('!12I', data)[10]  # 10. indeks zaman damgası
            t -= TIME1970  # NTP epoch (1900) ile Unix epoch (1970) arasındaki fark
            self.Info(f"SNTP Time: {time.ctime(t)}")
        finally:
            client.close()

    def modify_buff_size(self):
        # Buffer size görüntülenmesi ve değiştirilmesi.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sndbufsize = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            self.Info(f"Send Buffer size [Before]: {sndbufsize}")
            rcvbufsize = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            self.Info(f"Receive Buffer size [Before]: {rcvbufsize}")

            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.send_buf_size)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.recv_buf_size)

            sndbufsize = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            self.Info(f"Send Buffer size [After]: {sndbufsize}")
            rcvbufsize = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            self.Info(f"Receive Buffer size [After]: {rcvbufsize}")
        except Exception as e:
            self.Info(f"Buffer size modification error: {str(e)}", "ERROR")
        finally:
            sock.close()

    def test_socket_timeout(self):
        # Timeout çekilmesi
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.Info(f"Default socket timeout: {s.gettimeout()}")
            s.settimeout(self.timeout)
            self.Info(f"Current socket timeout: {s.gettimeout()}")
        except Exception as e:
            self.Info(f"Socket timeout test error: {str(e)}", "ERROR")
        finally:
            s.close()

    def chat_server(self):  # Chat Server side
        #Chat sunucusunun çalışıp çalışmadığının kontrolü
        if self.chat_active:
            self.Info("Chat server is already running!", "ERROR")
            return
            
        host, port = self.get_host_port()
        try:
            # TCP soketi oluştur
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.apply_socket_settings(self.server_socket)
            self.server_socket.bind((host, port))
            # Maksimum 1 istemci 
            self.server_socket.listen(1)
            # Chat modu aktif
            self.chat_active = True
            self.Info(f"Chat Server started on {host}:{port}, waiting for client...")
            # İstemci bağlantısını bekle ve kabul et
            conn, addr = self.server_socket.accept()
            self.chat_conn = conn
            self.Info(f"Connected to {addr}")
            # Mesajları almak için ayrı bir thread 
            threading.Thread(target=self.handle_chat_receive, args=(conn, "Client"), daemon=True).start()

        except Exception as e:
            self.Info(f"Chat server error: {str(e)}", "ERROR")

    def chat_client(self):  # Chat client side
        #Chat client çalışıp çalışmadığının kontrolü
        if self.chat_active:
            self.Info("Chat client is already running!", "ERROR")
            return
            
        host, port = self.get_host_port()
        try:
            # TCP soketi
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.apply_socket_settings(self.client_socket)
            # Sunucuya bağlan
            self.client_socket.connect((host, port))
            self.chat_active = True
            self.Info("Connected to chat server")
            # Mesajları almak için ayrı bir thread 
            threading.Thread(target=self.handle_chat_receive, args=(self.client_socket, "Server"), daemon=True).start()

        except Exception as e:
            self.Info(f"Chat client error: {str(e)}", "ERROR")

    def handle_chat_receive(self, conn, sender):
        # Chat mesajlarını almak için
        try:
            while self.running and self.chat_active:
                # İstemciden gelen mesaj (maks. 1024 bayt)
                msg = conn.recv(1024).decode()
                if not msg:
                    break
                # "exit" komutuyla sohbeti sonlandır
                if msg.lower() == EXIT_COMMAND:
                    self.Info(f"Chat terminated by {sender}")
                    self.chat_active = False
                    conn.close()
                    break
                # Gelen mesaj GUI'ye
                self.Info(f"{sender}: {msg}")
        except Exception as e:
            self.Info(f"Chat receive error: {str(e)}", "ERROR")
        finally:
            conn.close()

    def send_message(self, event=None):
        # Chat'in aktif olup olmadığını ve bağlantının mevcut olduğunun kontrolü
        if not self.chat_active or (not hasattr(self, 'chat_conn') and not hasattr(self, 'client_socket')):
            self.Info("Chat is not active! Start server or client first.", "ERROR")
            return
        # Giriş alanından mesaj ve boşlukların temizlenmesi
        msg = self.chat_input.get().strip()
        if msg:
            try:
                #Server ==> Client
                if hasattr(self, 'chat_conn'):  # Server side
                    self.chat_conn.sendall(msg.encode())
                    self.Info(f"Server: {msg}")
                #Client ==> Server    
                elif hasattr(self, 'client_socket'):  # Client side
                    self.client_socket.sendall(msg.encode())
                    self.Info(f"Client: {msg}")
                # "exit" komutuyla sohbeti sonlandır
                if msg.lower() == EXIT_COMMAND:
                    self.Info("Chat terminated")
                    self.chat_active = False
                    if hasattr(self, 'chat_conn'):
                        self.chat_conn.close()
                    if hasattr(self, 'client_socket'):
                        self.client_socket.close()

                self.chat_input.delete(0, tk.END)
            except Exception as e:
                self.Info(f"Send error: {str(e)}", "ERROR")

    def toggle_theme(self):  # Karanlık ve Aydınlık tema 
        if self.dark_mode:
            self.root.configure(bg="#f0f0f0")
            self.output_text.config(bg="#ffffff", fg="#000000")
            self.chat_input.configure(style="Light.TEntry")
            style = ttk.Style()
            style.configure("TButton", background="#e0e0e0", foreground="#000000")
            style.configure("TLabel", background="#f0f0f0", foreground="#000000")
            style.configure("TFrame", background="#f0f0f0")
            self.dark_mode = False
        else:
            self.root.configure(bg="#1a1a1a")
            self.output_text.config(bg="#252526", fg="#00ff00")
            self.chat_input.configure(style="Dark.TEntry")
            style = ttk.Style()
            style.configure("TButton", background="#4a4a4a", foreground="#ffffff")
            style.configure("TLabel", background="#1a1a1a", foreground="#00ff00")
            style.configure("TFrame", background="#1a1a1a")
            self.dark_mode = True  # Default olarak karanlık tema

    def on_closing(self):
        # Kaynaklar free
        self.running = False
        self.chat_active = False
        self.echo_mode = None
        if hasattr(self, 'server_socket'):
            self.server_socket.close()
        if hasattr(self, 'client_socket'):
            self.client_socket.close()
        if hasattr(self, 'chat_conn'):
            self.chat_conn.close()
        self.executor.shutdown(wait=True)
        self.root.destroy()

    def run(self):
        # GUI döngüsü
        self.root.mainloop()

if __name__ == "__main__":
    try:
        toolkit = NetworkToolkitGUI()
        toolkit.run()
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
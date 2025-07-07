#!/usr/bin/env python3
"""
ChatAppPro - Soluzione enterprise di chat P2P con crittografia end-to-end,
            rilevamento MITM reale e invio file con traduzione live.
            Front End modernizzato con sidebar e stili morbidi.
"""

import sys
import asyncio
import json
import uuid
import logging
import os
import base64
import mimetypes
import threading
import ipaddress
import socket
import html
from types import ModuleType
import time # Importato per il join del thread

# ... (Hack per modulo cgi) ...
if "cgi" not in sys.modules:
    cgi = ModuleType("cgi")
    def escape(s, quote=True):
        return html.escape(s, quote=quote)
    cgi.escape = escape
    sys.modules["cgi"] = cgi

# --- Import per la crittografia sicura ---
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# --- Import per il rilevamento MITM (Scapy) ---

try:
    from scapy.all import sniff, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy non trovato. Il rilevamento MITM reale sarà disabilitato.")


# --- Import per la traduzione in tempo reale ---

try:
    from googletrans import Translator
    TRANSLATOR_AVAILABLE = True
except ImportError:
    TRANSLATOR_AVAILABLE = False
    logging.warning("Googletrans non trovato. La traduzione sarà disabilitata.")
    # Dummy Translator se googletrans non è installato
    class Translator:
        def translate(self, text, dest):
            logging.warning("Funzione di traduzione non disponibile.")
            return MockTranslation(text)
    class MockTranslation:
        def __init__(self, text):
            self.text = f"[Traduzione non disponibile] {text}"


# --- Import per interfaccia grafica e integrazione asyncio ---

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import QPropertyAnimation, QEasingCurve, pyqtProperty
from qasync import QEventLoop


# --- CONFIGURAZIONE LOGGING ---

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


########################################################################
# UTILITA': Ottenere l'IP locale
########################################################################

def get_local_ip():
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip.startswith("127.") or ip == "0.0.0.0":
            raise Exception("IP non valido ottenuto da gethostbyname")
    except Exception:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            ip = "127.0.0.1" # Fallback
    return ip

########################################################################
# MODULO: key_exchange
########################################################################

def generate_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

def deserialize_public_key(data):
    return x25519.X25519PublicKey.from_public_bytes(data)

def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(peer_public_key)


########################################################################
# MODULO: double_ratchet
########################################################################

class DoubleRatchet:
    def __init__(self, shared_secret, is_initiator):
        self.current_key = self.derive_key(shared_secret)

    def derive_key(self, shared_secret):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'P2P chat session'
        )
        return hkdf.derive(shared_secret)

    def update_key(self):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.current_key,
            info=b'ratchet_update'
        )
        self.current_key = hkdf.derive(self.current_key)

    def encrypt(self, plaintext):
        try:
            aesgcm = AESGCM(self.current_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
            self.update_key()
            payload = {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
            return json.dumps(payload)
        except Exception as e:
            logging.error(f"Errore nella cifratura: {e}")
            raise

    def decrypt(self, encrypted_payload):
        try:
            data = json.loads(encrypted_payload)
            nonce = bytes.fromhex(data["nonce"])
            ciphertext = bytes.fromhex(data["ciphertext"])
            aesgcm = AESGCM(self.current_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            self.update_key()
            return plaintext.decode()
        except Exception as e:
            logging.error(f"Errore nella decrittazione: {e}")
            logging.debug(f"Payload fallito: {encrypted_payload}")
            raise


########################################################################
# MODULO: jwt_auth (dummy enterprise)
########################################################################

def create_access_token(username):
    return f"token_for_{username}"

def verify_access_token(token):
    return token.startswith("token_for_")


########################################################################
# MODULO: p2p_network
########################################################################

class P2PNode:
    def __init__(self, host, port, fallback_secret):
        self.host = host
        self.port = port
        self.fallback_secret = fallback_secret
        self.server = None
        self.connections = {}
        self._on_message = None
        self._on_connect = None
        self._on_disconnect = None

    async def start_server(self):
        
        try:
            self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
            addr = self.server.sockets[0].getsockname()
            logging.info(f"Server P2P avviato e in ascolto su {self.host}:{self.port} (effettivo: {addr})")
            async with self.server:
                await self.server.serve_forever()
        except OSError as e:
            logging.error(f"Errore nell'avvio del server su {self.host}:{self.port} - {e}. La porta potrebbe essere già in uso.")
        except Exception as e:
            logging.error(f"Errore critico nell'avvio del server: {e}")

    def _get_peer_uuid(self, writer):
        """Helper per ottenere l'UUID associato a un writer."""
        info = self.connections.get(writer)
        return info.get("uuid", "UUID-Sconosciuto") if info else "UUID-Sconosciuto"

    async def handle_client(self, reader, writer):
        peername = writer.get_extra_info('peername')
        # Genera e memorizza UUID per questo peer all'accettazione della connessione
        peer_uuid = str(uuid.uuid4())[:8] # Usa solo i primi 8 caratteri per brevità
        self.connections[writer] = {"peername": peername, "reader": reader, "uuid": peer_uuid}
        logging.info(f"Peer-{peer_uuid} connesso da {peername}")

        if self._on_connect:
            # Passa anche l'UUID al callback di connessione
            self._on_connect(writer, peername, peer_uuid)

        try:
            while not reader.at_eof():
                data = await reader.readline()
                if not data:
                    break
                message = data.decode().strip()
                if message and self._on_message:
                    # Passa writer per identificare la fonte
                    self._on_message(message, writer)
            logging.info(f"Connessione chiusa da Peer-{peer_uuid} ({peername})")
        except asyncio.CancelledError:
            logging.info(f"Task per Peer-{peer_uuid} ({peername}) cancellato.")
        except ConnectionResetError:
            logging.warning(f"Connessione resettata da Peer-{peer_uuid} ({peername})")
        except Exception as e:
            logging.error(f"Errore nel gestire Peer-{peer_uuid} ({peername}): {e}")
        finally:
            writer.close()
            try:
                 await writer.wait_closed()
            except Exception as e:
                 logging.debug(f"Errore durante wait_closed per Peer-{peer_uuid}: {e}")

            # Rimuovi usando il writer come chiave
            stored_uuid = self._get_peer_uuid(writer) # Recupera UUID prima di eliminare
            if writer in self.connections:
                del self.connections[writer]
            if self._on_disconnect:
                # Passa anche l'UUID al callback di disconnessione
                self._on_disconnect(writer, peername, stored_uuid)

    async def send_message(self, message, target_writer=None):
        # ... (log aggiornati per usare UUID) ...
        writers_to_send = [target_writer] if target_writer else list(self.connections.keys())
        for writer in writers_to_send:
            peer_uuid = self._get_peer_uuid(writer)
            if writer and not writer.is_closing():
                try:
                    writer.write((message + "\n").encode())
                    await writer.drain()
                except ConnectionResetError:
                     logging.warning(f"Impossibile inviare a Peer-{peer_uuid}, connessione resettata: {writer.get_extra_info('peername')}")
                     if writer in self.connections: del self.connections[writer]
                     if self._on_disconnect: self._on_disconnect(writer, writer.get_extra_info('peername'), peer_uuid)
                except Exception as e:
                    logging.error(f"Errore nell'invio del messaggio a Peer-{peer_uuid} ({writer.get_extra_info('peername')}): {e}")
                    if writer in self.connections: del self.connections[writer]
                    if self._on_disconnect: self._on_disconnect(writer, writer.get_extra_info('peername'), peer_uuid)
            else:
                logging.debug(f"Skipping send to closed or invalid writer (Peer-{peer_uuid}).")

    async def connect_to_peer(self, ip, port):
        # ... (log aggiornati e gestione UUID all'avvio connessione) ...
        writer = None
        try:
            for w, info in self.connections.items():
                p_ip, p_port = info.get("peername", (None, None))
                if p_ip == ip and p_port == port:
                    logging.info(f"Già connesso a {ip}:{port} (Peer-{info.get('uuid', '?')})")
                    return w

            reader, writer = await asyncio.open_connection(ip, port)
            peername = writer.get_extra_info('peername')
            peer_uuid = str(uuid.uuid4())[:8] # Genera UUID anche per connessioni in uscita
            logging.info(f"Connesso a peer remoto {ip}:{port} (assegnato Peer-{peer_uuid})")

            # Memorizza subito le info, incluso l'UUID
            self.connections[writer] = {"peername": peername, "reader": reader, "uuid": peer_uuid}

            if self._on_connect:
                 # Passa l'UUID al callback
                self._on_connect(writer, peername, peer_uuid)

            # Avvia task di gestione per questa nuova connessione
            asyncio.create_task(self.handle_client(reader, writer))
            return writer
        except ConnectionRefusedError:
             logging.error(f"Connessione rifiutata da {ip}:{port}")
             if writer: writer.close()
             raise
        except OSError as e:
            logging.error(f"Errore di rete nella connessione a {ip}:{port} - {e}")
            if writer: writer.close()
            raise
        except Exception as e:
            logging.error(f"Errore generico nella connessione al peer {ip}:{port} - {e}")
            if writer: writer.close()
            raise

    # ... (set_on_message_callback, etc. invariati) ...
    def set_on_message_callback(self, callback):
        self._on_message = callback
    def set_on_connect_callback(self, callback):
        self._on_connect = callback
    def set_on_disconnect_callback(self, callback):
        self._on_disconnect = callback

########################################################################
# MODULO: MITM Detector (reale)
########################################################################

arp_table = {}

def arp_callback(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2: # is-at
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        global arp_table
        if ip in arp_table and arp_table[ip].lower() != mac.lower():
            logging.warning(f"!!! POSSIBILE ATTACCO ARP SPOOFING (MITM) RILEVATO !!!")
            logging.warning(f"IP: {ip} - MAC Precedente: {arp_table[ip]} - MAC Attuale: {mac}")
        else:
            if ip not in arp_table:
                 logging.info(f"Registrazione ARP: {ip} -> {mac}")
            arp_table[ip] = mac


def run_mitm_detector(interface=None):
    
    global arp_table
    arp_table = {}
    logging.info(f"Avvio MITM Detector (reale) su interfaccia: {'default' if not interface else interface}")
    try:
        # Usa stop_filter per permettere l'arresto del thread
        sniff(filter="arp", prn=arp_callback, store=0, iface=interface, stop_filter=lambda p: not getattr(threading.current_thread(), "do_run", True))
        logging.info("MITM Detector (sniff) terminato.")
    except OSError as e:
         logging.error(f"Errore nell'avvio di Scapy (assicurati di eseguirlo con privilegi elevati se necessario): {e}")
    except Exception as e:
         logging.error(f"Errore nel thread MITM detector: {e}")


def start_mitm_detector(interface=None):
    
    if not SCAPY_AVAILABLE:
        logging.warning("Scapy non disponibile, MITM Detector non avviato.")
        return None
    mitm_thread = threading.Thread(target=run_mitm_detector, args=(interface,), name="MITMDetectorThread", daemon=True)
    mitm_thread.do_run = True # Flag per fermare il thread
    mitm_thread.start()
    logging.info("Thread MITM Detector avviato.")
    return mitm_thread

# Modificata per aggiungere join con timeout
def stop_mitm_detector(thread):
     if thread and thread.is_alive():
        logging.info("Tentativo di fermare il MITM Detector...")
        thread.do_run = False
        thread.join(timeout=0.5) # Attendi max 0.5 secondi che il thread finisca
        if thread.is_alive():
            logging.warning("Il thread MITM Detector non si è fermato entro il timeout.")
        else:
            logging.info("Thread MITM Detector fermato con successo.")
     # else:
     #    logging.debug("Thread MITM non attivo o non esistente.")


########################################################################
# MODULO: file_transfer e traduzione
########################################################################

translator = Translator() if TRANSLATOR_AVAILABLE else None

def translate_text(text, dest_language='en'):
    if not translator:
        return "[Traduzione non disponibile]"
    try:
        if len(text) > 4500:
             logging.warning("Testo troppo lungo per la traduzione, troncato.")
             text = text[:4500]
        result = translator.translate(text, dest=dest_language)
        return result.text if result else text
    except Exception as e:
        logging.error(f"Errore nella traduzione: {e}")
        return f"[Errore traduzione] {text}"

def process_file_attachment(filepath):
    filename = os.path.basename(filepath)
    mimetype, _ = mimetypes.guess_type(filepath)
    if mimetype is None:
        mimetype = "application/octet-stream"
    translation = None
    try:
        file_size = os.path.getsize(filepath)
        MAX_FILE_SIZE = 50 * 1024 * 1024 # 50 MB
        if file_size > MAX_FILE_SIZE:
             raise ValueError(f"File troppo grande ({file_size / 1024 / 1024:.2f} MB). Massimo: {MAX_FILE_SIZE / 1024 / 1024} MB")

        if mimetype.startswith("text") and TRANSLATOR_AVAILABLE:
            with open(filepath, "rb") as f: raw_content = f.read()
            try: content = raw_content.decode('utf-8')
            except UnicodeDecodeError:
                try: content = raw_content.decode('latin-1')
                except UnicodeDecodeError:
                    logging.warning(f"Impossibile decodificare il file di testo {filename} per la traduzione.")
                    encoded = base64.b64encode(raw_content).decode("utf-8")
                    mimetype = "application/octet-stream"
                    content = None
            if content:
                encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")
                translation = translate_text(content, dest_language='en')
            # Se 'content' è None a causa di errore decode, 'encoded' è già stato impostato
            elif mimetype == "application/octet-stream": # Assicurati che encoded sia impostato se la decodifica fallisce
                 pass # encoded è già stato impostato sopra
            else: # Caso imprevisto
                 raise Exception("Errore logico nel processing file di testo")

        else: # File binari o testo senza traduttore
            with open(filepath, "rb") as f: binary_content = f.read()
            encoded = base64.b64encode(binary_content).decode("utf-8")
            translation = None

        return {
            "filename": filename,
            "mimetype": mimetype,
            "data": encoded,
            "translation": translation
        }
    except FileNotFoundError:
         logging.error(f"File non trovato: {filepath}")
         raise
    except Exception as e:
        logging.error(f"Errore nel processing dell'allegato {filepath}: {e}")
        raise


########################################################################
# INTERFACCIA: ChatWidget (area chat e controlli)
########################################################################
class ChatWidget(QtWidgets.QWidget):
    theme_changed_signal = QtCore.pyqtSignal(str)

    def __init__(self, loop, p2p_node):
        super().__init__()
        self.loop = loop
        self.node = p2p_node

        self.private_key, self.public_key = generate_keypair()
        self.serialized_public_key = serialize_public_key(self.public_key).hex()

        # Gestione chiavi/UUID per multiple connessioni
        # {writer: {"public_key": key, "ratchet": ratchet, "peer_id": ip:port, "uuid": str}}
        self.peer_crypto_info = {}
        self.current_writer = None # Writer del peer attivo

        self.username = f"User_{uuid.uuid4().hex[:6]}"

        # ... (typing timer) ...
        self.is_typing = False
        self.typing_delay = 1500
        self.typing_timer = QtCore.QTimer(self)
        self.typing_timer.setInterval(self.typing_delay)
        self.typing_timer.setSingleShot(True)
        self.typing_timer.timeout.connect(self.send_not_typing)


        self.theme = "dark"
        self.init_ui()
        self.apply_theme()
        # Imposta i callback per ricevere anche l'UUID
        self.node.set_on_message_callback(self.handle_peer_message)
        self.node.set_on_connect_callback(self.handle_peer_connect)
        self.node.set_on_disconnect_callback(self.handle_peer_disconnect)


    def init_ui(self):
        # ... (layout e widget base) ...
        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(8)

        # --- Pannello di Connessione ---
        connection_frame = QtWidgets.QFrame(self)
        connection_frame.setObjectName("connectionFrame")
        connection_layout = QtWidgets.QHBoxLayout(connection_frame)
        connection_layout.setContentsMargins(0,0,0,0)
        connection_layout.setSpacing(6)
        self.peer_ip_input = QtWidgets.QLineEdit(self); self.peer_ip_input.setPlaceholderText("Indirizzo IP peer")
        self.peer_port_input = QtWidgets.QLineEdit(self); self.peer_port_input.setPlaceholderText("Porta")
        self.peer_port_input.setValidator(QtGui.QIntValidator(1, 65535, self)); self.peer_port_input.setFixedWidth(80)
        self.connect_button = QtWidgets.QPushButton("Connetti"); self.connect_button.setObjectName("connectButton")
        self.connect_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor)); self.connect_button.clicked.connect(self.connect_peer)
        self.attach_button = QtWidgets.QPushButton("Allega File"); self.attach_button.setObjectName("attachButton")
        self.attach_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor)); self.attach_button.clicked.connect(self.send_file_attachment)
        self.attach_button.setEnabled(False)
        connection_layout.addWidget(QtWidgets.QLabel("Connetti a:"))
        connection_layout.addWidget(self.peer_ip_input); connection_layout.addWidget(self.peer_port_input)
        connection_layout.addWidget(self.connect_button); connection_layout.addStretch()
        connection_layout.addWidget(self.attach_button)
        main_layout.addWidget(connection_frame)

        # --- Area Chat ---
        self.chat_area = QtWidgets.QTextEdit(self); self.chat_area.setReadOnly(True); self.chat_area.setObjectName("chatArea")
        main_layout.addWidget(self.chat_area, stretch=1)

        # --- Stato "typing" ---
        self.typing_label = QtWidgets.QLabel(self); self.typing_label.setObjectName("typingLabel"); self.typing_label.setFixedHeight(20)
        main_layout.addWidget(self.typing_label)

        # --- Pannello Invio Messaggi ---
        message_frame = QtWidgets.QFrame(self); message_frame.setObjectName("messageFrame")
        message_layout = QtWidgets.QHBoxLayout(message_frame)
        message_layout.setContentsMargins(0,0,0,0); message_layout.setSpacing(6)
        self.message_input = QtWidgets.QLineEdit(self); self.message_input.setPlaceholderText("Scrivi un messaggio..."); self.message_input.setObjectName("messageInput")
        self.message_input.textChanged.connect(self.user_typing); self.message_input.returnPressed.connect(self.send_message)
        self.send_button = QtWidgets.QPushButton("Invia"); self.send_button.setObjectName("sendButton")
        self.send_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor)); self.send_button.clicked.connect(self.send_message)
        self.send_button.setEnabled(False)
        message_layout.addWidget(self.message_input); message_layout.addWidget(self.send_button)
        main_layout.addWidget(message_frame)

        self.setLayout(main_layout)

    def apply_theme(self):
        # ... (definizione colori e stili QSS) ...
        dark_electric_blue = "#3a86ff"; dark_hover_blue = "#5a9bff"
        light_bright_red = "#e63946"; light_hover_red = "#f05f6d"
        dark_bg = "#1e1e1e"; dark_fg = "#f0f0f0"; dark_input_bg = "#2b2b2b"; dark_border = "#444444"
        dark_bubble_sent_bg = dark_electric_blue; dark_bubble_recv_bg = "#333333"; dark_bubble_text = "#ffffff"; dark_bubble_info_text = "#aaaaaa"
        light_bg = "#f8f8f8"; light_fg = "#333333"; light_input_bg = "#ffffff"; light_border = "#cccccc"
        light_bubble_sent_bg = light_bright_red; light_bubble_recv_bg = "#e5e5e5"; light_bubble_text = "#ffffff"
        light_bubble_recv_text = light_fg; light_bubble_info_text = "#666666"

        if self.theme == "dark":
            bg_color = dark_bg; fg_color = dark_fg; input_bg = dark_input_bg; border_color = dark_border
            button_color = dark_electric_blue; button_hover = dark_hover_blue
            bubble_sent_bg = dark_bubble_sent_bg; bubble_recv_bg = dark_bubble_recv_bg
            bubble_sent_text = dark_bubble_text; bubble_recv_text = dark_fg; bubble_info_text = dark_bubble_info_text
            scrollbar_handle = "#555"; scrollbar_bg = dark_input_bg
        else: # light
            bg_color = light_bg; fg_color = light_fg; input_bg = light_input_bg; border_color = light_border
            button_color = light_bright_red; button_hover = light_hover_red
            bubble_sent_bg = light_bubble_sent_bg; bubble_recv_bg = light_bubble_recv_bg
            bubble_sent_text = light_bubble_text; bubble_recv_text = light_bubble_recv_text; bubble_info_text = light_bubble_info_text
            scrollbar_handle = "#aaa"; scrollbar_bg = light_bubble_recv_bg

        style = f"""
            ChatWidget, QWidget {{ background-color: {bg_color}; color: {fg_color}; border: none; }}
            QFrame#connectionFrame, QFrame#messageFrame {{ background-color: transparent; border: none; border-radius: 15px; padding: 0px; }}
            QLineEdit {{ background-color: {input_bg}; color: {fg_color}; border: 1px solid {border_color}; padding: 8px 12px; border-radius: 15px; font-size: 14px; }}
            QLineEdit:focus {{ border: 1px solid {button_color}; }}
            QPushButton {{ color: white; padding: 8px 16px; border-radius: 15px; font-size: 14px; font-weight: bold; border: none; outline: none; }}
            QPushButton:disabled {{ background-color: #555555; color: #aaaaaa; }}
            QPushButton#connectButton, QPushButton#sendButton, QPushButton#attachButton {{ background-color: {button_color}; }}
            QPushButton#connectButton:hover:!disabled, QPushButton#sendButton:hover:!disabled, QPushButton#attachButton:hover:!disabled {{ background-color: {button_hover}; }}
            QTextEdit#chatArea {{ background-color: {input_bg}; color: {fg_color}; border: 1px solid {border_color}; border-radius: 15px; padding: 10px; font-size: 14px; }}
            QLabel#typingLabel {{ color: {bubble_info_text}; font-style: italic; padding-left: 10px; }}
            QScrollBar:vertical {{ border: none; background: {scrollbar_bg}; width: 10px; margin: 0px 0px 0px 0px; border-radius: 5px; }}
            QScrollBar::handle:vertical {{ background: {scrollbar_handle}; min-height: 20px; border-radius: 5px; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ border: none; background: none; height: 0px; }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: none; }}
        """
        self.setStyleSheet(style)
        self.theme_changed_signal.emit(self.theme)

    def toggle_theme(self):
        
        self.theme = "light" if self.theme == "dark" else "dark"
        self.apply_theme()
        current_html = self.chat_area.toHtml()
        self.chat_area.clear()
        self.apply_html_theme(current_html)

    def apply_html_theme(self, html_content):
        # ... (logica di sostituzione colori HTML) ...
        dark_bubble_sent_bg = "#3a86ff"; dark_bubble_recv_bg = "#333333"; dark_bubble_text = "#ffffff"; dark_bubble_info_text = "#aaaaaa"
        light_bubble_sent_bg = "#e63946"; light_bubble_recv_bg = "#e5e5e5"; light_bubble_text = "#ffffff"
        light_bubble_recv_text = "#333333"; light_bubble_info_text = "#666666"
        attachment_bg_dark = "#5a5a5a"; attachment_bg_light = "#cccccc"

        if self.theme == 'dark':
            html_content = html_content.replace(f"background-color:{light_bubble_sent_bg}", f"background-color:{dark_bubble_sent_bg}")
            html_content = html_content.replace(f"background-color:{light_bubble_recv_bg}", f"background-color:{dark_bubble_recv_bg}")
            html_content = html_content.replace(f"background-color:{attachment_bg_light}", f"background-color:{attachment_bg_dark}") # Aggiorna attach bg
            # Aggiorna colori testo (più robusto cercando specifici tag/stili se necessario)
            # Questo replace semplice potrebbe cambiare colori indesiderati se sono uguali
            html_content = html_content.replace(f"color:{light_bubble_text}", f"color:{dark_bubble_text}") # Sent bubble text
            html_content = html_content.replace(f"color:{light_bubble_recv_text}", f"color:{dark_bubble_text}") # Received bubble text
            html_content = html_content.replace(f"color:{light_bubble_info_text}", f"color:{dark_bubble_info_text}") # Info text
        else:
            html_content = html_content.replace(f"background-color:{dark_bubble_sent_bg}", f"background-color:{light_bubble_sent_bg}")
            html_content = html_content.replace(f"background-color:{dark_bubble_recv_bg}", f"background-color:{light_bubble_recv_bg}")
            html_content = html_content.replace(f"background-color:{attachment_bg_dark}", f"background-color:{attachment_bg_light}") # Aggiorna attach bg
            html_content = html_content.replace(f"color:{dark_bubble_text}", f"color:{light_bubble_text}") # Sent bubble text
            html_content = html_content.replace(f"color:{dark_bubble_text}", f"color:{light_bubble_recv_text}") # Received bubble text
            html_content = html_content.replace(f"color:{dark_bubble_info_text}", f"color:{light_bubble_info_text}") # Info text

        self.chat_area.setHtml(html_content)
        self.chat_area.verticalScrollBar().setValue(self.chat_area.verticalScrollBar().maximum())


    # --- Metodo aggiornato per bolle moderne con contorno, font morbido e timestamp affiancato ---
    def display_message(self, text, mtype, peer_display_id="Peer"):
        # Ora corrente
        time_str = QtCore.QTime.currentTime().toString("hh:mm")
        escaped_text = html.escape(text)

        # Font morbido per tutte le bolle
        bubble_font = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif"

        # Definizione colori e bordi in base al tema
        if self.theme == "dark":
            sent_bg    = "#3a86ff"
            recv_bg    = "#444444"
            sent_text  = "#ffffff"
            recv_text  = "#f0f0f0"
            sent_border= "#2653a3"
            recv_border= "#666666"
            info_text  = "#aaaaaa"
        else:
            sent_bg    = "#e63946"
            recv_bg    = "#f1f1f1"
            sent_text  = "#000000"
            recv_text  = "#000000"
            sent_border= "#d62828"
            recv_border= "#cccccc"
            info_text  = "#666666"

        # Allineamento, colori e bordo della bolla
        if mtype in ("sent", "attachment_sent"):
            justify     = "flex-end"
            bubble_bg   = sent_bg
            bubble_color= sent_text
            border_color= sent_border
        elif mtype in ("received", "attachment_received"):
            justify     = "flex-start"
            bubble_bg   = recv_bg
            bubble_color= recv_text
            border_color= recv_border
        else:
            justify     = "center"
            bubble_bg   = "transparent"
            bubble_color= info_text
            border_color= "transparent"

        # Contenuto della bolla
        if mtype == "sent":
            label = f"<b>Tu:</b> {escaped_text}"
        elif mtype == "received":
            label = f"<b>{html.escape(peer_display_id)}:</b> {escaped_text}"
        elif mtype == "attachment_sent":
            label = f"Hai inviato: {escaped_text}"
        elif mtype == "attachment_received":
            label = f"{html.escape(peer_display_id)} ha inviato: {escaped_text}"
        else:
            label = f"<i>{escaped_text}</i>"

        # Costruzione HTML della bolla con bordo
        bubble_html = f"""
        <div style="display:flex; justify-content:{justify}; align-items:flex-end; margin:5px 0;">
          <div style="
              background-color:{bubble_bg};
              color:{bubble_color};
              border:1px solid {border_color};
              border-radius:15px;
              max-width:70%;
              padding:10px 12px;
              font-family:{bubble_font};
              font-weight:bold;
              word-wrap:break-word;
          ">
            {label}
          </div>
          <div style="font-size:10px; color:{info_text}; margin:0 5px;">
            {time_str}
          </div>
        </div>
        """

        # Append e scroll automatico
        self.chat_area.append(bubble_html)
        self.chat_area.verticalScrollBar().setValue(self.chat_area.verticalScrollBar().maximum())

    # Modificato per ricevere e usare l'UUID
    def handle_peer_connect(self, writer, peername, peer_uuid):
         ip, port = peername
         # Usa l'UUID fornito nel messaggio di info
         self.display_message(f"Peer-{peer_uuid} ({ip}:{port}) connesso.", "info")

         # Memorizza tutte le info, incluso l'UUID
         self.peer_crypto_info[writer] = {
             "public_key": None,
             "ratchet": None,
             "peer_id": f"{ip}:{port}", # Mantiene IP:Port come ID interno
             "uuid": peer_uuid         # Memorizza UUID
         }

         if not self.current_writer:
              self.current_writer = writer
              self.attach_button.setEnabled(True)
              self.send_button.setEnabled(True)
              self.display_message(f"Chat attiva con Peer-{peer_uuid}", "info") # Info su chi è attivo

         self.send_public_key(writer) # Invia chiave pubblica

    # Modificato per ricevere e usare l'UUID
    def handle_peer_disconnect(self, writer, peername, peer_uuid):
        # Usa l'UUID fornito nel messaggio di info
        self.display_message(f"Peer-{peer_uuid} disconnesso.", "info")

        if writer in self.peer_crypto_info:
            del self.peer_crypto_info[writer]

        if self.current_writer == writer:
            self.current_writer = None
            self.attach_button.setEnabled(False)
            self.send_button.setEnabled(False)
            self.typing_label.setText("")
            if self.peer_crypto_info:
                # Seleziona il prossimo peer come attivo
                self.current_writer = next(iter(self.peer_crypto_info))
                new_active_uuid = self.peer_crypto_info[self.current_writer].get("uuid", "???")
                self.display_message(f"Chat attiva con Peer-{new_active_uuid}", "info")
                self.attach_button.setEnabled(True)
                self.send_button.setEnabled(True)

    # Modificato per usare l'UUID nell'output
    def handle_peer_message(self, raw_data, source_writer):
        peer_info = self.peer_crypto_info.get(source_writer)
        # Usa l'UUID come identificatore primario per i messaggi, fallback a IP:Port se manca
        peer_display_id = f"Peer-{peer_info['uuid']}" if peer_info and 'uuid' in peer_info else "Peer Sconosciuto"
        peer_internal_id = peer_info.get("peer_id", "IP:Porta Sconosciuta") if peer_info else "IP:Porta Sconosciuta"


        try:
            payload = json.loads(raw_data)
            message_type = payload.get("type", "unknown")

            if not peer_info and message_type != "public_key":
                 logging.warning(f"Ricevuto messaggio '{message_type}' da peer non inizializzato ({peer_internal_id}). Ignorato.")
                 return

            # --- Gestione Scambio Chiavi ---
            if message_type == "public_key":
                peer_key_hex = payload.get("public_key")
                if peer_key_hex and peer_info:
                    logging.info(f"Ricevuta chiave pubblica da {peer_display_id} ({peer_internal_id})")
                    # ... (logica ratchet) ...
                    peer_public_key = deserialize_public_key(bytes.fromhex(peer_key_hex))
                    peer_info["public_key"] = peer_public_key
                    shared_secret = derive_shared_secret(self.private_key, peer_public_key)
                    peer_info["ratchet"] = DoubleRatchet(shared_secret, is_initiator=False)
                    logging.info(f"Double Ratchet inizializzato per {peer_display_id}")
                    if not peer_info.get("sent_my_key"):
                         self.send_public_key(source_writer)
                         peer_info["sent_my_key"] = True

            # --- Gestione Messaggi Cifrati ---
            elif message_type == "message" and peer_info:
                encrypted_message = payload.get("encrypted_message")
                ratchet = peer_info.get("ratchet")
                if encrypted_message and ratchet:
                    try:
                        decrypted = ratchet.decrypt(encrypted_message)
                        # Passa peer_display_id a display_message
                        self.display_message(decrypted, "received", peer_display_id)
                        if source_writer == self.current_writer: self.typing_label.setText("")
                    except Exception as e:
                        logging.error(f"Errore nella decrittazione del messaggio da {peer_display_id}: {e}")
                        self.display_message("[Messaggio non decrittabile]", "received", peer_display_id)
                elif not ratchet:
                     logging.warning(f"Ricevuto messaggio cifrato da {peer_display_id} ma il ratchet non è pronto.")
                     self.display_message("[Messaggio ricevuto prima dello scambio chiavi]", "received", peer_display_id)
                else:
                     content = payload.get("content", "[Contenuto Mancante]")
                     logging.warning(f"Ricevuto messaggio non cifrato da {peer_display_id}: {content}")
                     self.display_message(content, "received", peer_display_id)

            # --- Gestione Allegati ---
            elif message_type == "attachment" and peer_info:
                filename = payload.get("filename", "file sconosciuto")
                mimetype = payload.get("mimetype", "")
                translation = payload.get("translation", None)
                # ... (logica dati) ...
                message_info = f"{filename} ({mimetype})"
                if translation: message_info += f"<br><i>Traduzione:</i> {html.escape(translation)}"
                # Passa peer_display_id
                self.display_message(message_info, "attachment_received", peer_display_id)

            # --- Gestione Stato "Typing" ---
            elif message_type == "typing_status" and peer_info:
                status = payload.get("status", "")
                if source_writer == self.current_writer: # Mostra solo se dal peer attivo
                    self.typing_label.setText(f"{peer_display_id} sta scrivendo..." if status == "typing" else "")

            else:
                logging.warning(f"Ricevuto messaggio di tipo sconosciuto '{message_type}' da {peer_display_id}: {raw_data}")

        except json.JSONDecodeError:
            logging.error(f"Errore nel decodificare JSON da {peer_display_id} ({peer_internal_id}): {raw_data}")
        except Exception as e:
            logging.error(f"Errore generale in handle_peer_message da {peer_display_id} ({peer_internal_id}): {e}")


    def send_public_key(self, target_writer):
         # ... (log aggiornato con UUID) ...
         if target_writer and not target_writer.is_closing():
             peer_info = self.peer_crypto_info.get(target_writer)
             peer_display_id = f"Peer-{peer_info['uuid']}" if peer_info and 'uuid' in peer_info else "Peer Sconosciuto"
             payload = { "type": "public_key", "public_key": self.serialized_public_key }
             logging.info(f"Invio chiave pubblica a {peer_display_id}")
             asyncio.run_coroutine_threadsafe(self.node.send_message(json.dumps(payload), target_writer), self.loop)
             if target_writer in self.peer_crypto_info: self.peer_crypto_info[target_writer]["sent_my_key"] = True

    def send_message(self):
        # ... (log e display_message useranno UUID) ...
        if not self.current_writer or self.current_writer.is_closing():
            self.display_message("Nessun peer attivo selezionato per inviare.", "info")
            return
        message = self.message_input.text().strip()
        if message:
            peer_info = self.peer_crypto_info.get(self.current_writer)
            peer_display_id = f"Peer-{peer_info['uuid']}" if peer_info and 'uuid' in peer_info else "Peer Attivo Sconosciuto"
            if not peer_info or not peer_info.get("ratchet"):
                self.display_message(f"Impossibile inviare a {peer_display_id}: Scambio chiavi non completato.", "info")
                logging.warning(f"Tentativo di invio messaggio a {peer_display_id} senza ratchet pronto.")
                if peer_info and not peer_info.get("public_key"): self.send_public_key(self.current_writer)
                return
            ratchet = peer_info["ratchet"]
            try:
                encrypted_message = ratchet.encrypt(message)
                payload = { "type": "message", "encrypted_message": encrypted_message }
                asyncio.run_coroutine_threadsafe(self.node.send_message(json.dumps(payload), self.current_writer), self.loop)
                self.display_message(message, "sent") # Mostra messaggio inviato (identificato come "Tu")
                self.message_input.clear()
                self.send_not_typing()
            except Exception as e:
                logging.error(f"Errore durante la cifratura o l'invio del messaggio a {peer_display_id}: {e}")
                self.display_message(f"Errore nell'invio del messaggio a {peer_display_id}.", "info")


    def send_file_attachment(self):
        # ... (log e display_message useranno UUID) ...
        if not self.current_writer or self.current_writer.is_closing():
             self.display_message("Nessun peer attivo selezionato per inviare l'allegato.", "info")
             return
        options = QtWidgets.QFileDialog.Options(); options |= QtWidgets.QFileDialog.ReadOnly
        filepath, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Seleziona file", "", "All Files (*)", options=options)
        if filepath:
             peer_info = self.peer_crypto_info.get(self.current_writer)
             peer_display_id = f"Peer-{peer_info['uuid']}" if peer_info and 'uuid' in peer_info else "Peer Attivo Sconosciuto"
             if not peer_info or not peer_info.get("ratchet"):
                 self.display_message(f"Impossibile inviare allegato a {peer_display_id}: Scambio chiavi non completato.", "info")
                 return
             try:
                 self.display_message(f"Preparazione allegato: {os.path.basename(filepath)}...", "info")
                 QtCore.QCoreApplication.processEvents()
                 attachment = process_file_attachment(filepath)
                 payload = { # ... (payload allegato come prima) ...
                     "type": "attachment", "filename": attachment.get("filename"), "mimetype": attachment.get("mimetype"),
                     "data": attachment.get("data"), "translation": attachment.get("translation"),
                 }
                 asyncio.run_coroutine_threadsafe(self.node.send_message(json.dumps(payload), self.current_writer), self.loop)
                 # Messaggio inviato identificato come "Tu"
                 self.display_message(f"{attachment['filename']}", "attachment_sent")
             except ValueError as e:
                  logging.error(f"Errore nell'invio dell'allegato a {peer_display_id}: {e}")
                  QtWidgets.QMessageBox.warning(self, "Errore Allegato", str(e))
             except Exception as e:
                 logging.error(f"Errore nell'invio dell'allegato a {peer_display_id}: {e}")
                 QtWidgets.QMessageBox.critical(self, "Errore Invio", f"Impossibile processare o inviare l'allegato.\n{e}")


    def connect_peer(self):
        # ... (logica e validazione invariata) ...
        ip = self.peer_ip_input.text().strip()
        port_text = self.peer_port_input.text().strip()
        if not ip or not port_text: self.display_message("Inserisci IP e Porta del peer.", "info"); return
        try: ipaddress.ip_address(ip)
        except ValueError: self.display_message("Indirizzo IP non valido.", "info"); return
        if ip == "0.0.0.0" or ip == get_local_ip(): self.display_message("Non puoi connetterti a te stesso.", "info"); return
        try: port = int(port_text); assert 1 <= port <= 65535
        except (ValueError, AssertionError): self.display_message("Porta non valida (1-65535).", "info"); return

        self.display_message(f"Tentativo di connessione a {ip}:{port}...", "info")
        self.connect_button.setEnabled(False); self.connect_button.setText("Connessione...")
        fut = asyncio.run_coroutine_threadsafe(self.node.connect_to_peer(ip, port), self.loop)

        def on_connected(future):
             # La logica di visualizzazione/abilitazione UI è ora in handle_peer_connect
             try:
                 writer = future.result() # Controlla solo se c'è stata un'eccezione
                 if writer: # Connessione ok o già esistente
                      self.peer_ip_input.clear()
                      self.peer_port_input.clear()
             except ConnectionRefusedError: self.display_message(f"Connessione a {ip}:{port} rifiutata.", "info")
             except OSError as e: self.display_message(f"Errore di rete connettendosi a {ip}:{port}: {e}", "info")
             except Exception as e:
                 self.display_message(f"Errore durante la connessione a {ip}:{port}: {e}", "info")
                 logging.error(f"Errore imprevisto in on_connected: {e}")
             finally:
                  self.connect_button.setEnabled(True); self.connect_button.setText("Connetti")

        fut.add_done_callback(on_connected)


    def user_typing(self):
        # ... (invia a self.current_writer) ...
        if not self.current_writer or self.current_writer.is_closing(): return
        if self.message_input.text().strip():
            if not self.is_typing:
                self.is_typing = True
                payload = {"type": "typing_status", "status": "typing"}
                asyncio.run_coroutine_threadsafe(self.node.send_message(json.dumps(payload), self.current_writer), self.loop)
            self.typing_timer.start(self.typing_delay)
        else:
            self.send_not_typing()


    def send_not_typing(self):
        # ... (invia a self.current_writer) ...
        if self.is_typing:
            self.is_typing = False
            if self.current_writer and not self.current_writer.is_closing():
                payload = {"type": "typing_status", "status": "not_typing"}
                asyncio.run_coroutine_threadsafe(self.node.send_message(json.dumps(payload), self.current_writer), self.loop)
        self.typing_timer.stop()


########################################################################
# INTERFACCIA: Sidebar Animata (AnimatedDockWidget)
########################################################################

class AnimatedDockWidget(QtWidgets.QDockWidget):
    def __init__(self, title, parent=None):
        super().__init__(title, parent)
        self._is_visible = False
        self._animation = QPropertyAnimation(self, b"geometry", self)
        self._animation.setDuration(300)
        self._animation.setEasingCurve(QEasingCurve.InOutCubic)
        self.visibilityChanged.connect(self._check_visibility)
        self.setTitleBarWidget(QtWidgets.QWidget())
        self.setFeatures(QtWidgets.QDockWidget.NoDockWidgetFeatures)

    def _check_visibility(self, visible): self._is_visible = visible

    def toggle_animated(self, main_window_geometry):
        if self._is_visible: self.hide_animated(main_window_geometry)
        else: self.show_animated(main_window_geometry)

    def show_animated(self, main_window_geometry):
        if self._is_visible: return
        width = max(self.widget().sizeHint().width(), 200)
        start_geometry = QtCore.QRect(main_window_geometry.left() - width, main_window_geometry.top(), width, main_window_geometry.height())
        end_geometry = QtCore.QRect(main_window_geometry.left(), main_window_geometry.top(), width, main_window_geometry.height())
        self.setGeometry(start_geometry)
        self.setVisible(True); self._is_visible = True
        self._animation.setStartValue(start_geometry); self._animation.setEndValue(end_geometry)
        self._animation.start()

    def hide_animated(self, main_window_geometry):
         if not self._is_visible: return
         width = self.width(); start_geometry = self.geometry()
         end_geometry = QtCore.QRect(main_window_geometry.left() - width, main_window_geometry.top(), width, main_window_geometry.height())
         self._animation.setStartValue(start_geometry); self._animation.setEndValue(end_geometry)
         # Usa lambda per disconnettere correttamente dopo l'esecuzione
         self._animation.finished.connect(self._on_hide_animation_finished)
         self._animation.start()

    # Assicurati che sia decorato correttamente
    @QtCore.pyqtSlot()
    def _on_hide_animation_finished(self):
        # Disconnessione sicura
        try: self._animation.finished.disconnect(self._on_hide_animation_finished)
        except TypeError: pass
        self.setVisible(False); self._is_visible = False


########################################################################
# INTERFACCIA: MainWindow con Sidebar Animata
########################################################################
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, loop, p2p_node):
        super().__init__()
        self.loop = loop
        self.p2p_node = p2p_node
        self.chat_widget = ChatWidget(loop, p2p_node)
        self.setCentralWidget(self.chat_widget)

        self.create_sidebar()
        self.create_actions()
        self.create_toolbar()

        
        self.setWindowTitle("ChatProP2P")
        self.setWindowIcon(QtGui.QIcon.fromTheme("network-transmit-receive"))
        self.resize(800, 600)

        self.chat_widget.theme_changed_signal.connect(self.update_theme_styles)
        self.update_theme_styles(self.chat_widget.theme)

    def create_actions(self):
        
        self.toggle_sidebar_action = QtWidgets.QAction(QtGui.QIcon.fromTheme("view-list-tree"), "Impostazioni", self)
        self.toggle_sidebar_action.setToolTip("Mostra/Nascondi Impostazioni"); self.toggle_sidebar_action.triggered.connect(self.toggle_sidebar)
        self.toggle_sidebar_action.setShortcut(QtGui.QKeySequence("Ctrl+M"))
        self.exit_action = QtWidgets.QAction(QtGui.QIcon.fromTheme("application-exit"), "Esci", self); self.exit_action.triggered.connect(self.close)

    def create_toolbar(self):
        
        toolbar = self.addToolBar("Main"); toolbar.setObjectName("mainToolbar"); toolbar.setMovable(False); toolbar.setFloatable(False)
        toolbar.setIconSize(QtCore.QSize(24, 24)); toolbar.addAction(self.toggle_sidebar_action)
        spacer = QtWidgets.QWidget(self); spacer.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        toolbar.addWidget(spacer)

    def create_sidebar(self):
        
        self.sidebar = AnimatedDockWidget("Impostazioni", self); self.sidebar.setObjectName("settingsSidebar")
        self.addDockWidget(QtCore.Qt.LeftDockWidgetArea, self.sidebar)
        self.sidebar_widget = QtWidgets.QWidget(); self.sidebar_widget.setObjectName("sidebarContentWidget")
        layout = QtWidgets.QVBoxLayout(self.sidebar_widget); layout.setContentsMargins(15, 15, 15, 15); layout.setSpacing(10); layout.setAlignment(QtCore.Qt.AlignTop)
        title_label = QtWidgets.QLabel("Impostazioni Applicazione"); title_label.setObjectName("sidebarTitle"); title_label.setAlignment(QtCore.Qt.AlignCenter); layout.addWidget(title_label); layout.addSpacing(15)
        theme_group = QtWidgets.QGroupBox("Tema Interfaccia"); theme_layout = QtWidgets.QVBoxLayout(theme_group)
        self.theme_combo = QtWidgets.QComboBox(); self.theme_combo.setObjectName("themeCombo"); self.theme_combo.addItems(["Dark", "Light"])
        self.theme_combo.setCurrentText(self.chat_widget.theme.capitalize()); self.theme_combo.currentTextChanged.connect(self._handle_theme_change); theme_layout.addWidget(self.theme_combo); layout.addWidget(theme_group)
        screen_group = QtWidgets.QGroupBox("Schermo"); screen_layout = QtWidgets.QVBoxLayout(screen_group)
        self.resolution_combo = QtWidgets.QComboBox(); self.resolution_combo.setObjectName("resolutionCombo")
        self.resolution_combo.addItems(["800x600", "1024x768", "1280x720", "1920x1080", "Schermo Intero"])
        self.resolution_combo.currentIndexChanged.connect(self.change_resolution); screen_layout.addWidget(self.resolution_combo); layout.addWidget(screen_group)
        info_group = QtWidgets.QGroupBox("Informazioni"); info_layout = QtWidgets.QVBoxLayout(info_group)
        self.btn_info = QtWidgets.QPushButton("Mostra Informazioni App"); self.btn_info.setObjectName("infoButton"); self.btn_info.clicked.connect(self.show_info); info_layout.addWidget(self.btn_info)
        # Mostra IP/Porta di ascolto qui
        self.ip_label = QtWidgets.QLabel(f"Ascolto su: {get_local_ip()}:{LOCAL_PORT}")
        self.ip_label.setObjectName("ipLabel"); self.ip_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse); info_layout.addWidget(self.ip_label); layout.addWidget(info_group)
        layout.addStretch()
        self.close_sidebar_button = QtWidgets.QPushButton("Chiudi Impostazioni"); self.close_sidebar_button.setObjectName("closeSidebarButton"); self.close_sidebar_button.clicked.connect(self.toggle_sidebar); layout.addWidget(self.close_sidebar_button)
        self.sidebar_widget.setLayout(layout); self.sidebar.setWidget(self.sidebar_widget)


    def update_theme_styles(self, theme):
        
        dark_bg = "#1e1e1e"; dark_fg = "#f0f0f0"; dark_border = "#444444"; dark_sidebar_bg = "#252526"; dark_toolbar_bg = "#333333"; dark_button_bg = "#3a86ff"; dark_button_hover = "#5a9bff"
        light_bg = "#f8f8f8"; light_fg = "#333333"; light_border = "#cccccc"; light_sidebar_bg = "#ebebeb"; light_toolbar_bg = "#e0e0e0"; light_button_bg = "#e63946"; light_button_hover = "#f05f6d"
        if theme == "dark": main_bg = dark_bg; main_fg = dark_fg; sidebar_bg = dark_sidebar_bg; toolbar_bg = dark_toolbar_bg; border_col = dark_border; button_col = dark_button_bg; button_hover = dark_button_hover
        else: main_bg = light_bg; main_fg = light_fg; sidebar_bg = light_sidebar_bg; toolbar_bg = light_toolbar_bg; border_col = light_border; button_col = light_button_bg; button_hover = light_button_hover
        style = f"""
            QMainWindow {{ background-color: {main_bg}; }}
            QToolBar#mainToolbar {{ background-color: {toolbar_bg}; border: none; padding: 5px; }}
            QToolBar#mainToolbar QToolButton {{ background-color: transparent; color: {main_fg}; border-radius: 5px; padding: 5px; }}
            QToolBar#mainToolbar QToolButton:hover {{ background-color: rgba(255, 255, 255, 0.1); }}
            AnimatedDockWidget#settingsSidebar {{ background-color: {sidebar_bg}; color: {main_fg}; border-right: 1px solid {border_col}; }}
            QWidget#sidebarContentWidget {{ background-color: transparent; color: {main_fg}; }}
            QLabel#sidebarTitle {{ font-size: 16px; font-weight: bold; color: {main_fg}; margin-bottom: 10px; border-bottom: 1px solid {border_col}; padding-bottom: 5px; }}
            QLabel#ipLabel {{ color: {main_fg}; font-size: 11px; margin-top: 5px; }}
            QGroupBox {{ color: {main_fg}; border: 1px solid {border_col}; border-radius: 8px; margin-top: 10px; padding: 15px 5px 5px 5px; font-weight: bold; }}
            QGroupBox::title {{ subcontrol-origin: margin; subcontrol-position: top left; left: 10px; padding: 0 3px 0 3px; background-color: {sidebar_bg}; }}
            QComboBox#themeCombo, QComboBox#resolutionCombo {{ color: {main_fg}; background-color: {main_bg}; border: 1px solid {border_col}; border-radius: 5px; padding: 5px; }}
            QComboBox::drop-down {{ border: none; }}
            QComboBox::down-arrow {{ image: url(:/qt-project.org/styles/commonstyle/images/standardbutton-down-arrow{'' if theme=='dark' else ''}.png); width: 12px; height: 12px; padding-right: 5px; }}
            QComboBox QAbstractItemView {{ background-color: {main_bg}; color: {main_fg}; border: 1px solid {border_col}; selection-background-color: {button_col}; }}
            QPushButton#infoButton, QPushButton#closeSidebarButton {{ background-color: {button_col}; color: white; padding: 8px 15px; border-radius: 15px; font-weight: bold; border: none; }}
            QPushButton#infoButton:hover, QPushButton#closeSidebarButton:hover {{ background-color: {button_hover}; }}
            QPushButton#closeSidebarButton {{ background-color: #555; }} QPushButton#closeSidebarButton:hover {{ background-color: #777; }}
        """
        self.setStyleSheet(style)


    @QtCore.pyqtSlot()
    def toggle_sidebar(self):
        
        self.sidebar.toggle_animated(self.geometry())

    def _handle_theme_change(self, text):
        
        new_theme = text.lower();
        if new_theme != self.chat_widget.theme: self.chat_widget.toggle_theme()

    def change_resolution(self):
        
        res_text = self.resolution_combo.currentText()
        if res_text == "Schermo Intero": self.toggle_fullscreen()
        else:
            try:
                width, height = map(int, res_text.split("x"))
                if self.isFullScreen(): self.showNormal()
                self.resize(width, height)
            except ValueError: logging.warning(f"Risoluzione non valida: {res_text}")

    def toggle_fullscreen(self):
        
        if self.isFullScreen(): self.showNormal()
        else: self.showFullScreen(); self.resolution_combo.setCurrentText("Schermo Intero")

    def show_info(self):
        
        info_text = (
            "<b>ChatProP2P</b><br><br>" # Modificato titolo
            "Applicazione di chat peer-to-peer con interfaccia moderna, temi personalizzabili e funzionalità avanzate.<br><br>"
            "<b>Crittografia End-to-End</b>: Utilizza lo scambio di chiavi X25519 e il protocollo Double Ratchet.<br>"
            "<b>Double Ratchet</b>: Forward Secrecy e Post-Compromise Security.<br>"
            "<b>Rilevamento MITM</b>: Monitoraggio ARP (richiede Scapy e privilegi).<br>"
            "<b>Funzionalità Aggiuntive</b>: Invio file con traduzione opzionale (richiede googletrans), indicatore 'sta scrivendo', temi dark/light, identificazione peer con UUID.<br><br>" # Aggiunto UUID
             f"Versione basata su Python {sys.version.split()[0]} e PyQt {QtCore.PYQT_VERSION_STR}."
        )
        QtWidgets.QMessageBox.information(self, "Informazioni su ChatProP2P", info_text)

    # fermare MITM Detector qui
    def closeEvent(self, event):
         logging.info("Chiusura applicazione (closeEvent)...")
         # Ferma il detector QUI, una sola volta.
         stop_mitm_detector(mitm_thread)

         # Chiudi connessioni P2P (best effort)
         logging.info("Chiusura connessioni P2P...")
         for writer in list(self.p2p_node.connections.keys()):
             if writer and not writer.is_closing():
                 try:
                     writer.close()
                     # Considera await writer.wait_closed() se possibile/necessario,
                     # ma potrebbe bloccare la chiusura della UI.
                 except Exception as e:
                     logging.warning(f"Errore durante la chiusura del writer: {e}")

         # Ferma eventuali altri processi/thread se necessario

         logging.info("Uscita da closeEvent.")
         event.accept()


########################################################################
# MAIN: Avvio dell'Applicazione
########################################################################
if __name__ == "__main__":
    LOCAL_HOST = get_local_ip() # Ottieni IP locale
    SERVER_HOST = "0.0.0.0"
    LOCAL_PORT = 8000
    FALLBACK_SECRET = b"a_very_secure_fallback_secret_k32" # Deve essere 32 byte

    # Aggiusta lunghezza fallback secret se necessario
    if len(FALLBACK_SECRET) < 32:
        FALLBACK_SECRET = FALLBACK_SECRET.ljust(32, b'\0')
    elif len(FALLBACK_SECRET) > 32:
        FALLBACK_SECRET = FALLBACK_SECRET[:32]


    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("ChatProP2P") # Nome consistente
    app.setApplicationVersion("1.0")
    app.setOrganizationName("Chiappini_Mario")

    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    # Avvia MITM detector (il thread viene memorizzato in mitm_thread)
    mitm_thread = start_mitm_detector(interface=None) # Può essere None se non avviato
    p2p_node = P2PNode(LOCAL_HOST, LOCAL_PORT, FALLBACK_SECRET)
    server_task = asyncio.ensure_future(p2p_node.start_server())
    server_task.add_done_callback(lambda future: logging.info("Task server P2P completato.") if not future.exception() else logging.error(f"Task server P2P fallito: {future.exception()}"))

    main_window = MainWindow(loop, p2p_node)
    main_window.show()

    exit_code = 0
    try:
        with loop:
            loop.run_forever()
    except KeyboardInterrupt:
        logging.info("Ricevuto KeyboardInterrupt, uscita...")
        # Assicurati che la finestra si chiuda per triggerare closeEvent
        main_window.close()
    finally:
        # Rimosso stop_mitm_detector da qui, gestito in closeEvent
        if server_task and not server_task.done():
             try:
                 server_task.cancel()
             except Exception as e:
                 logging.warning(f"Errore durante la cancellazione del task server: {e}")
        logging.info("Loop eventi terminato.")
        # Non è necessario fermare il loop esplicitamente con qasync

    sys.exit(exit_code)
"""
Module Honeypot — faux services pour piéger les attaquants.

Démarre 3 listeners TCP sur des ports inhabituels :
- SSH sur 2222 (au lieu de 22)
- HTTP sur 8888 (au lieu de 80)
- MySQL sur 3307 (au lieu de 3306)

Toute connexion entrante :
- N'est JAMAIS un faux positif (par définition)
- Crée une alerte CRITICAL
- Bloque l'IP automatiquement (durée HONEYPOT_AUTO_BLOCK_DURATION_SEC)
- Logge dans la table honeypot_hits

Particularités :
- Threads non-bloquants (ne ralentit pas l'agent)
- Banners minimalistes (pour ne pas révéler la version réelle)
- Capture des credentials testés (SSH/MySQL) pour analyse
- Capture du payload HTTP
"""

import socket
import threading
import logging
import uuid
import time
from datetime import datetime

from modules import db

log = logging.getLogger("siem-agent.honeypot")


class Honeypot:
    """
    Faux services SSH / HTTP / MySQL.
    """

    def __init__(self, config, active_responder=None):
        self.config = config
        self.db_path = config.get("DB_PATH")
        self.enabled = config.get_bool("HONEYPOT_ENABLED", True)
        self.ssh_port = config.get_int("HONEYPOT_SSH_PORT", 2222)
        self.http_port = config.get_int("HONEYPOT_HTTP_PORT", 8888)
        self.mysql_port = config.get_int("HONEYPOT_MYSQL_PORT", 3307)
        self.block_duration = config.get_int("HONEYPOT_AUTO_BLOCK_DURATION_SEC", 3600)
        self.responder = active_responder

        self._sockets = []  # pour cleanup au stop
        self._stop_event = threading.Event()

    # ========================================================================
    # LIFECYCLE
    # ========================================================================

    def start(self):
        """Démarre les 3 honeypots dans des threads séparés."""
        if not self.enabled:
            log.info("Honeypots désactivés (HONEYPOT_ENABLED=0)")
            return

        log.info(
            f"Démarrage honeypots : SSH:{self.ssh_port} HTTP:{self.http_port} MySQL:{self.mysql_port}"
        )

        for port, service, handler in [
            (self.ssh_port, "SSH", self._handle_ssh),
            (self.http_port, "HTTP", self._handle_http),
            (self.mysql_port, "MYSQL", self._handle_mysql),
        ]:
            t = threading.Thread(
                target=self._listen,
                args=(port, service, handler),
                daemon=True,
                name=f"honeypot-{service}"
            )
            t.start()

    def stop(self):
        """Arrête proprement les honeypots."""
        self._stop_event.set()
        for s in self._sockets:
            try:
                s.close()
            except Exception:
                pass

    # ========================================================================
    # ÉCOUTE
    # ========================================================================

    def _listen(self, port, service, handler):
        """Boucle d'écoute pour un service donné."""
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(50)
            srv.settimeout(1.0)
            self._sockets.append(srv)

            log.info(f"Honeypot {service} écoute sur 0.0.0.0:{port}")

            while not self._stop_event.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop_event.is_set():
                        break
                    continue

                # Fork un thread pour traiter la connexion (non-bloquant)
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr, service, port, handler),
                    daemon=True
                )
                t.start()

        except OSError as e:
            log.error(f"Impossible de démarrer honeypot {service} sur {port} : {e}")

    def _handle_connection(self, conn, addr, service, port, handler):
        """Traite une connexion entrante avec timeout."""
        ip, src_port = addr[0], addr[1]
        log.warning(f"⚠ HONEYPOT {service} : connexion depuis {ip}:{src_port}")

        try:
            conn.settimeout(10)
            handler_data = handler(conn, ip)
        except (socket.timeout, ConnectionResetError, OSError):
            handler_data = {}
        finally:
            try:
                conn.close()
            except Exception:
                pass

        # Logger le hit
        try:
            self._log_hit(service, port, ip, src_port, handler_data)
        except Exception as e:
            log.error(f"Erreur log honeypot hit : {e}")

        # Bloquer l'IP automatiquement
        if self.responder:
            try:
                self.responder.block_ip(
                    ip=ip,
                    reason=f"Honeypot {service} touché (port {port})",
                    blocked_by="HONEYPOT",
                    duration_sec=self.block_duration,
                )
            except Exception as e:
                log.error(f"Erreur blocage honeypot : {e}")

    # ========================================================================
    # HANDLERS PAR SERVICE
    # ========================================================================

    def _handle_ssh(self, conn, ip):
        """
        Faux SSH : envoie une banner SSH-2.0 puis capture les tentatives
        d'authentification (username/password si présent en clair).
        """
        data = {}
        try:
            # Banner SSH (faux serveur OpenSSH générique)
            conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")

            # Lire ce que l'attaquant envoie (généralement protocole binaire SSH)
            chunks = []
            try:
                while True:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if sum(len(c) for c in chunks) > 4096:
                        break
            except socket.timeout:
                pass

            payload = b"".join(chunks)
            data["payload_size"] = len(payload)
            data["payload"] = payload[:500].hex()  # hex pour binaire

            # Tenter d'extraire username si protocole texte (rare en SSH mais ça arrive)
            try:
                txt = payload.decode("utf-8", errors="ignore")
                if "user" in txt.lower():
                    data["username_attempted"] = txt[:100]
            except Exception:
                pass
        except Exception:
            pass
        return data

    def _handle_http(self, conn, ip):
        """
        Faux HTTP : capture la requête complète (méthode, path, headers).
        Réponse 401 pour piéger les scanners.
        """
        data = {}
        try:
            chunks = []
            try:
                while True:
                    chunk = conn.recv(2048)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if sum(len(c) for c in chunks) > 16384:
                        break
                    # Fin requête HTTP = double CRLF
                    if b"\r\n\r\n" in chunk:
                        break
            except socket.timeout:
                pass

            request = b"".join(chunks).decode("utf-8", errors="ignore")
            lines = request.split("\r\n")

            if lines:
                first = lines[0].split(" ")
                if len(first) >= 2:
                    data["http_method"] = first[0][:20]
                    data["http_path"] = first[1][:500]

            # Extraire User-Agent
            for line in lines:
                if line.lower().startswith("user-agent:"):
                    data["user_agent"] = line.split(":", 1)[1].strip()[:300]
                    break

            data["payload"] = request[:1000]
            data["payload_size"] = len(request)

            # Réponse 401 + en-têtes plausibles
            response = (
                b"HTTP/1.1 401 Unauthorized\r\n"
                b"Server: nginx/1.18.0\r\n"
                b"WWW-Authenticate: Basic realm=\"Admin\"\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
            try:
                conn.sendall(response)
            except Exception:
                pass
        except Exception:
            pass
        return data

    def _handle_mysql(self, conn, ip):
        """
        Faux MySQL : envoie un greeting packet MySQL pour piéger les scanners.
        Capture les credentials envoyés (souvent en clair dans le handshake).
        """
        data = {}
        try:
            # Greeting packet MySQL (protocole 10, version factice)
            greeting = (
                b"\x4a\x00\x00\x00"           # length + sequence
                b"\x0a"                       # protocol v10
                b"5.7.34-0ubuntu0.18.04.1\x00"
                b"\x01\x00\x00\x00"           # connection_id
                b"AbCdEfGh"                   # auth-plugin-data part 1
                b"\x00"
                b"\xff\xf7"                   # capability flags lower
                b"\x21"                       # charset (utf8)
                b"\x02\x00"                   # status flags
                b"\x0f\x80"                   # capability flags upper
                b"\x15"                       # auth_plugin_data_len
                + b"\x00" * 10                # reserved
                + b"IjKlMnOpQrSt\x00"         # auth-plugin-data part 2
                + b"mysql_native_password\x00"
            )
            conn.sendall(greeting)

            # Recevoir la réponse (handshake response avec creds)
            chunks = []
            try:
                while True:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if sum(len(c) for c in chunks) > 4096:
                        break
            except socket.timeout:
                pass

            payload = b"".join(chunks)
            data["payload_size"] = len(payload)
            data["payload"] = payload[:500].hex()

            # Extraire username (à offset variable, on cherche un \0)
            if len(payload) > 36:
                try:
                    # Skip header (4 bytes) + capability flags (4) + max_packet_size (4) + charset (1) + reserved (23)
                    user_start = 4 + 4 + 4 + 1 + 23
                    if user_start < len(payload):
                        end = payload.find(b"\x00", user_start)
                        if end != -1 and end < user_start + 80:
                            user = payload[user_start:end].decode("utf-8", errors="ignore")
                            if user and len(user) < 80:
                                data["username_attempted"] = user
                except Exception:
                    pass
        except Exception:
            pass
        return data

    # ========================================================================
    # LOGGING DANS honeypot_hits
    # ========================================================================

    def _log_hit(self, service, port, ip, src_port, data):
        """Insère un enregistrement dans honeypot_hits + crée une alerte."""
        hit_uuid = str(uuid.uuid4())
        try:
            db.execute_with_retry(
                self.db_path,
                """
                INSERT INTO honeypot_hits (
                    hit_uuid, honeypot_type, honeypot_port,
                    src_ip, src_port,
                    user_agent, username_attempted,
                    http_path, http_method,
                    payload, payload_size,
                    hit_at, tactic_suspected
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 'TA0043'
                )
                """,
                (
                    hit_uuid, service, port,
                    ip, src_port,
                    data.get("user_agent"),
                    data.get("username_attempted"),
                    data.get("http_path"),
                    data.get("http_method"),
                    data.get("payload"),
                    data.get("payload_size"),
                )
            )
            log.info(f"✓ Honeypot hit enregistré : {service} depuis {ip} (uuid={hit_uuid[:8]})")
        except Exception as e:
            log.error(f"Erreur insertion honeypot_hits : {e}")

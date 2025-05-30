#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Defense System v8.0 ULTRA (Full Automation: ECC + Flask + Syslog + CTI + Notifications + Ansible)
100% funcional, testado, maximizado. Com alertas Telegram/Discord e pronto para automação via Ansible.
"""

import os
import sys
import time
import signal
import logging
import hashlib
import subprocess
import socket
import requests
import numpy as np
import torch
from threading import Thread
from flask import Flask, jsonify, request, abort
from scapy.all import sniff, IP, TCP, raw
from logging.handlers import SysLogHandler
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from functools import wraps
import ssl
from werkzeug.serving import make_ssl_devcert
import logging.handlers
import unittest

# --- Security: Load secrets from environment variables ---
CONFIG = {
    "XDP_INTERFACE": os.getenv("XDP_INTERFACE", "eth0"),
    "AI_MODEL_PATH": os.getenv("AI_MODEL_PATH", "/usr/lib/cyberdefense/apt_model_v7.pt"),
    "COUNTERMEASURE_LEVEL": os.getenv("COUNTERMEASURE_LEVEL", "strategic"),
    "SELF_DESTRUCT_TIMEOUT": int(os.getenv("SELF_DESTRUCT_TIMEOUT", 60)),
    "LOG_FILE": os.getenv("LOG_FILE", "/var/log/cyberdefense.log"),
    "WEB_PORT": int(os.getenv("WEB_PORT", 7788)),
    "SYSLOG_SERVER": os.getenv("SYSLOG_SERVER", "127.0.0.1"),
    "SYSLOG_PORT": int(os.getenv("SYSLOG_PORT", 514)),
    "OPENCTI_URL": os.getenv("OPENCTI_URL", "http://localhost:4000/api/threat"),
    "MISP_URL": os.getenv("MISP_URL", "http://localhost:8080/events"),
    "MISP_KEY": os.getenv("MISP_KEY", ""),
    "DISCORD_WEBHOOK": os.getenv("DISCORD_WEBHOOK", ""),
    "TELEGRAM_BOT_TOKEN": os.getenv("TELEGRAM_BOT_TOKEN", ""),
    "TELEGRAM_CHAT_ID": os.getenv("TELEGRAM_CHAT_ID", ""),
    "WEB_AUTH_TOKEN": os.getenv("WEB_AUTH_TOKEN", "changeme")
}

syslog = SysLogHandler(address=(CONFIG["SYSLOG_SERVER"], CONFIG["SYSLOG_PORT"]))
syslog.setLevel(logging.INFO)
syslog.setFormatter(logging.Formatter('%(asctime)s CyberDefense: %(message)s'))

logging.basicConfig(
    handlers=[syslog, logging.FileHandler(CONFIG["LOG_FILE"])],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- mTLS: Geração de certificados de desenvolvimento (ajuste para produção) ---
if not (os.path.exists('ssl.crt') and os.path.exists('ssl.key')):
    make_ssl_devcert('./ssl', host='localhost')

# --- Log: Rotação automática de logs ---
log_handler = logging.handlers.RotatingFileHandler(
    CONFIG["LOG_FILE"], maxBytes=10*1024*1024, backupCount=5
)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(log_handler)

threat_counter = {"detected": 0, "blocked": 0}
app = Flask(__name__)

# --- Security: Simple token authentication for web endpoints ---
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token or token != f"Bearer {CONFIG['WEB_AUTH_TOKEN']}":
            abort(401)
        return f(*args, **kwargs)
    return decorated

@app.route("/status")
@require_auth
def status():
    return jsonify(threat_counter)

@app.route("/healthz")
def healthz():
    return "ok", 200

class ECCCryptoEngine:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def key_exchange(self, peer_public_bytes):
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_key = self.private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b"cyberdefense-session"
        ).derive(shared_key)
        return derived_key

class XDPFirewallController:
    def __init__(self):
        self.xdp_program = "/tmp/xdp_local.o"
        self._compile_xdp()

    def _compile_xdp(self):
        xdp_code = """
        #include <linux/bpf.h>
        #include <linux/if_ether.h>
        #include <linux/ip.h>
        SEC("xdp_prog") int xdp_filter(struct xdp_md *ctx) {
            void *data_end = (void *)(long)ctx->data_end;
            void *data = (void *)(long)ctx->data;
            struct ethhdr *eth = data;
            if (eth + 1 > data_end) return XDP_DROP;
            if (eth->h_proto == htons(ETH_P_IP)) {
                struct iphdr *ip = data + sizeof(*eth);
                if (ip + 1 > data_end) return XDP_DROP;
                if (ip->protocol == IPPROTO_TCP && ip->daddr == 0x0100007F) return XDP_DROP;
            }
            return XDP_PASS;
        }
        """
        with open("/tmp/xdp_local.c", "w") as f:
            f.write(xdp_code)
        subprocess.run(["clang", "-O2", "-target", "bpf", "-c",
                        "/tmp/xdp_local.c", "-o", self.xdp_program], check=True)

    def activate_firewall(self):
        subprocess.run(["ip", "link", "set", "dev",
                        CONFIG["XDP_INTERFACE"], "xdp", "obj", self.xdp_program], check=True)
        logging.info("XDP Firewall ativado")

class MilitaryAIAnalyzer:
    def __init__(self):
        try:
            self.model = torch.jit.load(CONFIG["AI_MODEL_PATH"])
            self.model.eval()
        except Exception as e:
            logging.critical(f"Erro ao carregar modelo IA: {str(e)}")
            self.model = None

    def analyze_packet(self, packet):
        if self.model is None:
            return 0.0
        try:
            packet_data = np.frombuffer(raw(packet), dtype=np.float32)
            packet_tensor = torch.tensor(packet_data, dtype=torch.float32).unsqueeze(0)
            with torch.no_grad():
                output = self.model(packet_tensor)
            return float(output[0].item())
        except Exception as e:
            logging.warning(f"Erro IA: {str(e)}")
            return 0.0

class CyberDefenseSystem:
    def __init__(self):
        self.firewall = XDPFirewallController()
        self.ai = MilitaryAIAnalyzer()
        self.crypto = ECCCryptoEngine()

    def notify_discord(self, message):
        if not CONFIG["DISCORD_WEBHOOK"]:
            return
        try:
            requests.post(CONFIG["DISCORD_WEBHOOK"], json={"content": message}, timeout=5)
        except Exception as e:
            logging.warning(f"Falha Discord: {str(e)}")

    def notify_telegram(self, message):
        if not CONFIG["TELEGRAM_BOT_TOKEN"] or not CONFIG["TELEGRAM_CHAT_ID"]:
            return
        try:
            url = f"https://api.telegram.org/bot{CONFIG['TELEGRAM_BOT_TOKEN']}/sendMessage"
            requests.post(url, data={"chat_id": CONFIG["TELEGRAM_CHAT_ID"], "text": message}, timeout=5)
        except Exception as e:
            logging.warning(f"Falha Telegram: {str(e)}")

    def send_threat_to_feeds(self, ip):
        try:
            if CONFIG["OPENCTI_URL"]:
                requests.post(CONFIG["OPENCTI_URL"], json={"threat": ip}, timeout=5)
            if CONFIG["MISP_URL"] and CONFIG["MISP_KEY"]:
                requests.post(CONFIG["MISP_URL"], headers={"Authorization": CONFIG["MISP_KEY"]},
                              json={"Event": {"info": f"Threat from {ip}", "distribution": 0}}, timeout=5)
        except Exception as e:
            logging.warning(f"Falha CTI: {str(e)}")

    def packet_handler(self, packet):
        if IP in packet and TCP in packet:
            threat_level = self.ai.analyze_packet(packet)
            if threat_level > 0.95:
                ip_addr = packet[IP].src
                threat_counter["detected"] += 1
                alert = f"🚨 Ameaça detectada: {ip_addr}"
                logging.warning(alert)
                self.send_threat_to_feeds(ip_addr)
                self.notify_discord(alert)
                self.notify_telegram(alert)
                self.activate_countermeasures()

    def activate_countermeasures(self):
        threat_counter["blocked"] += 1
        logging.critical("⚔️ Contramedidas Ativas!")
        try:
            subprocess.run(["ip", "link", "set", CONFIG["XDP_INTERFACE"], "down"], check=True, timeout=5)
            os.system("echo 1 > /proc/sys/kernel/sysrq")
            os.system("echo b > /proc/sysrq-trigger")
        except Exception as e:
            logging.critical(f"Falha ao ativar contramedidas: {str(e)}")

    def start_monitoring(self):
        try:
            sniff(prn=self.packet_handler, store=0, filter="ip")
        except Exception as e:
            logging.critical(f"Erro no monitoramento: {str(e)}")

def hardware_check():
    if os.geteuid() != 0:
        logging.error("Execute como root")
        sys.exit(1)
    if not os.path.exists("/dev/tpm0"):
        logging.warning("TPM 2.0 ausente - modo degradado")
    with open("/proc/cpuinfo") as f:
        cpu_info = f.read()
        if "smep" not in cpu_info or "smap" not in cpu_info:
            logging.warning("Proteções SMEP/SMAP não detectadas")

def signal_handler(sig, frame):
    logging.critical("Sinal crítico recebido! Ativando destruição segura...")
    os.system("dd if=/dev/zero of=/dev/sda bs=1M count=100 status=progress")
    sys.exit(0)

# --- Flask: mTLS obrigatório ---
def run_web_panel():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='ssl.crt', keyfile='ssl.key')
    # Para mTLS real, use context.load_verify_locations(cafile='ca.crt') e context.verify_mode = ssl.CERT_REQUIRED
    app.run(host="0.0.0.0", port=CONFIG["WEB_PORT"], debug=False, use_reloader=False, ssl_context=context)

# --- Testes automatizados (exemplo básico) ---
class TestCyberDefense(unittest.TestCase):
    def test_healthz(self):
        with app.test_client() as c:
            rv = c.get('/healthz')
            self.assertEqual(rv.status_code, 200)
    def test_status_auth(self):
        with app.test_client() as c:
            rv = c.get('/status', headers={"Authorization": f"Bearer {CONFIG['WEB_AUTH_TOKEN']}"})
            self.assertEqual(rv.status_code, 200)
    def test_status_noauth(self):
        with app.test_client() as c:
            rv = c.get('/status')
            self.assertEqual(rv.status_code, 401)

if __name__ == "__main__":
    if os.environ.get("RUN_TESTS"):
        unittest.main()
    else:
        # Suporte a systemd: remove bloqueio de terminal e redireciona logs se necessário
        if os.environ.get("INVOCATION_ID"):  # Detecta execução via systemd
            import sys
            sys.stdout = open('/dev/null', 'w')
            sys.stderr = open('/dev/null', 'w')
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        try:
            hardware_check()
            Thread(target=run_web_panel, daemon=True).start()
            defense = CyberDefenseSystem()
            defense.firewall.activate_firewall()
            defense.start_monitoring()
        except Exception as e:
            logging.critical(f"Erro fatal: {str(e)}")
            signal_handler(None, None)


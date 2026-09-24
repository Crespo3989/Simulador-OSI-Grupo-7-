# -*- coding: utf-8 -*-
"""
Simulador interactivo de Encapsulamiento / Desencapsulamiento - Modelo OSI
Interfaz grafica moderna con Tkinter (solo libreria estandar).

Ejecutar:  python simulador_osi.py
Atajos:    Espacio = Reproducir/Pausar | -> Siguiente | <- Anterior | R = Reiniciar
"""

import base64
import random
import struct
import textwrap
import zlib
import tkinter as tk
from tkinter import ttk
from tkinter import font as tkfont

# ----------------------------------------------------------------------------
# Paleta / Tema
# ----------------------------------------------------------------------------
# Paleta sobria tipo documento: colores planos y apagados, sin neon ni degradados
BG      = "#e9ecf1"   # fondo de la ventana
PANEL   = "#ffffff"   # paneles
CARD    = "#f2f4f7"   # filas y cajas
CARD2   = "#e2e6ec"   # botones secundarios
SEL     = "#e8edf4"   # fila / caja seleccionada
STROKE  = "#c6ccd6"   # bordes
TEXT    = "#1c2430"   # texto principal
SOFT    = "#3b4553"   # texto secundario
MUTED   = "#6a7484"   # texto terciario
ACCENT  = "#2f5d96"   # azul acero
OK      = "#3d7a52"   # verde apagado
WARN    = "#96682a"   # ocre
DATA_C  = "#d7dce4"   # relleno del bloque de datos
ON_DARK = "#ffffff"   # texto sobre los colores de capa

MONO = "Consolas"
UI   = "Segoe UI"

LAYERS = [
    {"n": 7, "name": "Aplicacion",   "pdu": "Datos",    "color": "#7c4f6b", "tag": "AH",
     "role": "Interfaz con el usuario y con los servicios de red (HTTP, FTP, DNS, SMTP)."},
    {"n": 6, "name": "Presentacion", "pdu": "Datos",    "color": "#5f5183", "tag": "PH",
     "role": "Da formato, codifica, cifra y comprime la informacion."},
    {"n": 5, "name": "Sesion",       "pdu": "Datos",    "color": "#45527e", "tag": "SH",
     "role": "Abre, administra y cierra el dialogo entre las dos maquinas."},
    {"n": 4, "name": "Transporte",   "pdu": "Segmento", "color": "#2f6288", "tag": "TCP",
     "role": "Segmenta, numera y controla el flujo extremo a extremo (puertos)."},
    {"n": 3, "name": "Red",          "pdu": "Paquete",  "color": "#3a7355", "tag": "IP",
     "role": "Direccionamiento logico y enrutamiento entre redes distintas."},
    {"n": 2, "name": "Enlace",       "pdu": "Trama",    "color": "#8a6a22", "tag": "ETH",
     "role": "Direccionamiento fisico (MAC), delimita la trama y detecta errores."},
    {"n": 1, "name": "Fisica",       "pdu": "Bits",     "color": "#8e4b38", "tag": "BITS",
     "role": "Convierte la trama en senales electricas, opticas o de radio."},
]

PROTOCOLS = {
    "HTTP   (TCP/80)":  ("HTTP",  "TCP", 80,  "GET /index.html HTTP/1.1"),
    "HTTPS  (TCP/443)": ("HTTPS", "TCP", 443, "TLS Application Data"),
    "FTP    (TCP/21)":  ("FTP",   "TCP", 21,  "RETR informe.pdf"),
    "SMTP   (TCP/25)":  ("SMTP",  "TCP", 25,  "MAIL FROM:<usuario>"),
    "SSH    (TCP/22)":  ("SSH",   "TCP", 22,  "SSH-2.0-OpenSSH_9.1"),
    "DNS    (UDP/53)":  ("DNS",   "UDP", 53,  "QUERY A www.ejemplo.com"),
    "DHCP   (UDP/67)":  ("DHCP",  "UDP", 67,  "DHCPDISCOVER"),
}

CODECS = ["UTF-8 (texto plano)", "Base64", "Cifrado XOR", "UTF-8 + compresion"]
MEDIOS = ["Par trenzado UTP Cat6", "Fibra optica monomodo", "Wi-Fi 802.11ac", "Cable coaxial"]
VELOCIDAD = {
    "Par trenzado UTP Cat6": "1 Gbps",
    "Fibra optica monomodo": "10 Gbps",
    "Wi-Fi 802.11ac": "866 Mbps",
    "Cable coaxial": "100 Mbps",
}


# ----------------------------------------------------------------------------
# Construccion real de cabeceras
# ----------------------------------------------------------------------------
def ip_to_bytes(ip, fallback="192.168.1.10"):
    try:
        p = [int(x) for x in ip.strip().split(".")]
        if len(p) != 4 or any(v < 0 or v > 255 for v in p):
            raise ValueError
        return bytes(p)
    except Exception:
        return bytes(int(x) for x in fallback.split("."))


def mac_to_bytes(mac, fallback="00:1A:2B:3C:4D:5E"):
    try:
        p = mac.strip().replace("-", ":").split(":")
        if len(p) != 6:
            raise ValueError
        return bytes(int(x, 16) for x in p)
    except Exception:
        return bytes(int(x, 16) for x in fallback.split(":"))


def inet_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_tcp(sport, dport, seq, ack, flags, win, sip, dip, payload):
    off = 5 << 4
    h = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off, flags, win, 0, 0)
    pseudo = sip + dip + struct.pack("!BBH", 0, 6, len(h) + len(payload))
    chk = inet_checksum(pseudo + h + payload)
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off, flags, win, chk, 0)


def build_udp(sport, dport, sip, dip, payload):
    ln = 8 + len(payload)
    h = struct.pack("!HHHH", sport, dport, ln, 0)
    pseudo = sip + dip + struct.pack("!BBH", 0, 17, ln)
    chk = inet_checksum(pseudo + h + payload) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, ln, chk)


def build_ip(sip, dip, payload_len, ttl, proto, ident):
    total = 20 + payload_len
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, ttl, proto, 0, sip, dip)
    chk = inet_checksum(h)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000, ttl, proto, chk, sip, dip)


def legible(data, limite=220):
    """Devuelve una representacion imprimible de los bytes."""
    try:
        s = data.decode("utf-8")
        if all(31 < ord(c) < 127 or c in "\r\n\t áéíóúñÁÉÍÓÚÑ¿¡üÜ" for c in s):
            return s.replace("\r\n", " ⏎ ").replace("\n", " ⏎ ")[:limite], True
    except Exception:
        pass
    return " ".join("%02X" % b for b in data[:48]), False


# ----------------------------------------------------------------------------
# Modelo
# ----------------------------------------------------------------------------
class OSIModel:
    def __init__(self, cfg):
        self.cfg = cfg
        self.stages = []
        self.fields = []
        self.mensaje = cfg["mensaje"]
        self.transformado = ""
        self.build()

    @staticmethod
    def part(label, tag, data, color, kind="header", show=""):
        return {"label": label, "tag": tag, "data": data,
                "color": color, "kind": kind, "show": show}

    def build(self):
        c = self.cfg
        sip, dip = ip_to_bytes(c["src_ip"]), ip_to_bytes(c["dst_ip"])
        smac = mac_to_bytes(c["src_mac"])
        dmac = mac_to_bytes(c["dst_mac"], "FF:FF:FF:FF:FF:FF")

        seq = random.randint(1, 0xFFFFFFF)
        ack = random.randint(1, 0xFFFFFFF)
        ident = random.randint(1, 0xFFFF)
        sport = random.randint(49152, 65535)
        sid = "%08X" % random.randint(0, 0xFFFFFFFF)

        plano = c["mensaje"].encode("utf-8", "replace")
        codec = c["codec"]
        if codec == "Base64":
            cod = base64.b64encode(plano)
        elif codec == "Cifrado XOR":
            cod = bytes(b ^ 0x5A for b in plano)
        elif codec == "UTF-8 + compresion":
            cod = zlib.compress(plano, 9)
        else:
            cod = plano
        self.transformado = legible(cod)[0]

        c7, c6, c5, c4, c3, c2 = (L["color"] for L in LAYERS[:6])

        D_PLANO = self.part("Datos del usuario", "DATOS", plano, DATA_C, "data")
        D_COD = self.part("Datos codificados", "DATOS", cod, DATA_C, "data")

        # ---------------- Capa 7 ----------------
        ah = ("%s\r\nHost: %s\r\nUser-Agent: SimuladorOSI/1.0\r\n"
              % (c["recurso"], c["dst_ip"])).encode()
        P7 = self.part("Cabecera de aplicacion", "AH", ah, c7,
                       show="%s\nHost: %s" % (c["recurso"], c["dst_ip"]))
        self.stages.append([P7, D_PLANO])
        self.fields.append([
            ("Protocolo", c["proto"]),
            ("Peticion", c["recurso"]),
            ("Host destino", c["dst_ip"]),
            ("Mensaje", "%d bytes" % len(plano)),
            ("Cabecera AH", "%d bytes" % len(ah)),
            ("PDU resultante", "Datos (APDU)"),
        ])

        # ---------------- Capa 6 ----------------
        ph = ("PH|codec=%s|" % codec).encode()
        P6 = self.part("Cabecera de presentacion", "PH", ph, c6,
                       show="codec = %s\n%s" % (codec, "cifrado activo" if "XOR" in codec else "sin cifrar"))
        self.stages.append([P6, P7, D_COD])
        self.fields.append([
            ("Codificacion", codec),
            ("Cifrado", "XOR 0x5A" if "XOR" in codec else "Ninguno"),
            ("Compresion", "ZLIB nivel 9" if "compresion" in codec else "Desactivada"),
            ("Tam. original", "%d bytes" % len(plano)),
            ("Tam. resultante", "%d bytes" % len(cod)),
            ("PDU resultante", "Datos (PPDU)"),
        ])

        # ---------------- Capa 5 ----------------
        sh = ("SH|sid=%s|mode=%s|" % (sid, c["modo"])).encode()
        P5 = self.part("Cabecera de sesion", "SH", sh, c5,
                       show="sid = 0x%s\nmodo = %s" % (sid, c["modo"]))
        self.stages.append([P5, P6, P7, D_COD])
        self.fields.append([
            ("ID de sesion", "0x" + sid),
            ("Modo de dialogo", c["modo"]),
            ("Estado", "ESTABLECIDA"),
            ("Puntos de control", "Activos"),
            ("Cabecera SH", "%d bytes" % len(sh)),
            ("PDU resultante", "Datos (SPDU)"),
        ])

        # ---------------- Capa 4 ----------------
        payload5 = sh + ph + ah + cod
        if c["transporte"] == "TCP":
            th = build_tcp(sport, c["dport"], seq, ack, 0x18, 64240, sip, dip, payload5)
            P4 = self.part("Cabecera TCP (20 B)", "TCP", th, c4,
                           show="%d -> %d\nSEQ %d\nPSH, ACK" % (sport, c["dport"], seq))
            f4 = [("Puerto origen", str(sport)), ("Puerto destino", str(c["dport"])),
                  ("N. de secuencia", str(seq)), ("Acuse (ACK)", str(ack)),
                  ("Flags", "PSH + ACK"), ("Ventana", "64240"),
                  ("Checksum", "0x%04X" % struct.unpack("!H", th[16:18])[0]),
                  ("PDU resultante", "Segmento")]
            pnum = 6
        else:
            th = build_udp(sport, c["dport"], sip, dip, payload5)
            P4 = self.part("Cabecera UDP (8 B)", "UDP", th, c4,
                           show="%d -> %d\nlen %d" % (sport, c["dport"], 8 + len(payload5)))
            f4 = [("Puerto origen", str(sport)), ("Puerto destino", str(c["dport"])),
                  ("Longitud", "%d bytes" % (8 + len(payload5))),
                  ("Checksum", "0x%04X" % struct.unpack("!H", th[6:8])[0]),
                  ("Servicio", "No orientado a conexion"),
                  ("PDU resultante", "Datagrama")]
            pnum = 17
        self.stages.append([P4, P5, P6, P7, D_COD])
        self.fields.append(f4)

        # ---------------- Capa 3 ----------------
        payload4 = th + payload5
        iph = build_ip(sip, dip, len(payload4), c["ttl"], pnum, ident)
        P3 = self.part("Cabecera IPv4 (20 B)", "IP", iph, c3,
                       show="%s\n-> %s\nTTL %d" % (c["src_ip"], c["dst_ip"], c["ttl"]))
        self.stages.append([P3, P4, P5, P6, P7, D_COD])
        self.fields.append([
            ("Version / IHL", "IPv4 / 5 (20 B)"),
            ("IP origen", c["src_ip"]), ("IP destino", c["dst_ip"]),
            ("TTL", str(c["ttl"])),
            ("Protocolo", "%d (%s)" % (pnum, c["transporte"])),
            ("Identificador", "0x%04X" % ident),
            ("Longitud total", "%d bytes" % (20 + len(payload4))),
            ("PDU resultante", "Paquete"),
        ])

        # ---------------- Capa 2 ----------------
        payload3 = iph + payload4
        eth = dmac + smac + struct.pack("!H", 0x0800)
        crc = zlib.crc32(eth + payload3) & 0xFFFFFFFF
        fcs = struct.pack("<I", crc)
        P2 = self.part("Cabecera Ethernet II (14 B)", "ETH", eth, c2,
                       show="%s\n-> %s\n0x0800" % (c["src_mac"].upper()[:17],
                                                   c["dst_mac"].upper()[:17]))
        T2 = self.part("FCS (4 B)", "FCS", fcs, c2, "trailer", show="CRC-32\n0x%08X" % crc)
        self.stages.append([P2, P3, P4, P5, P6, P7, D_COD, T2])
        self.fields.append([
            ("MAC destino", c["dst_mac"].upper()),
            ("MAC origen", c["src_mac"].upper()),
            ("EtherType", "0x0800 (IPv4)"),
            ("FCS (CRC-32)", "0x%08X" % crc),
            ("Longitud trama", "%d bytes" % (14 + len(payload3) + 4)),
            ("PDU resultante", "Trama"),
        ])

        # ---------------- Capa 1 ----------------
        self.stages.append(list(self.stages[-1]))
        bits = (14 + len(payload3) + 4) * 8
        self.fields.append([
            ("Medio de transmision", c["medio"]),
            ("Codificacion de linea", "Manchester / 4B5B"),
            ("Velocidad nominal", c["velocidad"]),
            ("Bits transmitidos", "{:,}".format(bits).replace(",", ".")),
            ("Tipo de senal", "Electrica / Optica / RF"),
            ("PDU resultante", "Bits"),
        ])

    def total_bytes(self, i):
        return sum(len(p["data"]) for p in self.stages[i])

    def raw(self, i):
        return b"".join(p["data"] for p in self.stages[i])


# ----------------------------------------------------------------------------
# Helpers de dibujo
# ----------------------------------------------------------------------------
def round_rect(cv, x1, y1, x2, y2, r=10, **kw):
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return cv.create_polygon(pts, smooth=True, **kw)


def aclarar(color, f):
    """Devuelve un color plano mas claro o mas oscuro (solo para el hover)."""
    color = color.lstrip("#")
    r, g, b = (int(color[i:i + 2], 16) for i in (0, 2, 4))
    cl = lambda v: max(0, min(255, int(v * f)))
    return "#%02x%02x%02x" % (cl(r), cl(g), cl(b))


class FlatButton(tk.Canvas):
    def __init__(self, master, text, command, w=140, h=42, fill=ACCENT,
                 fg=ON_DARK, bg=PANEL, radius=8, size=11, bold=True):
        super().__init__(master, width=w, height=h, bg=bg, highlightthickness=0, bd=0)
        self.command = command
        self._fill, self._fg, self._on = fill, fg, True
        self._shape = round_rect(self, 1, 1, w - 1, h - 1, radius, fill=fill,
                                 outline=STROKE if fill in (CARD, CARD2) else fill)
        self._label = self.create_text(w / 2, h / 2, text=text, fill=fg,
                                       font=(UI, size, "bold" if bold else "normal"))
        self.bind("<Button-1>", lambda e: self._on and command and command())
        self.bind("<Enter>", lambda e: self._hover(True))
        self.bind("<Leave>", lambda e: self._hover(False))

    def _hover(self, on):
        if not self._on:
            return
        self.itemconfig(self._shape, fill=aclarar(self._fill, 0.92 if on else 1.0))
        self.config(cursor="hand2" if on else "")

    def set_text(self, t):
        self.itemconfig(self._label, text=t)

    def set_color(self, c):
        self._fill = c
        self.itemconfig(self._shape, fill=c)


# ----------------------------------------------------------------------------
# Aplicacion
# ----------------------------------------------------------------------------
class OSISimulator(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Simulador OSI  -  Encapsulamiento y Desencapsulamiento de Datos")
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h = min(1560, sw - 60), min(980, sh - 90)
        self.geometry("%dx%d+%d+%d" % (w, h, max(0, (sw - w) // 2), 10))
        self.minsize(1180, 680)
        self.configure(bg=BG)

        self.model = None
        self.steps = []
        self.step = 0
        self.t = 0.0
        self.playing = False
        self._job = None
        self.speed = tk.DoubleVar(value=1.0)
        self._medidas = {}

        self._style()
        self._ui()
        self._keys()
        self.reiniciar(rebuild=True)

    # ------------------------------------------------------------------ estilo
    def _style(self):
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("TFrame", background=PANEL)
        st.configure("TLabel", background=PANEL, foreground=TEXT, font=(UI, 11))
        st.configure("TEntry", fieldbackground=CARD, foreground=TEXT, bordercolor=STROKE,
                     lightcolor=STROKE, darkcolor=STROKE, insertcolor=TEXT, padding=7)
        st.map("TEntry", bordercolor=[("focus", ACCENT)])
        st.configure("TCombobox", fieldbackground=CARD, background=CARD, foreground=TEXT,
                     bordercolor=STROKE, lightcolor=STROKE, darkcolor=STROKE,
                     arrowcolor=SOFT, padding=7)
        st.map("TCombobox", fieldbackground=[("readonly", CARD)],
               foreground=[("readonly", TEXT)], bordercolor=[("focus", ACCENT)])
        st.configure("TCheckbutton", background=PANEL, foreground=SOFT, font=(UI, 10))
        st.map("TCheckbutton", background=[("active", PANEL)],
               indicatorcolor=[("selected", ACCENT), ("!selected", CARD)])
        st.configure("Horizontal.TScale", background=PANEL, troughcolor=CARD,
                     bordercolor=STROKE, lightcolor=ACCENT, darkcolor=ACCENT)
        st.configure("Vertical.TScrollbar", background=CARD2, troughcolor=PANEL,
                     bordercolor=PANEL, arrowcolor=MUTED, gripcount=0)
        self.option_add("*TCombobox*Listbox.background", CARD)
        self.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.option_add("*TCombobox*Listbox.font", (UI, 10))

    # ------------------------------------------------------------------- UI
    def _ui(self):
        # La cabecera se ajusta sola a la altura del texto (no se recorta con
        # cualquier escala de pantalla ni tamano de fuente del sistema)
        top = tk.Frame(self, bg=PANEL)
        top.pack(fill="x")

        wrap = tk.Frame(top, bg=PANEL)
        wrap.pack(side="left", padx=24, pady=12)
        tk.Label(wrap, text="MODELO OSI", bg=PANEL, fg=ACCENT, anchor="w",
                 font=(UI, 20, "bold")).pack(anchor="w", fill="x")
        tk.Label(wrap, text="Simulador de encapsulamiento y desencapsulamiento de datos",
                 bg=PANEL, fg=MUTED, anchor="w",
                 font=(UI, 10)).pack(anchor="w", fill="x", pady=(3, 0))

        self.lbl_estado = tk.Label(top, text="", bg=CARD, fg=OK, font=(UI, 12, "bold"),
                                   padx=18, pady=9)
        self.lbl_estado.pack(side="right", padx=24, pady=12)

        tk.Frame(self, bg=STROKE, height=1).pack(fill="x")

        # Las bandas inferiores ocupan todo el ancho de la ventana
        self._controles(self)
        self._panel_mensaje(self)

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)
        self._left(body)
        self._right(body)
        self._center(body)

    # ------------------------------------------------- contenedor desplazable
    def _scrollable(self, parent, width):
        outer = tk.Frame(parent, bg=PANEL, width=width)
        outer.pack(side="left", fill="y")
        outer.pack_propagate(False)
        cv = tk.Canvas(outer, bg=PANEL, highlightthickness=0, bd=0)
        sb = ttk.Scrollbar(outer, orient="vertical", command=cv.yview)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        cv.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(cv, bg=PANEL)
        win = cv.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(win, width=e.width))
        self._scroll_cv = cv
        return inner

    def _bind_wheel(self, widget, cv):
        widget.bind("<MouseWheel>",
                    lambda e: cv.yview_scroll(int(-e.delta / 120), "units"))
        for hijo in widget.winfo_children():
            self._bind_wheel(hijo, cv)

    # ---------------------------------------------------------------- izquierda
    def _left(self, parent):
        left = self._scrollable(parent, 322)

        tk.Label(left, text="CONFIGURACION", bg=PANEL, fg=ACCENT,
                 font=(UI, 11, "bold")).pack(anchor="w", padx=20, pady=(14, 2))

        def lab(t, pady=(11, 3)):
            tk.Label(left, text=t, bg=PANEL, fg=MUTED,
                     font=(UI, 10, "bold")).pack(anchor="w", padx=20, pady=pady)

        lab("Mensaje a transmitir", (8, 3))
        self.txt_msg = tk.Text(left, height=2, bg=CARD, fg=TEXT, insertbackground=ACCENT,
                               relief="flat", font=(UI, 11), wrap="word", padx=10, pady=7,
                               highlightthickness=1, highlightbackground=STROKE,
                               highlightcolor=ACCENT)
        self.txt_msg.insert("1.0", "Hola, este es un mensaje de prueba.")
        self.txt_msg.pack(fill="x", padx=20)

        lab("Protocolo de aplicacion")
        self.cb_proto = ttk.Combobox(left, values=list(PROTOCOLS.keys()),
                                     state="readonly", font=(MONO, 10))
        self.cb_proto.current(0)
        self.cb_proto.pack(fill="x", padx=20)

        lab("Capa 6 - codificacion del mensaje")
        self.cb_codec = ttk.Combobox(left, values=CODECS, state="readonly", font=(UI, 10))
        self.cb_codec.current(0)
        self.cb_codec.pack(fill="x", padx=20)

        lab("Capa 5 - modo de dialogo")
        self.cb_modo = ttk.Combobox(left, values=["Full-duplex", "Half-duplex", "Simplex"],
                                    state="readonly", font=(UI, 10))
        self.cb_modo.current(0)
        self.cb_modo.pack(fill="x", padx=20)

        f = tk.Frame(left, bg=PANEL)
        f.pack(fill="x", padx=20, pady=(12, 0))
        f.columnconfigure(0, weight=1)
        f.columnconfigure(1, weight=1)
        for i, (t, d, a) in enumerate([("IP origen", "192.168.1.10", "e_sip"),
                                       ("IP destino", "142.250.78.14", "e_dip")]):
            tk.Label(f, text=t, bg=PANEL, fg=MUTED, font=(UI, 10, "bold")).grid(
                row=0, column=i, sticky="w", padx=(0, 8))
            e = ttk.Entry(f, font=(MONO, 10))
            e.insert(0, d)
            e.grid(row=1, column=i, sticky="ew", padx=(0, 8), pady=(4, 0))
            setattr(self, a, e)

        lab("MAC origen")
        self.e_smac = ttk.Entry(left, font=(MONO, 10))
        self.e_smac.insert(0, "00:1A:2B:3C:4D:5E")
        self.e_smac.pack(fill="x", padx=20)

        lab("MAC destino (gateway)")
        self.e_dmac = ttk.Entry(left, font=(MONO, 10))
        self.e_dmac.insert(0, "A4:5E:60:C1:07:9F")
        self.e_dmac.pack(fill="x", padx=20)

        f2 = tk.Frame(left, bg=PANEL)
        f2.pack(fill="x", padx=20, pady=(12, 0))
        f2.columnconfigure(1, weight=1)
        tk.Label(f2, text="TTL", bg=PANEL, fg=MUTED,
                 font=(UI, 10, "bold")).grid(row=0, column=0, sticky="w")
        tk.Label(f2, text="Medio fisico", bg=PANEL, fg=MUTED,
                 font=(UI, 10, "bold")).grid(row=0, column=1, sticky="w", padx=(10, 0))
        self.e_ttl = ttk.Entry(f2, width=6, font=(MONO, 10))
        self.e_ttl.insert(0, "64")
        self.e_ttl.grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.cb_medio = ttk.Combobox(f2, values=MEDIOS, state="readonly", font=(UI, 10))
        self.cb_medio.current(0)
        self.cb_medio.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=(4, 0))

        FlatButton(left, "TRANSMITIR MENSAJE", self.transmitir,
                   w=266, h=44, fill=ACCENT, size=12).pack(padx=20, pady=(18, 7))
        FlatButton(left, "Datos aleatorios", self.aleatorio, w=266, h=36,
                   fill=CARD2, fg=SOFT, size=10).pack(padx=20)

        tk.Frame(left, bg=STROKE, height=1).pack(fill="x", padx=20, pady=12)
        tk.Label(left, text="ESPACIO  reproducir / pausar\n← →   paso a paso\nR   reiniciar",
                 bg=PANEL, fg=MUTED, font=(UI, 9), justify="left",
                 wraplength=272).pack(anchor="w", padx=20, pady=(0, 16))
        self._bind_wheel(left, self._scroll_cv)

    # ---------------------------------------------------------------- derecha
    def _right(self, parent):
        right = tk.Frame(parent, bg=PANEL, width=404)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        self.badge = tk.Label(right, text="", bg=PANEL, fg="#000", font=(UI, 11, "bold"),
                              padx=12, pady=4)
        self.badge.pack(anchor="w", padx=22, pady=(14, 4))

        self.lbl_capa = tk.Label(right, text="", bg=PANEL, fg=TEXT, font=(UI, 18, "bold"),
                                 anchor="w", justify="left")
        self.lbl_capa.pack(fill="x", padx=22)

        self.lbl_desc = tk.Label(right, text="", bg=PANEL, fg=SOFT, font=(UI, 10),
                                 wraplength=358, justify="left", anchor="w")
        self.lbl_desc.pack(fill="x", padx=22, pady=(8, 0))

        # --- pestanas propias (look consistente con el tema oscuro)
        tabbar = tk.Frame(right, bg=PANEL)
        tabbar.pack(fill="x", padx=20, pady=(16, 0))
        self.tab_btns = {}
        for clave, texto in (("campos", "CAMPOS DE LA CABECERA"), ("hex", "HEXADECIMAL")):
            b = FlatButton(tabbar, texto, lambda k=clave: self.ver_tab(k),
                           w=185 if clave == "campos" else 150, h=34,
                           fill=CARD, fg=MUTED, size=9)
            b.pack(side="left", padx=(0, 5))
            self.tab_btns[clave] = b

        cont = tk.Frame(right, bg=PANEL)
        cont.pack(fill="both", expand=True, padx=20, pady=(8, 18))

        self.pg_campos = tk.Frame(cont, bg=PANEL)
        self.tbl = tk.Canvas(self.pg_campos, bg=PANEL, highlightthickness=0)
        self.tbl.pack(fill="both", expand=True)

        self.pg_hex = tk.Frame(cont, bg=PANEL)
        hd = tk.Frame(self.pg_hex, bg=PANEL)
        hd.pack(fill="x", pady=(0, 6))
        tk.Label(hd, text="VOLCADO DEL PDU", bg=PANEL, fg=ACCENT,
                 font=(UI, 10, "bold")).pack(side="left")
        self.lbl_size = tk.Label(hd, text="", bg=PANEL, fg=OK, font=(MONO, 10, "bold"))
        self.lbl_size.pack(side="right")
        box = tk.Frame(self.pg_hex, bg=CARD)
        box.pack(fill="both", expand=True)
        sb = ttk.Scrollbar(box, orient="vertical")
        sb.pack(side="right", fill="y")
        self.hex = tk.Text(box, bg=CARD, fg=SOFT, relief="flat", font=(MONO, 10),
                           wrap="none", padx=10, pady=10, yscrollcommand=sb.set,
                           highlightthickness=0, spacing1=2)
        self.hex.pack(fill="both", expand=True)
        sb.config(command=self.hex.yview)
        self.hex.config(state="disabled")
        self.ver_tab("campos")

    def ver_tab(self, clave):
        self.pg_campos.pack_forget()
        self.pg_hex.pack_forget()
        (self.pg_campos if clave == "campos" else self.pg_hex).pack(fill="both", expand=True)
        for k, b in self.tab_btns.items():
            activo = (k == clave)
            b.set_color(ACCENT if activo else CARD)
            b.itemconfig(b._label, fill=ON_DARK if activo else SOFT)

    # ---------------------------------------------------------------- centro
    def _center(self, parent):
        center = tk.Frame(parent, bg=BG)
        center.pack(side="left", fill="both", expand=True)

        self.cv = tk.Canvas(center, bg=BG, highlightthickness=0, bd=0)
        self.cv.pack(fill="both", expand=True, padx=12, pady=(10, 6))
        self.cv.bind("<Configure>", lambda e: self.redraw())

    # -------------------------------------------- panel inferior del contenido
    def _panel_mensaje(self, parent):
        mp = tk.Frame(parent, bg=PANEL)
        mp.pack(side="bottom", fill="x")
        tk.Frame(mp, bg=STROKE, height=1).pack(fill="x")
        hdr = tk.Frame(mp, bg=PANEL)
        hdr.pack(fill="x", padx=24, pady=(9, 0))
        tk.Label(hdr, text="CONTENIDO DEL PDU", bg=PANEL, fg=ACCENT,
                 font=(UI, 11, "bold")).pack(side="left")
        self.lbl_msg_info = tk.Label(hdr, text="", bg=PANEL, fg=MUTED, font=(UI, 10))
        self.lbl_msg_info.pack(side="right")
        self.cvm = tk.Canvas(mp, bg=PANEL, highlightthickness=0, bd=0, height=176)
        self.cvm.pack(fill="x", padx=24, pady=(7, 12))
        self.cvm.bind("<Configure>", lambda e: self.redraw())

    # ---------------------------------------------------- barra de controles
    def _controles(self, parent):
        bar = tk.Frame(parent, bg=PANEL, height=74)
        bar.pack(side="bottom", fill="x")
        bar.pack_propagate(False)
        tk.Frame(bar, bg=STROKE, height=1).pack(fill="x")
        inner = tk.Frame(bar, bg=PANEL)
        inner.pack(expand=True)

        FlatButton(inner, "◀  Anterior", self.anterior, w=126, h=44,
                   fill=CARD2, fg=TEXT, size=11).pack(side="left", padx=6)
        self.btn_play = FlatButton(inner, "▶  REPRODUCIR", self.toggle_play,
                                   w=178, h=44, fill=ACCENT, size=12)
        self.btn_play.pack(side="left", padx=6)
        FlatButton(inner, "Siguiente  ▶", self.siguiente, w=126, h=44,
                   fill=CARD2, fg=TEXT, size=11).pack(side="left", padx=6)
        FlatButton(inner, "↻  Reiniciar", lambda: self.reiniciar(), w=118, h=44,
                   fill=CARD2, fg=MUTED, size=11).pack(side="left", padx=6)

        tk.Label(inner, text="Velocidad", bg=PANEL, fg=MUTED,
                 font=(UI, 10, "bold")).pack(side="left", padx=(26, 8))
        ttk.Scale(inner, from_=0.25, to=3.0, variable=self.speed,
                  orient="horizontal", length=150).pack(side="left")
        self.lbl_speed = tk.Label(inner, text="1.00x", bg=PANEL, fg=TEXT,
                                  font=(MONO, 11, "bold"), width=6)
        self.lbl_speed.pack(side="left", padx=(10, 0))
        self.speed.trace_add("write",
                             lambda *a: self.lbl_speed.config(text="%.2fx" % self.speed.get()))

    def _keys(self):
        self.bind("<space>", lambda e: self.toggle_play())
        self.bind("<Right>", lambda e: self.siguiente())
        self.bind("<Left>", lambda e: self.anterior())
        self.bind("<r>", lambda e: self.reiniciar())
        self.bind("<R>", lambda e: self.reiniciar())

    # ------------------------------------------------------------------ datos
    def leer_config(self):
        proto, transporte, dport, recurso = PROTOCOLS[self.cb_proto.get()]
        try:
            ttl = max(1, min(255, int(self.e_ttl.get())))
        except ValueError:
            ttl = 64
        msg = self.txt_msg.get("1.0", "end-1c").strip() or "Mensaje de prueba"
        medio = self.cb_medio.get()
        return {"mensaje": msg, "proto": proto, "transporte": transporte, "dport": dport,
                "recurso": recurso, "codec": self.cb_codec.get(), "modo": self.cb_modo.get(),
                "src_ip": self.e_sip.get(), "dst_ip": self.e_dip.get(),
                "src_mac": self.e_smac.get(), "dst_mac": self.e_dmac.get(),
                "ttl": ttl, "medio": medio, "velocidad": VELOCIDAD.get(medio, "1 Gbps")}

    def aleatorio(self):
        rip = lambda: "%d.%d.%d.%d" % (random.choice([10, 172, 192]), random.randint(0, 255),
                                       random.randint(0, 255), random.randint(1, 254))
        rmac = lambda: ":".join("%02X" % random.randint(0, 255) for _ in range(6))
        for e, v in ((self.e_sip, rip()), (self.e_dip, rip()), (self.e_smac, rmac()),
                     (self.e_dmac, rmac()), (self.e_ttl, str(random.choice([32, 64, 128, 255])))):
            e.delete(0, "end")
            e.insert(0, v)
        self.cb_proto.current(random.randrange(len(PROTOCOLS)))
        self.cb_medio.current(random.randrange(len(MEDIOS)))
        self.txt_msg.delete("1.0", "end")
        self.txt_msg.insert("1.0", random.choice([
            "Hola, este es un mensaje de prueba.",
            "Transferencia de datos entre dos hosts.",
            "Solicitud de pagina web al servidor remoto.",
            "Consulta DNS del dominio www.ejemplo.com",
        ]))
        self.reiniciar(rebuild=True)

    def _pasos(self):
        s = [{"kind": "tx", "layer": i} for i in range(7)]
        s.append({"kind": "medium", "layer": 6})
        s += [{"kind": "rx", "layer": i} for i in range(6, -1, -1)]
        s.append({"kind": "done", "layer": 0})
        return s

    # ------------------------------------------------------------- reproduccion
    def transmitir(self):
        """Envia el mensaje del emisor al receptor a traves del modelo OSI.

        Resume el ciclo completo de la comunicacion:
          1. Lee la configuracion actual (mensaje, protocolo, IP, MAC, TTL...).
          2. Encapsula: construye los 7 PDU, de la capa 7 a la capa 1, anadiendo
             en cada una su cabecera (y la cola FCS en la capa de enlace).
          3. Prepara los 16 pasos del recorrido: 7 de encapsulamiento en el
             emisor, 1 de transmision por el medio fisico, 7 de
             desencapsulamiento en el receptor y la entrega final.
          4. Reproduce la animacion desde el primer paso.

        Devuelve el OSIModel generado, por si se quiere consultar el PDU de
        cualquier capa sin pasar por la interfaz.
        """
        self.pause()                                 # corta una animacion previa
        self.model = OSIModel(self.leer_config())    # encapsulamiento (capas 7 -> 1)
        self.steps = self._pasos()                   # recorrido emisor -> receptor
        self.step, self.t = 0, 0.0
        self.redraw()
        self.play()                                  # arranca la reproduccion
        return self.model

    def reiniciar(self, rebuild=False):
        self.pause()
        if rebuild or self.model is None:
            self.model = OSIModel(self.leer_config())
        self.steps = self._pasos()
        self.step, self.t = 0, 0.0
        self.redraw()

    def toggle_play(self):
        self.pause() if self.playing else self.play()

    def play(self):
        if self.step >= len(self.steps) - 1 and self.t >= 1.0:
            self.step, self.t = 0, 0.0
        self.playing = True
        self.btn_play.set_text("❘❘  PAUSAR")
        self.btn_play.set_color(WARN)
        self._tick()

    def pause(self):
        self.playing = False
        if self._job:
            self.after_cancel(self._job)
            self._job = None
        self.btn_play.set_text("▶  REPRODUCIR")
        self.btn_play.set_color(ACCENT)

    def _tick(self):
        if not self.playing:
            return
        dur = 1000.0 / max(0.1, self.speed.get())
        if self.steps[self.step]["kind"] == "medium":
            dur *= 1.6
        self.t += 33.0 / dur
        if self.t >= 1.0:
            if self.step < len(self.steps) - 1:
                self.step += 1
                self.t = 0.0
            else:
                self.t = 1.0
                self.pause()
        self.redraw()
        if self.playing:
            self._job = self.after(33, self._tick)

    def siguiente(self):
        self.pause()
        if self.step < len(self.steps) - 1:
            self.step += 1
            self.t = 1.0
            self.redraw()

    def anterior(self):
        self.pause()
        if self.step > 0:
            self.step -= 1
            self.t = 1.0
            self.redraw()

    # ------------------------------------------------------------------ dibujo
    def geo(self):
        w = max(self.cv.winfo_width(), 560)
        h = max(self.cv.winfo_height(), 420)
        pad = 16
        col_w = min(198, max(156, (w - 2 * pad) * 0.25))
        top = 44
        med_h = 70
        rows = h - top - med_h - 10
        return dict(w=w, h=h, pad=pad, col_w=col_w, top=top, row_h=rows / 7.0,
                    lx=pad, rx=w - pad - col_w, cx=w / 2.0,
                    med_y=top + rows + med_h / 2.0 - 12)

    def row_y(self, g, i):
        return g["top"] + i * g["row_h"] + g["row_h"] / 2.0

    @staticmethod
    def ease(t):
        return t * t * (3 - 2 * t)

    def pos(self, g):
        st = self.steps[self.step]
        k, i, e = st["kind"], st["layer"], self.ease(self.t)
        if k == "tx":
            # En la capa 7 el PDU nace en su fila: no debe salirse por arriba
            y0 = self.row_y(g, i - 1) if i > 0 else self.row_y(g, 0)
            return g["cx"], y0 + (self.row_y(g, i) - y0) * e
        if k == "medium":
            lcx, rcx = g["lx"] + g["col_w"] / 2, g["rx"] + g["col_w"] / 2
            pts = [(g["cx"], self.row_y(g, 6)), (lcx, g["med_y"]),
                   (rcx, g["med_y"]), (g["cx"], self.row_y(g, 6))]
            return self._along(pts, e)
        if k == "rx":
            y0 = self.row_y(g, i + 1) if i < 6 else self.row_y(g, 6)
            return g["cx"], y0 + (self.row_y(g, i) - y0) * e
        return g["cx"], self.row_y(g, 0)

    @staticmethod
    def _along(pts, t):
        segs, total = [], 0.0
        for a, b in zip(pts, pts[1:]):
            d = ((b[0] - a[0]) ** 2 + (b[1] - a[1]) ** 2) ** 0.5
            segs.append((a, b, d))
            total += d
        if total <= 0:
            return pts[0]
        target, acc = t * total, 0.0
        for a, b, d in segs:
            if acc + d >= target or d == 0:
                u = 0 if d == 0 else (target - acc) / d
                return a[0] + (b[0] - a[0]) * u, a[1] + (b[1] - a[1]) * u
            acc += d
        return pts[-1]

    def redraw(self):
        if not self.model:
            return
        cv = self.cv
        cv.delete("all")
        g = self.geo()
        st = self.steps[self.step]
        kind, li = st["kind"], st["layer"]

        # El rotulo de la operacion vive en la barra superior: aqui solo van
        # los titulos de cada pila, para no chocar con el PDU de la capa 7.
        cv.create_text(g["lx"] + g["col_w"] / 2, 17, text="EMISOR",
                       fill=SOFT, font=(UI, 12, "bold"))
        cv.create_text(g["rx"] + g["col_w"] / 2, 17, text="RECEPTOR",
                       fill=SOFT, font=(UI, 12, "bold"))

        for i, L in enumerate(LAYERS):
            y = g["top"] + i * g["row_h"]
            hh = g["row_h"] - 8
            atx = (kind == "tx" and i == li)
            arx = (kind in ("rx", "done") and i == li)
            med = (kind == "medium")
            self._box(cv, g["lx"], y, g["col_w"], hh, L, atx or (med and i == 6),
                      (kind == "tx" and i < li) or kind in ("medium", "rx", "done"))
            self._box(cv, g["rx"], y, g["col_w"], hh, L, arx or (med and i == 6),
                      (kind in ("rx", "done") and i > li) or kind == "done")

        self._medio(cv, g, kind)
        self._pdu(cv, g, kind, li)
        self._progreso(cv, g)
        self._lateral(kind, li)
        self._mensaje(kind, li)

    def _box(self, cv, x, y, w, h, L, activo, hecho):
        round_rect(cv, x, y, x + w, y + h, 8, fill=SEL if activo else CARD,
                   outline=L["color"] if activo else STROKE, width=2 if activo else 1)
        cy = y + h / 2
        r = 15
        cv.create_oval(x + 10, cy - r, x + 10 + 2 * r, cy + r,
                       fill=L["color"] if (activo or hecho) else CARD2,
                       outline=STROKE if not (activo or hecho) else "")
        cv.create_text(x + 10 + r, cy, text=str(L["n"]),
                       fill=ON_DARK if (activo or hecho) else MUTED,
                       font=(UI, 12, "bold"))
        cv.create_text(x + 44, cy - 10, anchor="w", text=L["name"],
                       fill=TEXT if (activo or hecho) else MUTED, font=(UI, 11, "bold"))
        cv.create_text(x + 44, cy + 10, anchor="w", text=L["pdu"].upper(),
                       fill=L["color"] if activo else MUTED, font=(UI, 9, "bold"))
        if hecho and not activo:
            cv.create_text(x + w - 10, cy, anchor="e", text="✓", fill=OK,
                           font=(UI, 13, "bold"))

    def _medio(self, cv, g, kind):
        y = g["med_y"]
        x1 = g["lx"] + g["col_w"] / 2
        x2 = g["rx"] + g["col_w"] / 2
        on = (kind == "medium")
        cv.create_line(x1, y, x2, y, fill=WARN if on else STROKE, width=6, capstyle="round")
        for k in range(int(x1) + 16, int(x2) - 12, 24):
            cv.create_oval(k - 3, y - 3, k + 3, y + 3, fill=WARN if on else STROKE, outline="")
        cv.create_text(g["cx"], y + 26,
                       text="MEDIO FISICO   %s   -   %s" % (self.model.cfg["medio"],
                                                            self.model.cfg["velocidad"]),
                       fill=WARN if on else MUTED, font=(UI, 10, "bold"))

    def _pdu(self, cv, g, kind, li):
        if kind == "done":
            cx, cy = g["cx"], self.row_y(g, 1)
            round_rect(cv, cx - 118, cy - 42, cx + 118, cy + 42, 8,
                       fill=PANEL, outline=OK, width=2)
            cv.create_text(cx, cy - 13, text="✓", fill=OK, font=(UI, 26, "bold"))
            cv.create_text(cx, cy + 20, text="MENSAJE ENTREGADO", fill=OK,
                           font=(UI, 11, "bold"))
            return
        parts = self.model.stages[li]
        px, py = self.pos(g)
        max_w = max(220, (g["rx"] - (g["lx"] + g["col_w"])) - 30)

        grow = 1.0
        if kind == "tx" and li != 6:
            grow = self.ease(self.t)
        elif kind == "rx" and li != 6:
            grow = 1.0 - self.ease(self.t)

        anchos, nuevos = [], []
        for p in parts:
            base = max(46.0, min(104.0, 30 + len(p["data"]) * 0.9))
            nuevo = (p["kind"] != "data" and p["color"] == LAYERS[li]["color"] and li < 6)
            nuevos.append(nuevo)
            anchos.append(base * (grow if nuevo else 1.0))
        total = sum(anchos) or 1
        k = min(1.0, (max_w - 10) / total)
        anchos = [a * k for a in anchos]
        total = sum(anchos)

        h = 58
        x = px - total / 2
        top = py - h / 2

        if kind == "medium" or li == 6:
            self._bits(cv, x, top, total, h)
        else:
            for p, aw in zip(parts, anchos):
                if aw < 1.5:
                    continue
                dato = (p["kind"] == "data")
                col = DATA_C if dato else p["color"]
                tinta = TEXT if dato else ON_DARK
                round_rect(cv, x, top, x + aw, top + h, 5, fill=col,
                           outline=BG, width=2)
                if aw > 30:
                    cv.create_text(x + aw / 2, top + h / 2 - 9, text=p["tag"],
                                   fill=tinta, font=(UI, 10, "bold"))
                    cv.create_text(x + aw / 2, top + h / 2 + 10, text="%d B" % len(p["data"]),
                                   fill=tinta, font=(MONO, 9, "bold"))
                elif aw > 14:
                    cv.create_text(x + aw / 2, top + h / 2, text=p["tag"][:3],
                                   fill=tinta, font=(UI, 8, "bold"))
                x += aw

        etq = "Bits en transito" if kind == "medium" else LAYERS[li]["pdu"]
        cv.create_text(px, top - 18, text="%s  -  %d bytes" % (etq, self.model.total_bytes(li)),
                       fill=TEXT, font=(UI, 12, "bold"))
        if kind in ("tx", "rx") and li < 6:
            cv.create_text(px, top + h + 18,
                           text=("+ se anade la cabecera %s" if kind == "tx"
                                 else "- se retira la cabecera %s") % LAYERS[li]["tag"],
                           fill=LAYERS[li]["color"], font=(UI, 10, "bold"))

    def _bits(self, cv, x, top, total, h):
        raw = self.model.raw(6)
        bits = "".join("{:08b}".format(b) for b in raw[:96])
        n = max(20, int(total / 8.2))
        off = int(self.t * 48)
        shown = (bits * 3)[off:off + n]
        round_rect(cv, x, top, x + total, top + h, 5, fill=PANEL,
                   outline=LAYERS[6]["color"], width=2)
        cv.create_text(x + total / 2, top + h / 2 - 10, text=shown,
                       fill=LAYERS[6]["color"], font=(MONO, 11, "bold"))
        cv.create_text(x + total / 2, top + h / 2 + 12, text="┐└" * 12,
                       fill=MUTED, font=(MONO, 10))

    def _progreso(self, cv, g):
        n = len(self.steps)
        w = g["w"] - 2 * g["pad"]
        y = g["h"] - 7
        cv.create_line(g["pad"], y, g["pad"] + w, y, fill=STROKE, width=5, capstyle="round")
        p = max(0.0, min(1.0, (self.step + self.t) / max(1, n - 1)))
        if p > 0.001:
            cv.create_line(g["pad"], y, g["pad"] + w * p, y, fill=ACCENT, width=5,
                           capstyle="round")

    # -------------------------------------------------- panel de contenido/mensaje
    def _mensaje(self, kind, li):
        cv = self.cvm
        cv.delete("all")
        W = max(cv.winfo_width(), 520)
        H = max(cv.winfo_height(), 150)
        parts = self.model.stages[li]
        pad, sep = 2, 5

        grow = 1.0
        if kind == "tx" and li != 6:
            grow = self.ease(self.t)
        elif kind == "rx" and li != 6:
            grow = 1.0 - self.ease(self.t)
        if kind == "done":
            grow = 0.0

        wrappers = [p for p in parts if p["kind"] != "data"]
        datap = next(p for p in parts if p["kind"] == "data")

        # Cada cabecera tiene un ancho comodo; el mensaje se queda con el resto
        util = W - 2 * pad - sep * len(parts)
        n = max(1, len(wrappers))
        base = min(172.0, max(84.0, (util - 300.0) / n))
        anchos = {}
        for p in wrappers:
            nuevo = (p["color"] == LAYERS[li]["color"] and li < 6) or kind == "done"
            anchos[id(p)] = base * (grow if nuevo else 1.0)
        msg_w = max(270.0, min(util - sum(anchos.values()), 660.0))

        total = sum(anchos.values()) + msg_w + sep * len(parts)
        x = max(pad, (W - total) / 2.0)
        y0, y1 = 4, H - 6
        for p in parts:
            if p["kind"] == "data":
                self._bloque_mensaje(cv, x, y0, msg_w, y1, datap, kind, li)
                x += msg_w + sep
            else:
                aw = anchos.get(id(p), 0.0)
                if aw > 3:
                    self._bloque_hdr(cv, x, y0, aw, y1, p)
                x += aw + sep

        # pie informativo
        texto, cod = legible(datap["data"])
        if kind == "done":
            self.lbl_msg_info.config(
                text="El receptor recupero el mensaje original intacto", fg=OK)
        elif kind == "medium":
            self.lbl_msg_info.config(
                text="La trama completa viaja como bits por el medio", fg=WARN)
        else:
            self.lbl_msg_info.config(
                text="Capa %d  -  %s  -  %d bytes en total"
                     % (LAYERS[li]["n"], LAYERS[li]["pdu"], self.model.total_bytes(li)),
                fg=MUTED)

    def _ancho_char(self, familia, tam, negrita=False):
        clave = (familia, tam, negrita)
        if clave not in self._medidas:
            f = tkfont.Font(family=familia, size=tam,
                            weight="bold" if negrita else "normal")
            muestra = "abcdefghijklmnopqrstuvwxyz0123456789 "
            self._medidas[clave] = max(4.0, f.measure(muestra) / len(muestra) * 1.08)
        return self._medidas[clave]

    def _bloque_hdr(self, cv, x, y0, w, y1, p):
        col = p["color"]
        round_rect(cv, x, y0, x + w, y1, 6, fill=CARD, outline=col, width=2)
        round_rect(cv, x, y0, x + w, y0 + 25, 6, fill=col, outline="")
        cv.create_rectangle(x, y0 + 15, x + w, y0 + 25, fill=col, outline="")
        cv.create_text(x + w / 2, y0 + 12, text=p["tag"], fill=ON_DARK,
                       font=(UI, 11, "bold"))
        cv.create_text(x + w / 2, y0 + 38, text="%d B" % len(p["data"]),
                       fill=col, font=(MONO, 9, "bold"))
        if w < 50:
            return
        ancho_chars = max(7, int((w - 12) / self._ancho_char(MONO, 8)))
        lineas = []
        for bloque in p["show"].split("\n"):
            lineas += textwrap.wrap(bloque, ancho_chars) or [""]
        yy = y0 + 56
        for ln in lineas[:8]:
            if yy > y1 - 8:
                break
            cv.create_text(x + w / 2, yy, text=ln, fill=SOFT, font=(MONO, 8))
            yy += 13

    def _bloque_mensaje(self, cv, x, y0, w, y1, p, kind, li):
        recuperado = (kind == "done") or (kind == "rx" and li <= 1)
        borde = OK if recuperado else "#4a5566"
        round_rect(cv, x, y0, x + w, y1, 6, fill=PANEL, outline=borde, width=3)
        round_rect(cv, x, y0, x + w, y0 + 25, 6, fill=borde, outline="")
        cv.create_rectangle(x, y0 + 15, x + w, y0 + 25, fill=borde, outline="")
        cv.create_text(x + w / 2, y0 + 12,
                       text="MENSAJE" + ("   ✓ RECUPERADO" if recuperado else ""),
                       fill=ON_DARK, font=(UI, 11, "bold"))

        texto, plano = legible(p["data"])
        cv.create_text(x + w / 2, y0 + 39,
                       text=("texto plano" if plano else "codificado / cifrado") +
                            "   -   %d bytes" % len(p["data"]),
                       fill=MUTED if plano else "#8a3b3b", font=(MONO, 9, "bold"))

        fuente = (UI, 13, "bold") if plano else (MONO, 10)
        ancho_chars = max(10, int((w - 26) / (self._ancho_char(UI, 13, True) if plano
                                              else self._ancho_char(MONO, 10))))
        lineas = textwrap.wrap(texto, ancho_chars)[:5] or ["(vacio)"]
        alto = 21 if plano else 16
        zona0, zona1 = y0 + 52, y1 - (26 if not plano else 8)
        yy = max(y0 + 58, (zona0 + zona1) / 2 - (len(lineas) * alto) / 2 + alto / 2)
        for ln in lineas:
            if yy > y1 - (24 if not plano else 10):
                break
            cv.create_text(x + w / 2, yy, text=ln, fill=TEXT if plano else "#8a3b3b",
                           font=fuente)
            yy += alto

        if not plano:
            cv.create_text(x + w / 2, y1 - 13,
                           text="original:  " + self.model.mensaje[:36],
                           fill=MUTED, font=(UI, 9, "italic"))

    # ------------------------------------------------------------- panel derecho
    def _lateral(self, kind, li):
        L = LAYERS[li]
        if kind == "tx":
            etq, col = "ENCAPSULANDO", ACCENT
            desc = (L["role"] + "\n\nSe anade la cabecera " + L["tag"] +
                    " al PDU que llega de la capa superior y el resultado baja a la capa inferior.")
            if li == 6:
                desc = L["role"] + "\n\nLa trama completa se convierte en una secuencia de bits y se codifica como senal."
        elif kind == "medium":
            etq, col = "TRANSMITIENDO", WARN
            desc = ("Los bits viajan por %s a %s. Los switches leen la cabecera Ethernet y "
                    "los routers la cabecera IP para decidir el reenvio."
                    % (self.model.cfg["medio"], self.model.cfg["velocidad"]))
        elif kind == "rx":
            etq, col = "DESENCAPSULANDO", OK
            desc = (L["role"] + "\n\nSe lee y se retira la cabecera " + L["tag"] +
                    "; la carga util resultante sube a la capa superior.")
            if li == 6:
                desc = L["role"] + "\n\nLa senal recibida se reconstruye como bits y se entrega a la capa de enlace."
        else:
            etq, col = "COMPLETADO", OK
            desc = ("El mensaje original fue reconstruido integramente y entregado a la "
                    "aplicacion del receptor.")

        self.badge.config(text=" %s   paso %d de %d " % (etq, self.step + 1, len(self.steps)),
                          bg=col, fg=ON_DARK)
        self.lbl_capa.config(text="Capa %d  -  %s" % (L["n"], L["name"]), fg=L["color"])
        self.lbl_desc.config(text=desc)
        self.lbl_estado.config(
            text="%s   ·   paso %d de %d   ·   %d bytes"
                 % (etq, self.step + 1, len(self.steps), self.model.total_bytes(li)), fg=col)
        self._tabla(self.model.fields[li], L["color"])
        self._hex(li)

    def _tabla(self, fields, color):
        t = self.tbl
        t.delete("all")
        w = max(t.winfo_width(), 340)
        h = max(t.winfo_height(), 120)
        rh = max(22, min(32, (h - 6) / max(1, len(fields[:9]))))
        y = 2
        for i, (k, v) in enumerate(fields[:9]):
            if i % 2 == 0:
                round_rect(t, 0, y, w, y + rh - 4, 6, fill=CARD, outline="")
            t.create_text(10, y + rh / 2 - 2, anchor="w", text=k, fill=MUTED, font=(UI, 10))
            t.create_text(w - 10, y + rh / 2 - 2, anchor="e", text=str(v),
                          fill=color if i == len(fields[:9]) - 1 else TEXT,
                          font=(MONO, 10, "bold"))
            y += rh

    def _hex(self, li):
        parts = self.model.stages[li]
        self.hex.config(state="normal")
        self.hex.delete("1.0", "end")
        flat = []
        for i, p in enumerate(parts):
            tag = "c%d" % i
            self.hex.tag_config(tag, foreground=p["color"] if p["kind"] != "data" else TEXT)
            flat += [(b, tag) for b in p["data"]]
        self.hex.tag_config("off", foreground=MUTED)
        self.hex.tag_config("asc", foreground=MUTED)

        lim = 384
        for off in range(0, min(len(flat), lim), 12):
            fila = flat[off:off + 12]
            self.hex.insert("end", "%04X  " % off, "off")
            for b, tag in fila:
                self.hex.insert("end", "%02X " % b, tag)
            self.hex.insert("end", "   " * (12 - len(fila)) + "  ", "off")
            self.hex.insert("end", "".join(chr(b) if 32 <= b < 127 else "."
                                           for b, _ in fila) + "\n", "asc")
        if len(flat) > lim:
            self.hex.insert("end", "\n... %d bytes mas\n" % (len(flat) - lim), "off")
        self.hex.insert("end", "\n")
        for i, p in enumerate(parts):
            self.hex.insert("end", "  %-26s %4d B\n" % (p["label"][:26], len(p["data"])),
                            "c%d" % i)
        self.hex.config(state="disabled")
        self.lbl_size.config(text="%d bytes" % len(flat))


if __name__ == "__main__":
    OSISimulator().mainloop()


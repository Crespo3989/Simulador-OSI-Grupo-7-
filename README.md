# Simulador OSI

Simulador interactivo de **encapsulamiento y desencapsulamiento de datos** a través de las 7 capas del modelo de referencia **OSI**, escrito en Python 3 con Tkinter.

A diferencia de una animación puramente ilustrativa, el simulador **construye cabeceras binarias reales** en cada capa (Ethernet II, IPv4, TCP/UDP), calcula sus checksums y su CRC-32 exactamente igual que una pila de red real, y permite inspeccionar el resultado en hexadecimal, byte a byte.

## Vista previa

> Ejecuta `python simulador_osi.py` para ver la animación en tiempo real: la pila del emisor encapsulando el mensaje, el tránsito por el medio físico y la pila del receptor desencapsulándolo.

## Características

- **Encapsulamiento real, no simulado**: cabecera Ethernet II (14 B) + FCS/CRC-32 (4 B), cabecera IPv4 (20 B) con checksum RFC 1071, cabecera TCP (20 B) o UDP (8 B) con pseudo-cabecera incluida en el checksum.
- **7 protocolos de aplicación**: HTTP, HTTPS, FTP, SMTP, SSH (TCP) y DNS, DHCP (UDP), cada uno con su puerto y payload de ejemplo.
- **4 codificaciones de capa de presentación**: UTF-8 plano, Base64, cifrado XOR y compresión zlib.
- **Configuración completa**: mensaje, IP/MAC origen y destino, TTL, medio físico (UTP, fibra, Wi-Fi, coaxial) con su velocidad nominal.
- **Animación controlable**: reproducir/pausar, paso a paso (adelante/atrás), reiniciar, control de velocidad (0.25×–3.00×).
- **Panel de detalle por capa**: tabla de campos reales de la cabecera (puertos, checksum, TTL, secuencia, etc.) y volcado hexadecimal con colores por capa.
- **Panel de contenido del PDU**: muestra el mensaje en texto plano o, si está codificado/cifrado, en hexadecimal con indicador visual.
- **Datos aleatorios**: genera IPs, MACs, TTL, protocolo, medio y mensaje de ejemplo con un clic.

## Requisitos

- Python 3.8 o superior (probado con 3.13)
- Tkinter (incluido en la distribución estándar de Python en Windows y macOS; en Linux instalar `python3-tk` si no está presente)
- Sin dependencias externas solo usa módulos de la librería estándar: `base64`, `random`, `struct`, `textwrap`, `zlib`, `tkinter`

## Instalación y ejecución

```bash
git clone https://github.com/Crespo3989/Simulador-OSI-Grupo-7-.git
cd Simulador-OSI-Grupo-7-
python simulador_osi.py
```

En Linux, si falta Tkinter:

```bash
sudo apt install python3-tk
```

## Atajos de teclado

| Tecla | Acción |
|---|---|
| `Espacio` | Reproducir / pausar |
| `→` | Avanzar un paso |
| `←` | Retroceder un paso |
| `R` | Reiniciar |

## Cómo usarlo

1. Escribe un mensaje en el panel izquierdo (**Configuración**).
2. Elige el protocolo de aplicación, la codificación de capa 6, el modo de diálogo de capa 5, direcciones IP/MAC, TTL y medio físico.
3. Pulsa **TRANSMITIR MENSAJE**.
4. Observa cómo el mensaje se encapsula capa por capa en el emisor, viaja por el medio físico y se desencapsula en el receptor.
5. Usa el panel derecho para inspeccionar los campos reales de cada cabecera y el volcado hexadecimal completo del PDU en cada paso.

## Arquitectura del código

El proyecto vive en un único archivo, organizado en cuatro bloques:

| Bloque | Contenido |
|---|---|
| Configuración | `LAYERS`, `PROTOCOLS`, `CODECS`, `MEDIOS` — tablas de datos de las capas y protocolos soportados |
| Construcción binaria | `ip_to_bytes`, `mac_to_bytes`, `inet_checksum`, `build_tcp`, `build_udp`, `build_ip` — cabeceras reales byte a byte |
| Modelo de dominio | `OSIModel` — encapsula el mensaje en las 7 capas y expone `stages`, `fields`, `total_bytes()`, `raw()` |
| Interfaz gráfica | `OSISimulator` (Tkinter) — configuración, animación, panel de detalle y panel de contenido del PDU |

## Limitaciones conocidas

- Es una simulación local dentro de un mismo proceso: no envía tráfico por una red real ni usa sockets.
- El cifrado XOR es exclusivamente didáctico, no es un mecanismo de seguridad real.
- No simula pérdida de paquetes, fragmentación, retransmisión ni control de congestión.



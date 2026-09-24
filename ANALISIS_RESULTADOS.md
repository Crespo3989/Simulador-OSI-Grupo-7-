# Análisis de Resultados — Simulador OSI

Datos obtenidos ejecutando directamente el motor de cálculo del simulador (`OSIModel`), sin la interfaz gráfica, para obtener cifras exactas de bytes por capa.

## 1. Objetivo del análisis

Este documento cuantifica, con cifras exactas obtenidas directamente del motor de datos del simulador (la clase `OSIModel`), el comportamiento del proceso de encapsulamiento OSI ante distintas configuraciones: protocolo de aplicación, codificación de la capa de presentación y tamaño del mensaje original. El propósito es verificar que el simulador reproduce fielmente las reglas de cada protocolo y extraer conclusiones pedagógicas sobre el costo ("overhead") de las cabeceras.

## 2. Metodología

Se ejecutó la clase `OSIModel` —el mismo código que usa la interfaz gráfica— de forma directa, sin la ventana de Tkinter, variando un parámetro a la vez y manteniendo el resto constante en la configuración base:

| Parámetro base | Valor |
|---|---|
| Mensaje | "Hola, este es un mensaje de prueba." (35 bytes en UTF-8) |
| Protocolo | HTTP (TCP, puerto 80) |
| Codificación (capa 6) | UTF-8 (texto plano) |
| IP origen / destino | 192.168.1.10 / 142.250.78.14 |
| TTL | 64 |
| Medio físico | Par trenzado UTP Cat6 (1 Gbps) |

> Para cada corrida se registró el número de bytes acumulados en cada una de las 7 capas mediante el método `total_bytes(i)`, que suma la longitud real de todas las cabeceras y datos presentes en esa etapa.

## 3. Escenario base: crecimiento del PDU capa por capa

| Capa | Nombre | PDU | Bytes acumulados | Incremento |
|---|---|---|---|---|
| 7 | Aplicación | Datos | 112 | +112 |
| 6 | Presentación | Datos | 141 | +29 |
| 5 | Sesión | Datos | 174 | +33 |
| 4 | Transporte | Segmento | 194 | +20 |
| 3 | Red | Paquete | 214 | +20 |
| 2 | Enlace | Trama | 232 | +18 |
| 1 | Física | Bits | 232 | +0 |

### 3.1 Lectura de resultados

- El mayor incremento aislado ocurre al pasar a la capa 7 (+112 B), pero esa cifra ya incluye el mensaje mismo (35 B) más la cabecera de aplicación (AH, 77 B: la línea de petición HTTP y el encabezado Host).
- Los incrementos de las capas 4 (+20 B) y 3 (+20 B) coinciden exactamente con el tamaño estándar de las cabeceras TCP (20 bytes) e IPv4 sin opciones (20 bytes), confirmando que el simulador construye cabeceras de tamaño real y no simulado.
- El incremento de la capa 2 (+18 B) corresponde a 14 bytes de cabecera Ethernet II (MAC destino + MAC origen + EtherType) más 4 bytes de FCS (CRC-32), es decir, 18 bytes exactos según el estándar IEEE 802.3.
- La capa física no agrega bytes (+0): solo convierte la misma trama en una representación de bits, coherente con que la capa 1 no añade una cabecera propia.
- El mensaje original de 35 bytes termina viajando dentro de una trama de 232 bytes: un sobrecosto (overhead) de 197 bytes, equivalente al **562.9%** del tamaño original.

## 4. Comparativa de codificaciones de la capa de presentación

| Codificación | Datos codificados | Cabecera PH | Trama final | Overhead |
|---|---|---|---|---|
| UTF-8 (texto plano) | 35 B | 29 B | 232 B | 562.9% |
| Base64 | 48 B | 16 B | 232 B | 562.9% |
| Cifrado XOR (0x5A) | 35 B | 21 B | 224 B | 540.0% |
| UTF-8 + compresión (zlib-9) | 41 B | 28 B | 237 B | 577.1% |

### 4.1 Hallazgos

- **Base64** expande los datos de 35 a 48 bytes (+37%, coherente con la relación teórica 4/3 de esta codificación), pero la trama final resulta **idéntica** a la del texto plano (232 B), porque la cabecera de presentación embebe literalmente el nombre de la codificación (`PH|codec=Base64|`), que es más corta que `PH|codec=UTF-8 (texto plano)|`; el ahorro en la cabecera compensa casi exactamente la expansión de los datos.
- El **cifrado XOR** no cambia el tamaño de los datos (35 B en ambos casos, por ser una operación byte a byte), resultando en la trama más liviana de las cuatro (224 B): confirma que XOR aporta "ofuscación" sin costo de tamaño, a diferencia de un cifrado con relleno (padding) como AES en modo bloque.
- La **compresión** (zlib nivel 9) es la única codificación que empeora el resultado (41 B en lugar de 35 B, un 17% más grande): para mensajes cortos, la cabecera y el checksum propios del formato DEFLATE/zlib pesan más que la redundancia que logran eliminar. Es un resultado esperado y pedagógicamente valioso: la compresión solo es rentable a partir de cierto tamaño de mensaje.

## 5. Comparativa de protocolos de aplicación (TCP vs. UDP)

| Protocolo | Transporte | Puerto | Trama final | Overhead |
|---|---|---|---|---|
| HTTP | TCP | 80 | 232 B | 562.9% |
| HTTPS | TCP | 443 | 228 B | 551.4% |
| SMTP | TCP | 25 | 227 B | 548.6% |
| SSH | TCP | 22 | 227 B | 548.6% |
| FTP | TCP | 21 | 224 B | 540.0% |
| DNS | UDP | 53 | 219 B | 525.7% |
| DHCP | UDP | 67 | 208 B | 494.3% |

### 5.1 Hallazgos

- Los dos protocolos basados en **UDP** (DNS y DHCP) producen las tramas más livianas del conjunto, porque la cabecera UDP (8 B) es 12 bytes más pequeña que la cabecera TCP (20 B): TCP necesita ese espacio adicional para el número de secuencia, el número de acuse y los flags que sostienen una conexión orientada a confirmación, que UDP no ofrece.
- Entre los protocolos TCP, las diferencias restantes (232 a 224 B) se explican por la longitud del payload de ejemplo de la capa de aplicación: `GET /index.html HTTP/1.1` (HTTP) es más largo que `RETR informe.pdf` (FTP), por ejemplo.
- **DHCP** resulta el más liviano de todos (208 B) por combinar transporte UDP con el payload de ejemplo más corto (`DHCPDISCOVER`), consistente con su uso real como protocolo de arranque de red de bajo overhead.

## 6. Efecto del tamaño del mensaje sobre el overhead relativo

| Mensaje original | Trama final | Bytes agregados | Overhead relativo |
|---|---|---|---|
| 4 B | 201 B | 197 B | 4925.0% |
| 35 B | 232 B | 197 B | 562.9% |
| 141 B | 338 B | 197 B | 139.7% |

### 6.1 Hallazgos

- El número de bytes agregados por las cabeceras (**197 B**) permanece exactamente constante en los tres casos, porque ninguna cabecera de este escenario incluye el tamaño del mensaje como texto variable: todas son campos de longitud fija o cadenas fijas (ruta HTTP, host, nombre de codificación, ID de sesión, puertos, TTL, MACs).
- Como el overhead absoluto es constante, el overhead relativo cae drásticamente al crecer el mensaje: de 4925% con un mensaje de 4 bytes a 139.7% con uno de 141 bytes. Este resultado reproduce un principio real de las redes de datos: los paquetes pequeños son proporcionalmente mucho más costosos de transmitir que los paquetes grandes, motivo por el cual protocolos reales agrupan datos (por ejemplo, el algoritmo de Nagle en TCP o el uso de tramas jumbo) para amortizar el costo fijo de las cabeceras.

## 7. Verificación de integridad (checksum y CRC)

Se verificó que los mecanismos de detección de errores calculados por el simulador sean matemáticamente correctos y no solo decorativos, recalculando de forma independiente el CRC-32 de la trama Ethernet del escenario base:

| Verificación | Resultado |
|---|---|
| Tamaño de la trama (capa 2, incluye FCS) | 232 bytes |
| FCS embebido al final de la trama | Coincide byte a byte con el CRC-32 calculado de forma independiente sobre el resto de la trama (Ethernet + IP + TCP + datos) |
| Checksum de la cabecera IPv4 | Calculado con el algoritmo estándar de complemento a uno de 16 bits (RFC 1071) |
| Checksum de la cabecera TCP | Calculado incluyendo la pseudo-cabecera IP exigida por el estándar (IP origen, IP destino, protocolo y longitud) |

> La verificación se realizó recalculando el CRC-32 de forma externa a la clase `OSIModel` (con `zlib.crc32`) y comparando el resultado, byte a byte, contra los 4 bytes de FCS que el propio modelo agrega al final de la trama. El resultado coincidió exactamente, confirmando que el simulador no solo "dibuja" un checksum simbólico, sino que aplica el algoritmo real sobre los bytes reales del paquete.

## 8. Conclusiones

- El simulador reproduce con exactitud aritmética el tamaño de las cabeceras estándar de Ethernet II (14 B), IPv4 (20 B), TCP (20 B) y UDP (8 B), lo que permite usarlo como herramienta confiable para calcular overhead real, no solo como animación conceptual.
- El costo de encapsulamiento es en gran medida fijo (bytes constantes) y no proporcional al mensaje, por lo que su impacto relativo depende fuertemente del tamaño del payload: a mayor mensaje, menor overhead porcentual.
- La elección de protocolo de transporte (TCP vs. UDP) es la variable que más impacta el tamaño final de la trama entre las opciones exploradas, más que la elección de codificación de presentación.
- Las técnicas de la capa de presentación (Base64, XOR, compresión) tienen efectos medibles y a veces contraintuitivos —como que comprimir un mensaje corto lo agrande—, lo que confirma su valor didáctico para discutir cuándo conviene aplicar cada técnica.
- Los mecanismos de integridad (checksum IP/TCP y CRC-32 de Ethernet) están implementados de forma matemáticamente correcta y verificable, no solo ilustrativa.

## 9. Recomendaciones pedagógicas

- Utilizar la comparativa de protocolos (sección 5) para introducir la diferencia entre servicios orientados a conexión (TCP) y no orientados a conexión (UDP).
- Utilizar la comparativa de codificaciones (sección 4) para discutir cuándo la compresión es contraproducente, conectando con el concepto de entropía de la información.
- Utilizar la sección 6 (efecto del tamaño del mensaje) para introducir el concepto de eficiencia de canal y la motivación detrás de mecanismos reales como el algoritmo de Nagle o las tramas jumbo.

## 10. Conclusiones generales del proyecto

El desarrollo del Simulador OSI permitió comprender, desde la práctica y no solo desde la teoría, cómo un mensaje se transforma al atravesar las siete capas del modelo OSI. La lógica del programa se organizó en cuatro bloques claramente diferenciados: las tablas de configuración (capas, protocolos, codificaciones y medios físicos), las funciones de bajo nivel que construyen cabeceras binarias reales, la clase `OSIModel` que orquesta el encapsulamiento completo, y la interfaz gráfica que anima el resultado. Esta separación permitió que la lógica de red (qué se transmite) quedara independiente de la lógica de presentación (cómo se muestra en pantalla), lo que facilitó probar y corregir cada parte por separado durante el desarrollo.

El funcionamiento del encapsulamiento se representa de forma literal y no simbólica: cada capa agrega una cabecera real y de tamaño correcto (Ethernet, IPv4, TCP o UDP) sobre el PDU que recibe de la capa superior, hasta convertirlo en una trama completa lista para el medio físico. El desencapsulamiento, en cambio, no vuelve a analizar los bytes recibidos: reproduce en sentido inverso las mismas piezas que ya se construyeron una sola vez, retirando visualmente cada cabecera hasta entregar el mensaje original intacto en el receptor. Esta decisión de diseño simplificó la implementación sin sacrificar el valor didáctico del ejercicio, ya que el objetivo era enseñar el orden y el peso de cada cabecera, no construir un analizador de protocolos completo.

La aplicación del modelo OSI en el programa se logró mediante una estructura de datos (`LAYERS`) que actúa como fuente única de verdad para las siete capas, usada tanto por el motor de cálculo (`OSIModel`) como por el módulo de dibujo en pantalla, garantizando coherencia entre lo que se documenta y lo que realmente ocurre en el código byte a byte.

Python, apoyado únicamente en su librería estándar (`struct`, `zlib`, `base64`, `tkinter`), resultó adecuado para representar procesos de red sin depender de librerías externas ni de una conexión real, gracias a su facilidad para manipular bytes a bajo nivel y, al mismo tiempo, construir una interfaz gráfica completa e interactiva en un solo lenguaje.

Entre las principales dificultades encontradas durante la programación destacan el cálculo correcto de los checksums y el CRC (que exigió revisar con cuidado los estándares RFC 1071 e IEEE 802.3 para no obtener valores simplemente decorativos), la sincronización de la animación con los datos reales del modelo para que cada paso mostrara la información exacta de su capa, y el ajuste del diseño visual para que la interfaz siguiera siendo legible en distintas resoluciones de pantalla.

Superar estas dificultades reforzó la importancia de las pruebas y la depuración del código: verificar cada cabecera de forma aislada, imprimir y comparar valores intermedios, y recalcular manualmente checksums y CRC fuera del programa fueron pasos indispensables para confirmar que el simulador no solo se veía correcto, sino que también era matemáticamente correcto a nivel de bytes. En definitiva, el proyecto demuestra que probar cada componente por separado, antes de integrarlo a la interfaz gráfica, es lo que permite distinguir un simulador visualmente convincente de uno que además es técnicamente confiable.

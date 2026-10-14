# FLKicker-Q8

Adaptación de FLKicker 0.7 para la tablet Q8-A33
con Armbian Linux ARMv7 (armhf).

## Proyecto original

Autor original: jcarlosrf26

https://github.com/jcarlosrf26/flkicker32

FLKicker es un cliente no oficial de Kick,
desarrollado en C++ con FLTK.

## Adaptación Q8

Modificaciones realizadas por Josexx220.

Dispositivo utilizado:
- Tablet Q8-A33
- Procesador Allwinner A33 (ARMv7)
- Armbian Linux armhf
- Pantalla 1024x600

## Modificaciones

- Adaptación y pruebas en ARMv7.
- Incorporación de consulta de grabaciones VOD.
- Interfaz para explorar grabaciones.
- Incorporación de reproducción VOD.
- Modificaciones de interfaz relacionadas con favoritos.

## Código fuente

ports/armv7-q8/flkicker.cpp

Este archivo contiene la versión modificada
para Q8-A33.

## Estado

Versión experimental desarrollada para Q8-A33.

Compilación verificada en Armbian ARMv7.

## Licencia

GNU GPL v3.0, conforme al proyecto original.

Se conservan los créditos del proyecto original.
FLKicker-Q8 es una adaptación no oficial.

## Compilación en Armbian ARMv7

Plataforma probada: Q8-A33, ARMv7 armhf,
Armbian Debian 12, FLTK 1.3.8 y GCC 12.2.

### Dependencias

Instalar con APT:

- g++
- pkg-config
- libfltk1.3-dev
- libcurl4-openssl-dev
- libjson-c-dev
- libssl-dev
- mpv
- ffmpeg

### Compilación

Desde el directorio ports/armv7-q8:

    g++ -O2 -std=c++17 flkicker.cpp -o flkicker-q8 $(fltk-config --cxxflags --ldflags --use-images) $(pkg-config --cflags --libs libcurl json-c) -lcrypto -pthread

### Ejecución

Desde una sesión gráfica:

    ./flkicker-q8

### Compatibilidad

Adaptación experimental para ARMv7.
No reemplaza la versión original para PC.
La compatibilidad con otros dispositivos ARM
todavía no ha sido comprobada.

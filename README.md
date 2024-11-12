# Resolución de DVWA (Damn Vulnerable Web Application)


Este repositorio contiene la resolución detallada de la máquina **DVWA (Damn Vulnerable Web Application)**, una aplicación web intencionalmente vulnerable, diseñada para aprender y practicar técnicas de seguridad web de manera segura en un entorno controlado.

### ¿Qué es DVWA?

DVWA es una plataforma utilizada comúnmente para estudiar ataques como inyección de SQL, inyección de comandos, cross-site scripting (XSS), entre otros. Es una herramienta de aprendizaje invaluable para aquellos interesados en mejorar sus habilidades en seguridad web y en el manejo de vulnerabilidades comunes.

### Estructura del Repositorio

Para facilitar el análisis y resolución de cada uno de los retos, este repositorio está dividido en los distintos niveles de seguridad que DVWA ofrece:

- **Low**: Nivel básico de seguridad con pocas restricciones.
- **Medium**: Nivel medio de seguridad, con medidas de protección adicionales.
- **Hard**: Nivel avanzado de seguridad, con contramedidas más robustas.
- **Impossible**: Nivel teóricamente invulnerable en el que las vulnerabilidades están mitigadas al máximo.

Cada nivel incluye explicaciones, métodos utilizados, y capturas de pantalla donde sea necesario para ayudar a comprender la técnica aplicada en cada caso.

### Instalación

```bash
#DESCARGAR DVWA
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

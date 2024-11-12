```bash
#DESCARGAR DVWA
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

## Brute Force


![](/ANEXOS/Pasted%20image%2020241015193100.png)

En este apartado, encontramos un formulario de inicio de sesión simple. Este tipo de formulario es un objetivo común para ataques de **fuerza bruta** y, en algunos casos, puede ser vulnerable a **inyecciones SQL**. A continuación, explicamos cómo ejecutar un ataque de fuerza bruta con `hydra` y, posteriormente, cómo aprovechar una vulnerabilidad SQL para iniciar sesión como administrador.

### 1. Ataque de Fuerza Bruta con Hydra

Para llevar a cabo un ataque de fuerza bruta en este formulario de login, utilizaremos la herramienta `hydra`, la cual permite probar diferentes combinaciones de nombres de usuario y contraseñas. Hydra acepta múltiples tipos de formularios, y en este caso trabajaremos con un formulario de autenticación por método GET.

**Comando para formularios con método GET**

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt "http-get-form://172.17.0.2/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=submit:H=Cookie\:<cookie>; <security cookie>:<Codigo de error>"
```
#### Explicación de los Parámetros

1. **-l admin**: Especifica el nombre de usuario a utilizar en el ataque (en este caso, `admin`).
2. **-P /usr/share/wordlists/rockyou.txt**: Indica el archivo de diccionario (wordlist) con las posibles contraseñas. Aquí usamos el popular `rockyou.txt`.
3. **http-get-form**: Hydra necesita conocer el tipo de formulario. En este caso, es un formulario de login que envía datos mediante GET.
4. **URL del formulario**: Proporcionamos la URL del formulario en el formato `http-get-form://host/path`.
5. **Parámetros del formulario**:
    - **username=^USER^** y **password=^PASS^**: Campos del formulario donde Hydra reemplaza `^USER^` y `^PASS^` con las credenciales del ataque.
    - **Login=submit**: Valor del botón de envío del formulario, necesario para indicar que se desea iniciar sesión.
6. **H=Cookie**: Cookie de sesión que puede requerirse en algunos sitios.
7. **&lt;security cookie&gt;**: Define la cookie de nivel de seguridad en DVWA, que puede ser `security=low`, `security=medium`, etc.
8. **<Código de error>**: Texto que aparece en la respuesta del servidor cuando el intento de login es incorrecto. Hydra necesita esta información para identificar intentos fallidos.

**Nota**: Antes de ejecutar el ataque, examina el código fuente del formulario para identificar correctamente todos estos parámetros y ajustar el comando.

### 2. Ataque con Inyección SQL

Otra forma de lograr acceso es probar una inyección SQL simple. En formularios de autenticación mal protegidos, una consulta SQL manipulada puede permitir eludir la verificación de contraseña.

En este caso, podemos intentar una inyección SQL básica usando el nombre de usuario y omitiendo la contraseña con un comentario SQL:

```sql
admin '#
```

#### Explicación de la Inyección

- **`admin`**: Especifica el nombre de usuario.
- **`'#`**: El carácter `'` cierra la cadena de consulta SQL, y `#` es un comentario en SQL que ignora el resto de la consulta (en este caso, la verificación de contraseña).

Si el formulario es vulnerable a inyecciones SQL, esta entrada permitirá el acceso como `admin`, sin necesidad de una contraseña válida.

### Conclusión

Ambas técnicas —fuerza bruta y inyección SQL— demuestran dos enfoques para comprometer un sistema con seguridad débil.

## Command Injection

### Descripción

Este proyecto tiene como objetivo demostrar la vulnerabilidad de inyección de comandos en un formulario que permite realizar peticiones `ping` a direcciones IP. A través de esta vulnerabilidad, se puede verificar si el sistema está validando correctamente las entradas de usuario, lo que podría permitir la ejecución de comandos no autorizados.

### Escenario

El formulario permite ingresar una dirección IP y realiza una solicitud `ping`. Sin embargo, si no hay una validación adecuada de las entradas, es posible inyectar comandos maliciosos. En este caso, se intentará inyectar un comando que liste el contenido del archivo `/etc/passwd`, un archivo crítico en sistemas Unix/Linux que contiene información sobre los usuarios del sistema.

### Ejemplo de Inyección de Comandos

Para explotar esta vulnerabilidad, inyectaremos un comando adicional junto con la solicitud de `ping`. La inyección se basa en aprovechar el carácter `|`, que permite encadenar comandos en sistemas Unix/Linux. Utilizaremos el siguiente comando para intentar leer el archivo `/etc/passwd`:

```bash
8.8.8.8 | cat /etc/passwd
```

**Explicación**:

- `8.8.8.8`: Es la dirección IP objetivo inicial que el sistema intentará hacer ping.
- `| cat /etc/passwd`: Este comando se ejecuta en el sistema y muestra el contenido del archivo `/etc/passwd`, que contiene información sobre los usuarios registrados en el sistema.

![[Pasted image 20241015192953.png]]

### Resultados de la Inyección

Si el sistema es vulnerable, el contenido del archivo `/etc/passwd` se mostrará en la respuesta, confirmando que los comandos inyectados se ejecutan en el servidor. Esto compromete seriamente la seguridad del sistema, ya que el atacante puede ver la estructura de usuarios y explorar otros comandos maliciosos, como por ejemplo una reverse shell.


## XSS Almacenado y CSRF en DVWA

En esta sección, exploraremos cómo aprovechar una vulnerabilidad de **XSS almacenado** junto con un ataque de **CSRF** para modificar la contraseña de un usuario. Estos tipos de ataques son comunes en aplicaciones web con una seguridad deficiente y pueden explotarse para ejecutar acciones sin el consentimiento del usuario.

### Comandos Utilizados para el Ataque

A continuación, se presentan algunos ejemplos de código HTML para inyectar un enlace que utiliza un ataque CSRF para cambiar la contraseña del usuario. Esta técnica puede aprovecharse en un entorno vulnerable donde no se implementen medidas de seguridad adecuadas, como la verificación de tokens anti-CSRF.

### 1. Ejemplo de Ataque XSS Almacenado con un Enlace de CSRF

La siguiente línea de HTML crea un enlace que, al ser pulsado, enviará una solicitud GET para cambiar la contraseña del usuario sin su consentimiento:

```html
<a href="http://172.17.0.2/vulnerabilities/csrf/?password_new=1234&password_conf=1234&Change=Change#">Bloodborne para PC</a>
```

#### Explicación

- **`href`**: El enlace apunta a la URL que contiene los parámetros `password_new` y `password_conf`, que establecen la nueva contraseña en `1234`.
- **Texto**: `"Bloodborne para PC"` es el texto visible del enlace, que sirve como señuelo para hacer que el usuario haga clic.

Cuando el usuario hace clic en el enlace, se envía una solicitud GET a la página vulnerable, que cambia la contraseña sin requerir confirmación.

### 2. Ejemplo de Ataque XSS con Evento `onmouseover`

En este segundo ejemplo, el enlace activa la solicitud CSRF cuando el usuario pasa el ratón sobre el texto, sin necesidad de que haga clic:

```html
<a href="#" onmouseover="window.location.href='http://172.17.0.2/vulnerabilities/csrf/?password_new=1234&password_conf=1234&Change=Change#';" onclick="event.preventDefault();">Bloodborne para PC</a>
```

#### Explicación

- **`onmouseover`**: El evento `onmouseover` redirige automáticamente al usuario a la URL de ataque cuando el cursor pasa sobre el enlace.
- **`onclick="event.preventDefault();"`**: Evita el comportamiento por defecto del enlace, evitando que el usuario sospeche al no ser redirigido inmediatamente.

Este enfoque es útil cuando el atacante quiere hacer el enlace aún más discreto y minimizar la interacción del usuario.

### 3. Ejemplo de Ataque Usando una Etiqueta `<p>` y Evento `onmouseover`

Otra opción es utilizar una etiqueta `<p>` en lugar de `<a>`, lo que podría ser menos sospechoso. En este caso, la etiqueta `<p>` incluye un evento `onmouseover` que ejecuta el ataque:

```html
<p onmouseover="window.location.href='http://172.17.0.2/vulnerabilities/csrf/?password_new=1234&password_conf=1234&Change=Change#';" onclick="event.preventDefault();">Bloodborne para PC</p>
```

#### Explicación

- **Etiqueta `<p>`**: Usar una etiqueta de párrafo en lugar de un enlace puede hacer que el ataque sea menos evidente y reducir la sospecha del usuario.
- **`onmouseover`**: El ataque se activa cuando el cursor del usuario pasa sobre el texto.

### Análisis del Ataque Combinado XSS y CSRF

- **XSS Almacenado**: Estos ejemplos pueden insertarse en un campo vulnerable a XSS almacenado en DVWA, de modo que se inyecte en la página y se muestre a otros usuarios.
- **CSRF**: La URL inyectada lleva al usuario a cambiar la contraseña sin su conocimiento.

### Conclusión

Estos ataques destacan la importancia de implementar **tokens anti-CSRF** y **validación de entradas** para evitar la ejecución de scripts maliciosos y solicitudes no autorizadas. En un entorno real, es crucial que las aplicaciones utilicen medidas de seguridad adecuadas para proteger a los usuarios contra XSS almacenado y CSRF.

## SQL Injection 

La inyección SQL (SQL Injection) es una técnica que permite a un atacante manipular las consultas SQL enviadas a la base de datos para extraer, modificar o eliminar datos. A continuación, se muestra cómo utilizar inyección SQL para extraer información de una tabla y comprobar vulnerabilidades SQL de tipo "blind".

### Ejemplos de Inyección SQL para Extraer Información

1. **Listar todos los registros en una tabla**  
    Una de las técnicas básicas de SQL Injection consiste en introducir una condición lógica que siempre sea verdadera para extraer todos los registros:

```sql
1' OR 1 = 1 #
```

**Explicación**: La expresión `OR 1=1` siempre se evalúa como verdadera, lo que fuerza a la base de datos a devolver todos los registros de la tabla en lugar de solo uno.

![[Pasted image 20241112013020.png]]
2. **Listar los nombres de las tablas en la base de datos**  
	Si la base de datos permite consultas avanzadas, puedes utilizar `UNION SELECT` para extraer información sobre la estructura de la base de datos, como los nombres de las tablas:

```sql
' UNION SELECT table_name,NULL FROM information_schema.tables #
```

**Explicación**: `information_schema.tables` es una tabla del sistema que contiene los nombres de todas las tablas. Aquí se solicita el campo `table_name`, mientras que el segundo campo se completa con `NULL` para mantener la estructura de columnas.

![[Pasted image 20241112013055.png]]

**Listar usuarios y contraseñas**  
Para extraer directamente las credenciales, podemos usar `UNION SELECT` para combinar nuestra consulta con la tabla `users`:

```sql
' UNION SELECT user, password FROM users #
```

**Explicación**: Esta consulta intentará devolver los valores de las columnas `user` y `password` de la tabla `users`, revelando así la información de los usuarios almacenados en la base de datos.

![[Pasted image 20241112013118.png]]
## SQL Injection blind

### SQL Injection Blind (Ciega)

En una **inyección SQL ciega**, la aplicación no muestra directamente los resultados de la consulta. En su lugar, se basa en respuestas de verdadero/falso para confirmar la existencia de ciertas condiciones.

1. **Comprobar si es vulnerable a SQL Injection Blind**  
    Realizando pruebas condicionales podemos determinar si el sitio es vulnerable a inyección SQL ciega. Si la aplicación responde de manera distinta a cada condición, se puede concluir que es vulnerable:

```sql
1' and 1='1
```

```sql
1' and 1='2
```

**Explicación**: En el primer caso (`1=1`), la consulta es verdadera, mientras que en el segundo (`1=2`), la consulta es falsa. Las diferencias en la respuesta de la aplicación indican la existencia de SQL Injection Blind.

![[Pasted image 20241112013154.png]]
![[Pasted image 20241112013214.png]]

**Extraer la contraseña del usuario `admin` mediante SQL Injection Blind**  
Utilizando el método de **inyección ciega basada en booleanos**, es posible extraer los caracteres de una contraseña uno por uno, utilizando la función `substring()`:

```sql
1' and (select substring(password,1,1) from users where user='admin')='5
```

**Explicación**:

- `SUBSTRING(password, 1, 1)`: Extrae el carácter de la contraseña en la posición indicada por el primer carácter en este caso`1`.
- La consulta compara este carácter con un valor estimado (representado por `5`). Al modificar este valor en cada posición y probar cada carácter posible, se puede extraer la contraseña completa de forma ciega.

![[Pasted image 20241112013309.png]]

### Conclusión

El uso de SQL Injection y SQL Injection Blind permite extraer información confidencial de la base de datos, lo que resalta la importancia de implementar medidas de seguridad como la **validación de entradas** y el uso de **consultas preparadas** en todas las aplicaciones.

## Weak Session IDs

![[Pasted image 20241106155859.png]]


En este nivel, se genera una nueva cookie de sesión cada vez que pulsamos el botón, y el objetivo es analizar si la cookie sigue un patrón predecible o inseguro.

![[Pasted image 20241106160144.png]]
![[Pasted image 20241106160304.png]]

### Observación del Patrón

Al observar varias cookies generadas, se puede notar un patrón sencillo: el valor de la cookie aumenta en uno en cada solicitud. Esto sugiere un patrón de incremento secuencial, lo cual representa una debilidad en la seguridad, ya que un atacante podría predecir el valor de futuras cookies.

### Código PHP de DVWA

Para comprender mejor cómo se genera esta cookie, revisamos el código fuente de DVWA. Aquí está el código relevante:

```php
<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    if (!isset ($_SESSION['last_session_id'])) {
        $_SESSION['last_session_id'] = 0;
    }
    $_SESSION['last_session_id']++;
    $cookie_value = $_SESSION['last_session_id'];
    setcookie("dvwaSession", $cookie_value);
}
?> 
```


#### Análisis del Código

- En el fragmento `$_SESSION['last_session_id']++`, vemos que el valor de `$_SESSION['last_session_id']` aumenta en 1 cada vez que se envía una solicitud POST.
- La cookie `dvwaSession` se establece con el valor de `$_SESSION['last_session_id']`, que representa el valor actual de la sesión incrementada secuencialmente.

Esta implementación de cookies es insegura porque permite a un atacante predecir el valor de la próxima sesión simplemente observando el patrón de incremento.

### Conclusión

La vulnerabilidad aquí se basa en la **predictibilidad** de la cookie, un riesgo potencial para la **suplantación de sesión**. Esta práctica va en contra de las buenas prácticas de seguridad, ya que los identificadores de sesión deben ser únicos y aleatorios para evitar ataques de secuestro de sesión.

## JavaScript Attacks

![[Pasted image 20241111233630.png]]



Para completar este reto, necesitamos enviar la palabra `success` como valor correcto de la frase. Sin embargo, al enviar directamente `success`, recibimos una respuesta inesperada:

```bash
POST /vulnerabilities/javascript/ HTTP/1.1
Host: 172.17.0.2
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://172.17.0.2/vulnerabilities/javascript/
Content-Type: application/x-www-form-urlencoded
Content-Length: 66
Origin: http://172.17.0.2
DNT: 1
Sec-GPC: 1
Connection: close
Cookie: PHPSESSID=l0q95i5b003862hu8oicrdi1c1; security=low
Upgrade-Insecure-Requests: 1
Priority: u=0, i

token=8b479aefbd90795395b3e7089ae0dc09&phrase=ChangeMe&send=Submit

```


Aquí observamos que el `token` tiene siempre el mismo valor, incluso al probar distintas frases. Este token, con 32 caracteres, sugiere el uso de un hash **MD5**.

### Comprobación del Token

Verificamos la longitud del `token` en Bash para confirmar que tiene 32 caracteres:

```bash
echo -n "8b479aefbd90795395b3e7089ae0dc09"| wc -c
32
```

Para intentar obtener el valor original del `token`, usamos un descifrador en línea y encontramos lo siguiente:

- **Token descifrado**: `PunatrZr`

![[Pasted image 20241112003051.png]]

Sabiendo esto, podemos intentar hashear en md5 la palabra success y el valor que obtengamos intercambiarlo por el token existente, pero esto no funciona.

```bash
echo -n "success" | md5sum
260ca9dd8a4577fc00b7bd5810298076
```

Con esta información, decidimos probar un enfoque distinto ya que el token parece utilizar un método de cifrado adicional.

### Inspección del Código JavaScript

Al revisar el código de la página, encontramos una función interesante:

```javascript
function rot13(inp) {
  return inp.replace(/[a-zA-Z]/g,function(c){return String.fromCharCode((c<="Z"?90:122)>=(c=c.charCodeAt(0)+13)?c:c-26);});
}

function generate_token() {
  var phrase = document.getElementById("phrase").value;
  document.getElementById("token").value = md5(rot13(phrase));
}
generate_token();
```

Este código nos indica que el token se genera aplicando una función `rot13` a la frase (`phrase`), que luego se hashea en MD5. La función `rot13` rota cada letra del `phrase` 13 posiciones en el alfabeto, y `generate_token` usa el resultado de `rot13` como entrada para generar el token MD5.

### Reversión de `rot13`

Sabemos que el valor descifrado del token `PunatrZr` es el resultado de `rot13("ChangeMe")`. Podemos revertir la función `rot13` en Bash para ver si esto es correcto:

```bash
echo 'PunatrZr' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
ChangeMe
```

Esto confirma que `PunatrZr` es `rot13("ChangeMe")`, por lo que el token original es `md5(rot13("ChangeMe"))`.

### Generar el Token para `success`

Para resolver el reto, necesitamos el valor de `md5(rot13("success"))`. Usamos Bash para aplicar `rot13` a `success` y luego hashearlo en MD5:

```bash
alias rot13="tr 'A-Za-z' 'N-ZA-Mn-za-m'"

echo -n "success" | rot13 | md5sum
38581812b435834ebf84ebcc2c6424d6
```

### Solución Final

Al reemplazar el token existente con `38581812b435834ebf84ebcc2c6424d6` y enviar la solicitud, logramos resolver el reto.

![[Pasted image 20241112010718.png]]

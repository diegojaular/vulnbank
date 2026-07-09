# 01 · SQL Injection en el login

**Categoría OWASP:** [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
**Severidad:** Crítica · **Impacto:** salto de autenticación, robo de datos, control total de la BBDD.

---

## Qué es

Una inyección SQL ocurre cuando una aplicación construye una consulta a la base de
datos **pegando texto que viene del usuario** directamente dentro del SQL. Si ese texto
contiene caracteres que el motor SQL interpreta como código (comillas, `--`, `OR`...),
el atacante deja de rellenar un dato y pasa a **reescribir la consulta**.

## El código vulnerable

En [`UserRepository.java`](../src/main/java/com/cibernati/vulnbank/UserRepository.java):

```java
String sql = "SELECT id, username, balance, role FROM users " +
        "WHERE username = '" + username + "' AND password = '" + password + "'";
return jdbc.queryForList(sql);
```

El `username` y el `password` se concatenan a mano. La aplicación *espera* recibir un
nombre, pero no hay nada que lo obligue a serlo.

## La explotación

Con un login normal la consulta es:

```sql
SELECT ... FROM users WHERE username = 'diego' AND password = 'S3cr3tPass!'
```

Ahora mandamos como usuario el texto `admin' -- ` (nombre, una comilla, y `--`):

```bash
curl -s -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'"'"' -- ","password":"x"}'
```

La consulta que se ejecuta pasa a ser:

```sql
SELECT ... FROM users WHERE username = 'admin' -- ' AND password = 'x'
```

La comilla cierra el valor del `username`, y `--` **comenta todo lo que viene después**,
incluida la comprobación de la contraseña. Resultado: entramos como `admin` sin conocerla.

```json
{"ok":true,"user":{"ID":2,"USERNAME":"admin","BALANCE":99999,"ROLE":"ADMIN"}}
```

> Variante clásica equivalente: `' OR '1'='1' -- ` como usuario, que hace la condición
> siempre verdadera y devuelve el primer usuario de la tabla.

## El arreglo: consultas parametrizadas

La solución **no** es "filtrar comillas" (eso se salta de mil formas). Es no mezclar nunca
datos con código: se usan **parámetros** (`?`), y el driver de la base de datos se encarga
de tratar el valor como un dato, sin interpretarlo como SQL.

```java
public List<Map<String, Object>> login(String username, String password) {
    String sql = "SELECT id, username, balance, role FROM users " +
            "WHERE username = ? AND password = ?";
    return jdbc.queryForList(sql, username, password);
}
```

Con esto, mandar `admin' -- ` busca literalmente un usuario llamado `admin' -- `, que no
existe, y el login falla como debe.

## Cómo se ve esto en un proyecto Java real

- **JDBC / `JdbcTemplate`** → usar siempre `?` y pasar los valores como argumentos, nunca
  concatenar.
- **JPA / Hibernate** → usar parámetros con nombre (`:username`) o *named queries*. El
  peligro reaparece si usas `createQuery` con un string construido a mano, o SQL nativo
  concatenado.
- **Oracle (PL/SQL)** → mismo principio con *bind variables* (`:1`, `:name`). Concatenar
  en `EXECUTE IMMEDIATE` es la versión Oracle del mismo fallo.

## Regla para llevarse a casa

> Los datos que vienen del usuario **nunca** deben formar parte del texto de una consulta.
> Van siempre como parámetros. Si ves una `"` seguida de `+` variable `+ "` en un SQL,
> es una inyección esperando a ocurrir.

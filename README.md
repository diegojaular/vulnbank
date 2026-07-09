# VulnBank — laboratorio de vulnerabilidades web (Java + Spring Boot)

Aplicación **deliberadamente vulnerable** que reproduce, sobre un stack real
(Spring Boot + JDBC + base de datos), los fallos de seguridad más habituales en
aplicaciones Java empresariales. Cada vulnerabilidad viene con:

- el **código vulnerable** ejecutable,
- una **explotación** paso a paso que puedes reproducir tú mismo,
- y el **arreglo** explicado, con el enfoque defensivo correcto.

El objetivo es didáctico: entender *por qué* falla el código y cómo se escribe seguro,
desde el punto de vista de quien programa la aplicación (AppSec / código seguro).

> ⚠️ Este proyecto contiene vulnerabilidades a propósito. **No lo despliegues en internet
> ni reutilices su código en producción.**

## Vulnerabilidades

| #  | Vulnerabilidad | OWASP | Writeup |
|----|----------------|-------|---------|
| 01 | SQL Injection en el login | A03 Injection | [docs/01-sql-injection.md](docs/01-sql-injection.md) |

*(se irán añadiendo más: XSS, control de acceso roto, almacenamiento de contraseñas, config insegura...)*

## Cómo ejecutarlo

Requisitos: **Java 17+**. No hace falta instalar Maven ni una base de datos (se usa el
Maven wrapper incluido y una base de datos H2 en memoria).

```bash
./mvnw spring-boot:run        # Windows: mvnw.cmd spring-boot:run
```

La API queda en `http://localhost:8080`. Usuarios de prueba: `diego` / `S3cr3tPass!`,
`admin` / `adminPassword`, `maria` / `maria2024`.

### Probar el login

```bash
# Login legítimo
curl -s -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"diego","password":"S3cr3tPass!"}'

# Inyección SQL: entrar como admin sin su contraseña
curl -s -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'"'"' -- ","password":"x"}'
```

## Stack

- Java 17 · Spring Boot · Spring JDBC
- Base de datos H2 en memoria (consola en `http://localhost:8080/h2-console`)

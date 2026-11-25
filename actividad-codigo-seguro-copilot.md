# Actividad: Escribir código seguro con Microsoft Copilot

**Tipo:** Tarea de práctica • 30 min  
**Curso:** Seguridad y autenticación (Módulo 4: Uso de Microsoft Copilot para implementar funciones de seguridad)

---

## Introducción

En esta actividad, utilizará Microsoft Copilot para generar código seguro para una aplicación web, centrándose en mitigar vulnerabilidades comunes como la inyección de SQL y la secuencia de comandos entre sitios (XSS). También escribirá pruebas para garantizar que el código generado protege contra posibles amenazas a la seguridad.

Esta es la primera de tres actividades en las que protegerá la aplicación **SafeVault**. Las prácticas de codificación segura implementadas aquí servirán como base para los sistemas de autenticación y autorización en las actividades posteriores.

---

## Instrucciones

### Paso 1: Revisar el escenario

Para comenzar, revisa el siguiente escenario relacionado con la construcción de la aplicación web **SafeVault**:

SafeVault es una aplicación web segura diseñada para gestionar datos confidenciales, incluidas credenciales de usuario y registros financieros. Su papel como desarrollador principal es garantizar que la aplicación sea robusta frente a ataques mediante la implementación de prácticas de codificación seguras.

**Requisitos iniciales:**
- Validación de las entradas del usuario para evitar inyecciones maliciosas.
- Asegurar las consultas a la base de datos para eliminar las vulnerabilidades de inyección de SQL.
- Probar el código para garantizar que resiste ataques XSS y de inyección de SQL.

Su objetivo es utilizar Microsoft Copilot para escribir código seguro y generar pruebas que simulen escenarios de ataque.

#### Código base de la aplicación

**Formulario Web (Validación de entrada)**
```html
<!-- webform.html -->
<form action="/submit" method="post">
    <label for="username">Username:</label>
    <input type="text" id="username" name="username">

    <label for="email">Email:</label>
    <input type="email" id="email" name="email">

    <button type="submit">Submit</button>
</form>
```

**Esquema y conexión de la base de datos (consultas parametrizadas)**
```sql
-- database.sql
CREATE TABLE Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Username VARCHAR(100),
    Email VARCHAR(100)
);
```

**Configuración del marco de pruebas (pruebas de vulnerabilidades)**
```csharp
// Tests/TestInputValidation.cs
using NUnit.Framework;

[TestFixture]
public class TestInputValidation {
    [Test]
    public void TestForSQLInjection() {
        // Placeholder for SQL Injection test
    }

    [Test]
    public void TestForXSS() {
        // Placeholder for XSS test
    }
}
```

---

### Paso 2: Generar código seguro para la Validación de entrada

Utilice Copilot para generar código que:
- Valide las entradas de los usuarios eliminando caracteres maliciosos y garantizando la integridad de los datos.
- Evite que los usuarios introduzcan secuencias de comandos o consultas potencialmente dañinas.

> **Ejemplo:** Implemente una función que desinfecte las entradas de un formulario web, como `username` y `email`.

---

### Paso 3: Utilice consultas parametrizadas para evitar la inyección de SQL

Utilice Copilot para:
- Escribir consultas de base de datos utilizando sentencias parametrizadas.
- Manejar de forma segura los datos proporcionados por el usuario, como las credenciales de inicio de sesión o las entradas de búsqueda.

> **Ejemplo:** Generar una consulta segura para recuperar información del usuario utilizando marcadores de posición para los parámetros.

---

### Paso 4: Pruebe el código en busca de vulnerabilidades

Utilice Copilot para:
- Generar pruebas unitarias para simular intentos de inyección de SQL.
- Escribir pruebas para vulnerabilidades XSS inyectando scripts maliciosos en las entradas del usuario.

Ejecute las pruebas y compruebe que el código generado evita eficazmente estos ataques.

---

### Paso 5: Guarde su trabajo

Al final de esta actividad, usted tendrá:
- Código seguro que valida las entradas del usuario y previene ataques de inyección de SQL.
- Pruebas que verifican la solidez del código frente a vulnerabilidades comunes.

Guarda todo el código seguro y los casos de pruebas en tu entorno sandbox. Este trabajo será ampliado en la **Actividad 2**, donde implementarás sistemas de autenticación y autorización.

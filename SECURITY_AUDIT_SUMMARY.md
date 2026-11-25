# Resumen de Auditoría y Depuración de Seguridad — SafeVault (Actividad 3)

## 1. Vulnerabilidades y brechas identificadas

Durante la revisión integral del código base de **SafeVault** tras las Actividades 1 y 2, se verificó que las consultas SQL ya utilizaban parámetros (`SqliteParameter`) y el acceso administrativo estaba protegido por roles (`admin` / `user`), pero se detectaron cinco brechas de seguridad y endurecimiento pendientes:

1. **Riesgo de XSS almacenado en la salida del panel administrativo (`src/SafeVault/Services/AdminDashboardService.cs`)**:
   - `GetAdminDashboard` proyectaba directamente `Username` y `Email` desde la base de datos sin codificación HTML de salida. Si existieran registros heredados o insertados externamente con etiquetas `<script>` o atributos de eventos HTML, podrían renderizarse sin escapar.
2. **Falta de sanitización para contenido generado por usuarios (UGC), URLs y protección contra ReDoS (`src/SafeVault/Security/InputSanitizer.cs`)**:
   - `SanitizeForHtml` neutralizaba etiquetas HTML, pero esquemas de URL peligrosos (`javascript:`, `vbscript:`, `data:text/html`) o rutas protocol-relative (`//evil.com`) sobrevivían a la codificación HTML si se usaban en atributos `href` o `src`.
   - Tampoco existía un sanitizador específico de UGC que eliminara bytes nulos (`\0`) y caracteres de control manteniendo saltos de línea seguros antes de codificar HTML.
   - Las expresiones regulares generadas con `[GeneratedRegex]` carecían de `matchTimeoutMilliseconds` explícito frente a ataques ReDoS.
3. **Truncamiento silencioso de 72 bytes en BCrypt (`src/SafeVault/Security/PasswordHasher.cs`)**:
   - `MaxPasswordLength` permitía hasta `128` caracteres, superando el límite nativo de `72` bytes UTF-8 del algoritmo BCrypt, lo que podía provocar colisiones silenciosas en contraseñas largas o trabajo innecesario de CPU durante `VerifyPassword`.
4. **Normalización insuficiente ante traversal en rutas RBAC (`src/SafeVault/Security/AuthorizationService.cs`)**:
   - `AuthorizeRoute` normalizaba espacios y mayúsculas/minúsculas sin rechazar explícitamente secuencias de traversal (`..`), barras invertidas (`\`), dobles barras (`//`), variantes codificadas (`%2e`, `%2f`, `%5c`) ni caracteres de control.
5. **Ausencia de límites contra bytes nulos y longitud excesiva en búsquedas (`src/SafeVault/Data/UserRepository.cs`)**:
   - Aunque `SearchUsers` utilizaba consultas parametrizadas con `ESCAPE '\'`, aceptaba términos arbitrariamente largos o con bytes `\0`.

## 2. Correcciones aplicadas

- **`src/SafeVault/Services/AdminDashboardService.cs`**: `GetAdminDashboard` aplica `InputSanitizer.SanitizeForHtml(...)` sobre `Username` y `Email` como defensa en profundidad contra XSS almacenado.
- **`src/SafeVault/Security/InputSanitizer.cs`**:
  - Se agregó `matchTimeoutMilliseconds: 250` en las cuatro expresiones `[GeneratedRegex]`.
  - Se implementó `SanitizeUserContent(string?)` para eliminar `\0` y caracteres de control no permitidos, normalizar saltos de línea a `\n` y aplicar `WebUtility.HtmlEncode`.
  - Se implementó `SanitizeUrl(string?)` para permitir únicamente rutas relativas de barra simple (`/ruta`) o URIs absolutos `http://` / `https://`, devolviendo `string.Empty` ante esquemas `javascript:`, `vbscript:`, `data:` o URLs `//...`.
- **`src/SafeVault/Security/PasswordHasher.cs`**: se fijó `MaxPasswordBytes = 72` (`MaxPasswordLength = 72`) y se valida `Encoding.UTF8.GetByteCount(password) <= 72` en `ValidatePasswordStrength`, `HashPassword` y `VerifyPassword`.
- **`src/SafeVault/Security/AuthorizationService.cs`**: se añadió `ContainsUnsafeRouteTokens` en `AuthorizeRoute` para denegar de inmediato cualquier ruta con `..`, `\`, `//`, `%2e`, `%2f`, `%5c` o caracteres de control.
- **`src/SafeVault/Data/UserRepository.cs`**: `SearchUsers` rechaza cadenas con `\0` o longitud mayor a `100` caracteres manteniendo consultas parametrizadas (`@Pattern` con `ESCAPE '\'`).

## 3. Verificación y pruebas de ataque (`dotnet test`)

Se añadió la suite de simulación de ataques **`Tests/TestSecurityAuditFixes.cs`** junto con las suites existentes **`Tests/TestInputValidation.cs`** y **`Tests/TestAuthenticationAndAuthorization.cs`**.

Resultado observado al ejecutar `dotnet test --verbosity normal`:
- **Compilación:** Correcta (**0 advertencias**, **0 errores**).
- **Pruebas totales:** **45** | **Correctas:** **45** | **Incorrectas:** **0** | **Omitidas:** **0**.
- Escenarios cubiertos en `TestSecurityAuditFixes`:
  - Intentos de escalamiento de privilegios y consultas apiladas SQLi (`'; UPDATE Users SET Role='admin' WHERE 1=1; --`, `' UNION SELECT ...`) verificando integridad de roles y filas.
  - Rechazo de bytes nulos y términos sobredimensionados en `SearchUsers`.
  - Neutralización de XSS almacenado inyectado directamente en SQLite al consultar `AdminDashboardService.GetAdminDashboard`.
  - Bloqueo de vectores XSS en UGC y en URLs (`javascript:`, `JaVaScRiPt:`, `data:text/html`, `vbscript:`, `//evil.com/phish`).
  - Rechazo de contraseñas que exceden 72 bytes UTF-8 (ASCII y multibyte) evitando colisiones por truncamiento en BCrypt.
  - Bloqueo de traversal y rutas malformadas en `AuthorizationService.AuthorizeRoute` incluso para usuarios con rol `admin`.

## 4. Aporte de la asistencia tipo Copilot en la depuración

La asistencia guiada permitió auditar sistemáticamente las fronteras de entrada/salida y autenticación del proyecto, detectar casos límite sutiles más allá de los ejemplos básicos (como XSS en atributos URL, XSS almacenado en proyecciones administrativas, truncamiento silencioso de BCrypt a 72 bytes UTF-8, traversal codificado en rutas RBAC y timeouts ReDoS), generar las correcciones puntuales preservando la compatibilidad previa y redactar pruebas automatizadas de regresión que comprueban el bloqueo efectivo de cada vector de ataque.

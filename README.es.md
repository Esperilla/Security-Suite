# 🔐 Suite de Seguridad - Java POO

[![Java](https://img.shields.io/badge/Java-17%2B-orange?logo=openjdk)](https://openjdk.org/)
[![Estado](https://img.shields.io/badge/Estado-En%20Desarrollo-yellow.svg)]()

Una aplicación de consola en Java que proporciona herramientas de seguridad para la gestión de contraseñas y cifrado de archivos, desarrollada aplicando principios de **Programación Orientada a Objetos**.

## 📋 Tabla de Contenidos

- [Características](#-características)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [Arquitectura](#-arquitectura)
- [Seguridad](#-seguridad)
- [Estructura del Proyecto](#-estructura-del-proyecto)

---

## ✨ Características

### 🔑 Gestor de Contraseñas (Bóveda)
- **Almacenamiento seguro** de secretos cifrados con PBKDF2-HMAC-SHA256 y AES-256-GCM
- **Búsqueda inteligente** con algoritmo de Levenshtein (tolerancia a errores tipográficos)
- Operaciones CRUD completas (Crear, Leer, Actualizar, Eliminar)
- **Política de contraseñas robusta** (mínimo 8 caracteres, mayúsculas, números y símbolos)
- Cambio de contraseña maestra con re-cifrado automático
- Nombres únicos sin distinguir mayúsculas/minúsculas; los valores conservan sus espacios
- Límites de tamaño para nombres/valores y búsqueda Levenshtein acotada para evitar consumos excesivos

### 🔒 Cifrador de Archivos
- Cifrado/descifrado de archivos individuales usando la contraseña maestra
- Extensión `.locked` para archivos cifrados
- Escritura atómica del destino y eliminación del original solo después de una conversión exitosa
- No sobrescribe destinos existentes (la validación de `.locked` ignora mayúsculas y minúsculas)
- Verifica el archivo de salida antes de eliminar el original

### 📊 Sistema de Auditoría
- **Bitácora de eventos** con registro de todas las operaciones
- Niveles de severidad: INFO, WARN, ERROR
- Retención automática de logs (7 días)
- Sin registro de valores sensibles (solo nombres de secretos)

### 🛡️ Seguridad Implementada
- **AES-256-GCM** con IV aleatorio por operación
- Formato versionado `SSV2` con sal PBKDF2 aleatoria y cabecera (magic/versión/sal) autenticada como AAD
- Compatibilidad con datos antiguos SHA-256; la migración es opcional, conserva `.legacy.bak` sin sobrescribirlo y no impide iniciar sesión
- Entrada de contraseñas oculta en terminal
- Limpieza de contraseñas en memoria (`char[]`)
- Límite de intentos de autenticación

---

## 📦 Requisitos

- **Java 17** o superior
- **Terminal real** (PowerShell, CMD, Bash)
  > ⚠️ **No funciona desde terminales integradas de IDE** debido al uso de `System.console()` para ocultar contraseñas

---

## 🚀 Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/Esperilla/Suite-de-Seguridad.git
cd Suite-de-Seguridad
```

### 2. Compilar el proyecto

```powershell
# Windows (PowerShell)
javac -d out src/models/*.java src/modules/*.java src/main/*.java
```

```bash
# Linux/Mac
javac -d out src/models/*.java src/modules/*.java src/main/*.java
```

### 3. Ejecutar

```powershell
# Windows (PowerShell)
java -cp out main.Main
```

Pruebas críticas sin dependencias:

```powershell
javac --release 17 -d out src\models\*.java src\modules\*.java src\main\*.java tests\CriticalTests.java
java -cp out CriticalTests
```

```bash
# Linux/Mac
java -cp out main.Main
```

---

## 💻 Uso

### Primera Ejecución

Al ejecutar por primera vez, se te pedirá crear una **contraseña maestra**:

```
--- SUITE DE SEGURIDAD (JAVA POO) ---

--- Configuración Inicial ---
Bienvenido. Crea una contraseña maestra.

Requisitos de la contraseña:
  • Mínimo 8 caracteres
  • Al menos una letra mayúscula
  • Al menos un número
  • Al menos un carácter especial (!@#$%^&* etc.)

Nueva contraseña: ********
Confirma contraseña: ********
¡Sistema configurado correctamente!
```

### Menú Principal

```
--- Menú Principal ---
1. Gestor de Contraseñas
2. Cifrador de Archivos
3. Salir
>
```

### Gestor de Contraseñas

```
--- Gestor de Contraseñas ---
1. Agregar secreto
2. Ver secreto
3. Listar secretos
4. Eliminar secreto
5. Actualizar secreto
6. Cambiar contraseña maestra
7. Guardar y Regresar
>
```

**Búsqueda inteligente**: No necesitas recordar el nombre exacto del secreto. El sistema encuentra coincidencias aunque cometas errores tipográficos:

```
Buscar secreto: gmai

✔ Secreto encontrado: Gmail
Valor: mi_contraseña_segura
```

### Cifrador de Archivos

```
--- Cifrador de Archivos ---
1. Cifrar archivo
2. Descifrar archivo
3. Regresar
>
```

> 💡 **Tip**: Usa `/` en lugar de `\` para las rutas de archivos:
> ```
> Ruta del archivo: C:/Users/usuario/documento.txt
> ```

---

## 🏗️ Arquitectura

El proyecto implementa una arquitectura modular basada en **Programación Orientada a Objetos**:

```
┌─────────────────────────────────────────────────────────┐
│                      Main.java                          │
│                   (Punto de entrada)                    │
└──────────────────────────┬──────────────────────────────┘
                           │
            ┌──────────────┴──────────────┐
            ▼                             ▼
┌───────────────────────┐     ┌───────────────────────┐
│    VaultModule        │     │    FileModule         │
│  (Gestor Contraseñas) │     │  (Cifrador Archivos)  │
└───────────┬───────────┘     └───────────┬───────────┘
            │                             │
            └──────────────┬──────────────┘
                           ▼
              ┌─────────────────────────┐
              │      BaseModule         │
              │   (Clase Abstracta)     │
              │   - Polimorfismo        │
              │   - Herencia            │
              └─────────────────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │   EncryptionUtils       │
              │   - AES-GCM 256 bits    │
              │   - IV aleatorio        │
              └─────────────────────────┘
```

### Conceptos POO Aplicados

| Concepto          | Implementación                                  |
|-------------------|-------------------------------------------------|
| **Herencia**      | `BaseModule` → `VaultModule`, `FileModule`    |
| **Polimorfismo**  | Método `execute()` en cada módulo               |
| **Abstracción**   | Clase abstracta `BaseModule`                    |
| **Encapsulación** | Atributos privados con getters                  |
| **Composición**   | `Main` usa `Vault` y `VaultStorage`             |
| **Serialización** | `Vault` implementa `Serializable`               |

---

## 🔒 Seguridad

### Cifrado AES-GCM

El sistema utiliza **AES-256-GCM** (Galois/Counter Mode) para el cifrado:

| Característica           | Descripción                       |
|--------------------------|-----------------------------------|
| **Algoritmo**            | AES-256                           |
| **Modo**                 | GCM (autenticación integrada)     |
| **IV**                   | 12 bytes aleatorios por operación |
| **Tag de autenticación** | 128 bits                          |

### Política de Contraseñas

Las contraseñas maestras deben cumplir:
- ✅ Mínimo 8 caracteres
- ✅ Al menos una letra mayúscula
- ✅ Al menos un número
- ✅ Al menos un carácter especial (`!@#$%^&*()-_=+[]{}|;:'',.<>?/~``)

### Protección contra Ataques

- **Fuerza bruta**: Límite de 3 intentos para cambio de contraseña
- **Inicio de sesión**: Límite de 3 intentos; las bóvedas antiguas se respaldan y migran atómicamente tras autenticarse
- **Memoria**: Contraseñas limpiadas con `Arrays.fill(arr, '\0')`
- **Replay**: IV único por cada operación de cifrado
- **Bitácora**: Se guarda en `logs/audit.log`; los mensajes se sanitizan para evitar líneas falsificadas
- Los archivos persistentes se restringen al propietario cuando es posible y la bitácora rota al superar 1 MiB

### Formato, migración y persistencia de la bóveda

Las bóvedas nuevas usan `SSV2`: PBKDF2-HMAC-SHA256 (210.000 iteraciones), una sal
aleatoria de 16 bytes y AES-256-GCM con IV aleatorio de 12 bytes y etiqueta de 128
bits. El encabezado (magic, versión y sal) se autentica como AAD; se rechazan las
versiones desconocidas y los metadatos alterados. Las bóvedas y archivos legacy con
SHA-256 siguen siendo legibles, pero los archivos `.locked` antiguos deben descifrarse
y cifrarse otra vez para usar el formato actual.

Al iniciar sesión con una bóveda legacy, primero se descifra y valida completamente.
El archivo original se copia a `boveda.dat.legacy.bak` solo si ese respaldo todavía
no existe. El archivo nuevo se genera en un temporal, se descifra, se reconstruye y
se compara antes de publicarlo. Si la migración falla, se registra y se muestra una
advertencia, se conserva intacta la bóveda antigua y el inicio de sesión continúa;
la migración puede reintentarse en otra ejecución. El respaldo se conserva como copia
explícita de recuperación y nunca se sobrescribe automáticamente.

Los cambios de la bóveda se marcan como pendientes y se guardan al elegir
«Guardar y Regresar» o al salir. EOF también intenta guardar y los errores se
informan, no se consideran una salida limpia. Los nombres se recortan y son únicos
sin distinguir mayúsculas/minúsculas (`Locale.ROOT`); los valores secretos y las
contraseñas nunca se recortan. Hay límites prácticos para nombres, valores y
búsquedas. La persistencia fuerza el temporal, usa movimiento atómico cuando está
disponible, valida el resultado y sincroniza la carpeta padre cuando el sistema lo
permite. Los archivos grandes se leen con `readAllBytes()`, por lo que deben caber
en la memoria disponible.

---

## 📁 Estructura del Proyecto

```
Security-Suite/
├── 📄 README.es.md                    # Este archivo
├── 📄 Security-Suite.iml      # Configuración de IntelliJ IDEA
├── 📁 src/
│   ├── 📁 main/
│   │   └── 📄 Main.java            # Punto de entrada de la aplicación
│   ├── 📁 models/
│   │   ├── 📄 Vault.java                # Almacén de secretos en memoria
│   │   ├── 📄 VaultStorage.java         # Persistencia cifrada
│   │   ├── 📄 EncryptionUtils.java      # Funciones criptográficas
│   │   ├── 📄 AuditLog.java             # Sistema de logging
│   │   └── 📄 FileSecurity.java         # Permisos y sincronización del sistema de archivos
│   └── 📁 modules/
│       ├── 📄 BaseModule.java           # Clase abstracta base
│       ├── 📄 VaultModule.java          # Gestor de contraseñas
│       └── 📄 FileModule.java           # Cifrador de archivos
├── 📁 tests/                       # Pruebas críticas sin framework
├── 📁 logs/                        # Bitácora local (ignorada por Git)
└── 📄 boveda.dat                   # Bóveda cifrada (se genera al usar)
```

---

## 🎓 Contexto Académico

- Aplicación práctica de POO en Java
- Implementación de criptografía moderna
- Diseño de software modular
- Buenas prácticas de programación segura

---

## 👤 Autor

- GitHub: [@Esperilla](https://github.com/Esperilla)
---
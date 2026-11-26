# ⚔️ KILLVirus — NextGen Forensics & Local EDR

**KILLVirus** es una suite de seguridad endpoint (EDR local) y análisis forense para Windows, desarrollada en Python y CustomTkinter. 100% gratuita y de código abierto (FOSS), diseñada para técnicos de soporte, investigadores de ciberseguridad y entusiastas.

---

## 🚀 Capacidades y Arquitectura

* **Motor CTI de Hashes:** Detección de malware por SHA-256 alimentado por los feeds de inteligencia de amenazas de **ThreatFox** (*abuse.ch*). La actualización de firmas es opcional y requiere un *Auth-Key* gratuito de abuse.ch.
* **Análisis Estático PE:** Inspección de cabeceras de ejecutables (.exe, .dll) con cálculo de entropía por secciones y auditoría de llamadas a la API sospechosas.
* **Reglas YARA:** Detección de firmas y patrones complejos en disco y memoria RAM (requiere `yara-python`, disponible hasta Python 3.13).
* **Validación Authenticode:** Integración nativa con la API de Windows (WinVerifyTrust). La firma solo *rebaja* la confianza: nunca indulta un hash o una regla YARA coincidente.
* **Escaneo de Procesos en RAM:** Inspección activa y terminación forzosa de procesos y subprocesos maliciosos.
* **Auditoría de Persistencia Completa:** Claves de ejecución del Registro (Run / RunOnce), carpetas de Inicio, **servicios de Windows**, **tareas programadas** y consolas abiertas al encender el equipo.
* **Protección en Vivo:** Monitor de sistema de archivos en segundo plano minimizable a la bandeja del sistema (*System Tray*).
* **Canarios Anti-Ransomware:** Archivos cebo en Documentos, Escritorio e Imágenes; cualquier modificación, renombrado o borrado dispara una alerta e intenta atribuir el proceso responsable (handle abierto o delta de I/O, sin inventar culpables cuando hay ambigüedad).
* **AMSI:** Escaneo de scripts de PowerShell/VBScript/JScript en memoria antes de ejecutarse (usa el motor antimalware del sistema, sin subir contenido a la nube).
* **Monitor de Procesos:** Detección de procesos nuevos cuyo ejecutable coincide con firmas conocidas (polling ligero con `psutil`, sin drivers ni ETW).
* **Agente Headless + Servicio de Windows:** El motor de protección funciona sin la ventana abierta, arranca con Windows, se recupera solo si se cae y comparte datos con la interfaz.
* **Autoprotección:** ACLs endurecidas en firmas, cuarentena, reportes y logs (solo tu usuario, SYSTEM y Administradores) + manifiesto SHA-256 para detectar código alterado.
* **Gestor Forense:** Cuarentena cifrada con DPAPI (el contenido no queda ejecutable en reposo), metadatos y exportación de reportes.
* **100% Gratuito y Libre:** Sin suscripciones, muros de pago, cuentas ni licencias. No requiere conexión a internet y no recopila telemetría invasiva.

---

## ☕ Apoyo al Proyecto

KILLVirus es un proyecto de código abierto y mantenimiento independiente. Si la herramienta te resulta de utilidad y deseas colaborar con su evolución continua:

- ☕ **Cafecito (Argentina):** https://cafecito.app/cristian_dev
- ⭐ **Repositorio oficial:** https://github.com/CristianNLC/KILLVirus---NextGen-Forensics-Local-EDR

---

## 🛠️ Instalación y Uso

### Ejecutable Listo para Usar
Descarga el instalador oficial desde el apartado de **Releases** (KILLVirus_v2_Setup.exe) e instálalo con permisos de administrador.

### Ejecución desde Código Fuente
```bash
git clone https://github.com/CristianNLC/KILLVirus---NextGen-Forensics-Local-EDR.git
cd KILLVirus---NextGen-Forensics-Local-EDR
pip install -r requirements.txt
python app.pyw
```

### Requisitos y notas

- **Python 3.12 o 3.13** recomendado: `yara-python` todavía no publica *wheels* para 3.14. Sin ese módulo la app sigue funcionando (hash SHA-256, heurísticas y análisis PE) y la barra lateral lo indica como «Motor YARA: no disponible».
- **Datos de ejecución:** en desarrollo se usan las carpetas del propio proyecto; empaquetado, todo se guarda en `%LOCALAPPDATA%\KILLVirus` (firmas, cuarentena, reportes y configuración).
- **Actualización de firmas:** en *Configuración → Auth-Key de abuse.ch* se pega una clave gratuita de <https://auth.abuse.ch/>. Sin clave, la app funciona igual pero no descarga firmas nuevas.
- **Servicio de Windows (opcional):** desde *Servicio y Autoprotección* o con `powershell -ExecutionPolicy Bypass -File scripts\install_service.ps1` (pide UAC). El agente corre aunque cierres la ventana y Windows lo reinicia si se cae. Se desinstala con `scripts\uninstall_service.ps1` o el propio instalador.
- **Autoprotección:** el botón *Aplicar ACLs* quita la herencia de permisos en las carpetas de datos y genera un manifiesto de integridad. No pretende detener malware que ya corre con tu misma cuenta; para eso están el servicio, el watchdog y los canarios.

### Compilación y firma (mantenedores)

El release se compila con **Python 3.13** (3.14 todavía no tiene wheels de
`yara-python`):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1 -Clean
# Firma de prueba (certificado autofirmado; no sirve para distribuir):
powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1 -Sign -SelfSigned
# Firma real con un certificado del almacén o un .pfx:
powershell -ExecutionPolicy Bypass -File scripts\sign_build.ps1 -Thumbprint <SHA1>
powershell -ExecutionPolicy Bypass -File scripts\sign_build.ps1 -PfxPath cert.pfx -PfxPassword ***
```

El instalador se genera con Inno Setup a partir de `installer.iss`. Firmá tanto
`KILLVirus_v2.exe` como el `Setup.exe` final: sin sello de tiempo RFC3161 la
firma caduca con el certificado. Al subir la versión, actualizá también
`packaging/version_info.txt` (metadatos del `.exe`).

### Autocomprobación

```bash
python scripts/selftest.py
```

Verifica rutas, motor de firmas, heurísticas, Authenticode, el parser de ThreatFox y la cola de protección en vivo. No usa muestras reales de malware (el antivirus del sistema podría borrar el propio script).

# ⚔️ KILLVirus — NextGen Forensics & Local EDR

**KILLVirus** es una suite de seguridad endpoint (EDR local) y análisis forense para Windows, desarrollada en Python y CustomTkinter. 100% gratuita y de código abierto (FOSS), diseñada para técnicos de soporte, investigadores de ciberseguridad y entusiastas.

---

## 🚀 Capacidades y Arquitectura

* **Motor CTI de Hashes:** Detección de malware por SHA-256 alimentado por los feeds de inteligencia de amenazas de **ThreatFox** (*abuse.ch*). La actualización de firmas es opcional y requiere un *Auth-Key* gratuito de abuse.ch.
* **Análisis Estático PE:** Inspección de cabeceras de ejecutables (.exe, .dll) con cálculo de entropía por secciones y auditoría de llamadas a la API sospechosas.
* **Reglas YARA:** Detección de firmas y patrones complejos en disco y memoria RAM (requiere `yara-python`, disponible hasta Python 3.13).
* **Validación Authenticode:** Integración nativa con la API de Windows (WinVerifyTrust). La firma solo *rebaja* la confianza: nunca indulta un hash o una regla YARA coincidente.
* **Escaneo de Procesos en RAM:** Inspección activa y terminación forzosa de procesos y subprocesos maliciosos.
* **Auditoría de Persistencia:** Revisión exhaustiva de claves de ejecución en el Registro de Windows (Run / RunOnce).
* **Protección en Vivo:** Monitor de sistema de archivos en segundo plano minimizable a la bandeja del sistema (*System Tray*).
* **Gestor Forense:** Cuarentena segura con aislamiento criptográfico, metadatos y exportación de reportes.
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

### Autocomprobación

```bash
python scripts/selftest.py
```

Verifica rutas, motor de firmas, heurísticas, Authenticode, el parser de ThreatFox y la cola de protección en vivo. No usa muestras reales de malware (el antivirus del sistema podría borrar el propio script).

# ⚔️ KILLVirus — NextGen Forensics & Local EDR

**KILLVirus** es una suite de seguridad endpoint (EDR local) y análisis forense para Windows, desarrollada en Python y CustomTkinter. 100% gratuita y de código abierto (FOSS), diseñada para técnicos de soporte, investigadores de ciberseguridad y entusiastas.

---

## 🚀 Capacidades y Arquitectura

* **Motor CTI de Hashes:** Detección de malware por SHA-256 alimentado por los feeds de inteligencia de amenazas de **ThreatFox** (*abuse.ch*).
* **Análisis Estático PE:** Inspección de cabeceras de ejecutables (.exe, .dll) con cálculo de entropía por secciones y auditoría de llamadas a la API sospechosas.
* **Reglas YARA:** Detección de firmas y patrones complejos en disco y memoria RAM.
* **Validación Authenticode:** Integración nativa con la API de Windows (WinVerifyTrust) para mitigar falsos positivos en binarios oficiales firmados.
* **Escaneo de Procesos en RAM:** Inspección activa y terminación forzosa de procesos y subprocesos maliciosos.
* **Auditoría de Persistencia:** Revisión exhaustiva de claves de ejecución en el Registro de Windows (Run / RunOnce).
* **Protección en Vivo:** Monitor de sistema de archivos en segundo plano minimizable a la bandeja del sistema (*System Tray*).
* **Gestor Forense:** Cuarentena segura con aislamiento criptográfico, metadatos y exportación de reportes.
* **100% Gratuito y Libre:** Sin suscripciones, muros de pago ni recopilación de telemetría invasiva.

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
`ash
git clone [https://github.com/CristianNLC/KILLVirus---NextGen-Forensics-Local-EDR.git](https://github.com/CristianNLC/KILLVirus---NextGen-Forensics-Local-EDR.git)
cd KILLVirus---NextGen-Forensics-Local-EDR
pip install -r requirements.txt
python app.pyw
`

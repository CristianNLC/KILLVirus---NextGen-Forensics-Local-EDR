# ⚔️ KILLVirus - NextGen Forensics & Local EDR

**KILLVirus** es una solución de seguridad endpoint (EDR local) desarrollada en Python y empaquetada como ejecutable nativo para Windows. Integra motores de análisis estático, reglas YARA, telemetría de memoria en RAM, auditoría de persistencia y verificación de certificados digitales de Windows para mitigar falsos positivos.

---

## 🚀 Capacidades y Arquitectura

* **Motor CTI de Hashes:** Detección de malware por SHA-256 alimentado por los feeds de inteligencia de amenazas de **ThreatFox** (*abuse.ch*).
* **Análisis Estático PE:** Inspección de cabeceras de binarios (`.exe`, `.dll`) calculando entropía por secciones (detección de empaquetadores/packers) y filtrado de llamadas a la API sospechosas.
* **Reglas YARA:** Escaneo de firmas en memoria y disco mediante expresiones compiladas complejas.
* **Validación Authenticode:** Integración con la API nativa de Windows (`WinVerifyTrust` en `wintrust.dll`) para verificar firmas digitales y eliminar falsos positivos en binarios legítimos.
* **Escaneo de Procesos en RAM:** Inspección activa de procesos en ejecución con capacidad de terminación de hilos maliciosos.
* **Auditoría de Persistencia:** Revisión exhaustiva de claves de registro `Run` y `RunOnce`.
* **Protección en Tiempo Real:** Monitor de sistema de archivos en segundo plano con *Watchdog*, minimizable a la bandeja del sistema (*System Tray*).
* **Inteligencia en la Nube:** Consultas asíncronas a la API v3 de **VirusTotal**.
* **Aislamiento Forense:** Gestor visual de cuarentena con retención de metadatos y generación de informes forenses en HTML.

---

## 🛠️ Instalación y Uso

### Ejecutable listo para usar
Descarga y ejecuta el instalador oficial ubicado en `dist_installer/KILLVirus_Setup.exe`.

### Ejecución desde código fuente
1. Clonar el repositorio:
   ```bash
   git clone [https://github.com/TU_USUARIO/KILLVirus.git](https://github.com/TU_USUARIO/KILLVirus.git)
   cd KILLVirus
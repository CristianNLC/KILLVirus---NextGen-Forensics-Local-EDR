import os
import webbrowser
from datetime import datetime

REPORTS_DIR = os.path.join(os.getcwd(), "reportes")

def generate_html_report(target_path, total_scanned, threats_found):
    """
    Genera un informe forense en HTML limpio y responsivo, y lo abre en el navegador.
    threats_found debe ser una lista de diccionarios:
    [{'file': '...', 'path': '...', 'hash': '...', 'reason': '...', 'quarantined': True/False}]
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"reporte_seguridad_{file_timestamp}.html"
    report_path = os.path.join(REPORTS_DIR, report_filename)

    threat_count = len(threats_found)
    status_class = "status-danger" if threat_count > 0 else "status-clean"
    status_text = f"Amenazas Detectadas: {threat_count}" if threat_count > 0 else "Sistema Limpio (0 Amenazas)"

    # Generar filas de la tabla de detecciones
    table_rows = ""
    if threat_count > 0:
        for t in threats_found:
            table_rows += f"""
            <tr>
                <td class="bold-text">{t.get('file', 'N/A')}</td>
                <td><span class="badge badge-threat">{t.get('reason', 'Malware Detectado')}</span></td>
                <td class="mono-text">{t.get('hash', 'N/A')}</td>
                <td class="mono-text">{t.get('path', 'N/A')}</td>
                <td>{"<span class='badge badge-success'>Aislado</span>" if t.get('quarantined') else "<span class='badge badge-warning'>Omitido</span>"}</td>
            </tr>
            """
    else:
        table_rows = """
        <tr>
            <td colspan="5" style="text-align: center; color: #28a745; padding: 25px; font-weight: bold;">
                ✓ No se encontraron amenazas activas ni artefactos maliciosos en la ubicación inspeccionada.
            </td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte Forense de Seguridad - Antivirus Local</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif; }}
        body {{ background-color: #f4f6f9; color: #333; padding: 30px; }}
        .container {{ max-width: 1100px; margin: 0 auto; background: #fff; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.06); overflow: hidden; }}
        .header {{ background: #1f2937; color: #fff; padding: 25px 30px; display: flex; justify-content: space-between; align-items: center; }}
        .header h1 {{ font-size: 22px; font-weight: 600; letter-spacing: -0.5px; }}
        .header span {{ font-size: 13px; color: #9ca3af; }}
        .summary-bar {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; padding: 25px 30px; background: #fafafa; border-bottom: 1px solid #e5e7eb; }}
        .card {{ background: #fff; padding: 15px 20px; border-radius: 6px; border: 1px solid #e5e7eb; }}
        .card .title {{ font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase; margin-bottom: 5px; }}
        .card .value {{ font-size: 18px; font-weight: bold; color: #111827; word-break: break-all; }}
        .status-danger {{ color: #dc2626 !important; }}
        .status-clean {{ color: #16a34a !important; }}
        .table-container {{ padding: 25px 30px; }}
        .table-title {{ font-size: 16px; font-weight: 600; margin-bottom: 15px; color: #111827; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }}
        th {{ background: #f9fafb; color: #4b5563; padding: 12px 14px; font-weight: 600; border-bottom: 2px solid #e5e7eb; }}
        td {{ padding: 12px 14px; border-bottom: 1px solid #e5e7eb; vertical-align: middle; }}
        tr:hover {{ background-color: #f8fafc; }}
        .mono-text {{ font-family: "Consolas", monospace; font-size: 11px; color: #4b5563; word-break: break-all; }}
        .bold-text {{ font-weight: 600; color: #111827; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
        .badge-threat {{ background: #fee2e2; color: #b91c1c; }}
        .badge-success {{ background: #dcfce7; color: #15803d; }}
        .badge-warning {{ background: #fef3c7; color: #b45309; }}
        .footer {{ text-align: center; padding: 20px; font-size: 12px; color: #9ca3af; border-top: 1px solid #f3f4f6; }}
        @media print {{
            body {{ background: #fff; padding: 0; }}
            .container {{ box-shadow: none; border: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Informe Forense de Seguridad</h1>
                <span>Generado por Antivirus Local</span>
            </div>
            <div>
                <span>Fecha: {timestamp_str}</span>
            </div>
        </div>
        
        <div class="summary-bar">
            <div class="card">
                <div class="title">Ruta Inspeccionada</div>
                <div class="value" style="font-size: 14px;">{target_path}</div>
            </div>
            <div class="card">
                <div class="title">Archivos Analizados</div>
                <div class="value">{total_scanned}</div>
            </div>
            <div class="card">
                <div class="title">Diagnóstico Final</div>
                <div class="value {status_class}">{status_text}</div>
            </div>
        </div>

        <div class="table-container">
            <div class="table-title">Detalle de Artefactos e Incidentes</div>
            <table>
                <thead>
                    <tr>
                        <th>Archivo</th>
                        <th>Detección / Heurística</th>
                        <th>Hash SHA-256</th>
                        <th>Ruta de Origen</th>
                        <th>Estado</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Reporte forense generado localmente. Para archivar como PDF presione <strong>Ctrl + P</strong> en su navegador.
        </div>
    </div>
</body>
</html>
"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    webbrowser.open(f"file://{os.path.abspath(report_path)}")
    return report_path
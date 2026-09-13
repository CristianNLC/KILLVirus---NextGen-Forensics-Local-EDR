import sys
import os
import winreg

MENU_LABEL = "Analizar con Antivirus Local"

def get_launch_command():
    """Genera la orden de ejecución apuntando al ejecutable o al script Python."""
    if getattr(sys, 'frozen', False):
        # Modo ejecutable compilado con PyInstaller (.exe)
        exe_path = os.path.abspath(sys.executable)
        return f'"{exe_path}" "%1"'
    else:
        # Modo script de desarrollo (.pyw)
        python_exe = os.path.abspath(sys.executable)
        # Cambiar python.exe a pythonw.exe para evitar ventana de consola
        pythonw_exe = python_exe.lower().replace("python.exe", "pythonw.exe")
        if not os.path.exists(pythonw_exe):
            pythonw_exe = python_exe
        script_path = os.path.abspath("app.pyw")
        return f'"{pythonw_exe}" "{script_path}" "%1"'

def register_context_menu():
    """Registra la opción de menú contextual en Windows para archivos y carpetas."""
    cmd_string = get_launch_command()
    targets = [
        r"Software\Classes\*\shell\AntivirusLocal",
        r"Software\Classes\Directory\shell\AntivirusLocal"
    ]

    try:
        for key_path in targets:
            # Crear la clave principal del menú
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, MENU_LABEL)

            # Crear la subclave de comando de ejecución
            cmd_path = f"{key_path}\\command"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, cmd_path) as cmd_key:
                winreg.SetValueEx(cmd_key, "", 0, winreg.REG_SZ, cmd_string)

        return True, "Integración añadida al menú contextual con éxito."
    except Exception as e:
        return False, f"Error al registrar: {e}"

def unregister_context_menu():
    """Elimina las claves registradas en el menú contextual."""
    targets = [
        (r"Software\Classes\*\shell", "AntivirusLocal"),
        (r"Software\Classes\Directory\shell", "AntivirusLocal")
    ]

    try:
        for parent_path, subkey_name in targets:
            try:
                full_parent = parent_path + "\\" + subkey_name
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, full_parent) as k:
                    winreg.DeleteKey(k, "command")
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, parent_path) as parent:
                    winreg.DeleteKey(parent, subkey_name)
            except FileNotFoundError:
                continue
        return True, "Integración eliminada del menú contextual."
    except Exception as e:
        return False, f"Error al desinstalar menú: {e}"
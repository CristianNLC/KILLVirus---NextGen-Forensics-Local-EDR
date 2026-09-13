import threading
from PIL import Image, ImageDraw
import pystray

def create_shield_icon():
    """Genera un icono de escudo nítido de 64x64 en memoria."""
    width = 64
    height = 64
    image = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    
    # Dibujar escudo con borde brillante
    points = [
        (32, 4),
        (58, 14),
        (52, 46),
        (32, 60),
        (12, 46),
        (6, 14)
    ]
    draw.polygon(points, fill="#0066cc", outline="#38bdf8", width=2)
    return image

class SystemTrayManager:
    def __init__(self, on_show_callback, on_exit_callback):
        self.on_show = on_show_callback
        self.on_exit = on_exit_callback
        self.icon = None

    def _on_clicked(self, icon, item):
        if self.on_show:
            self.on_show()

    def _on_quit(self, icon, item):
        self.stop()
        if self.on_exit:
            self.on_exit()

    def start(self):
        """Inicia el icono en su propio hilo independiente."""
        if self.icon is not None:
            return

        img = create_shield_icon()
        menu = pystray.Menu(
            pystray.MenuItem("Abrir Antivirus Local", self._on_clicked, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Cerrar Antivirus", self._on_quit)
        )
        self.icon = pystray.Icon("AntivirusLocal", img, "Antivirus Local Activo", menu)
        
        thread = threading.Thread(target=self.icon.run, daemon=True)
        thread.start()

    def stop(self):
        """Remueve el icono de la bandeja de forma segura."""
        if self.icon is not None:
            try:
                self.icon.stop()
            except Exception:
                pass
            self.icon = None
import os
from PIL import Image, ImageDraw

def create_killvirus_icon():
    os.makedirs("assets", exist_ok=True)
    size = 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # 1. Fondo: Escudo estilo Kill Bill (Amarillo y negro)
    shield_pts = [
        (128, 16),
        (232, 56),
        (208, 184),
        (128, 240),
        (48, 184),
        (24, 56)
    ]
    # Sombra y base
    draw.polygon(shield_pts, fill="#eab308")  # Amarillo vibrante
    
    # Borde exterior oscuro
    draw.polygon(shield_pts, outline="#18181b", width=12)

    # 2. Franja deportiva negra central (guiño directo al traje samurái)
    draw.rectangle([112, 30, 144, 226], fill="#18181b")

    # 3. Filo de katana / corte diagonal en blanco/plateado
    draw.line([(36, 220), (220, 36)], fill="#ffffff", width=10)
    # Brillo del corte
    draw.line([(40, 224), (224, 40)], fill="#38bdf8", width=4)

    # Guardar como PNG y como ICO multirresolución
    png_path = os.path.join("assets", "icon.png")
    ico_path = os.path.join("assets", "icon.ico")
    
    img.save(png_path, format="PNG")
    img.save(ico_path, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print(f"[✓] Iconos generados con éxito en {ico_path} y {png_path}")

if __name__ == "__main__":
    create_killvirus_icon()
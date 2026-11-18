# Draws assets/legion-login-logo.png: the Ubuntu logo and LEGION, used as the
# GDM login-screen logo. GDM scales it to about 48 pixels tall.
#   python3 tools/login-logo.py /usr/share/fonts/truetype/ubuntu/Ubuntu-B.ttf assets/legion-login-logo.png
import math, sys
from PIL import Image, ImageDraw, ImageFont
W, H = 1200, 300           # 4:1; GDM shows it about 48 px tall
SS = 4                     # supersampling for smooth edges
ORANGE = (233, 84, 32, 255); WHITE = (255, 255, 255, 255)
big = Image.new("RGBA", (W*SS, H*SS), (0, 0, 0, 0))
# Ubuntu Circle of Friends on an orange disc, drawn as vector shapes.
cx, cy, R = 150*SS, 150*SS, 130*SS
px = big.load()
p = dict(scale=0.78, ro=0.60, ri=0.32, hd=0.90, hr=0.24, gap=0.09, cut=19)
def logo(x, y):
    if math.hypot(x, y) > 1.0: return 0
    x, y = x/p["scale"], y/p["scale"]
    for a in (60, 180, 300):
        hx, hy = p["hd"]*math.cos(math.radians(a)), p["hd"]*math.sin(math.radians(a))
        d = math.hypot(x-hx, y-hy)
        if d <= p["hr"]: return 2
        if d <= p["hr"] + p["gap"]: return 1
    r = math.hypot(x, y)
    if p["ri"] <= r <= p["ro"]:
        th = math.degrees(math.atan2(y, x)) % 360
        if all(abs((th - a + 180) % 360 - 180) > p["cut"] for a in (60, 180, 300)): return 2
    return 1
for yy in range(cy - R, cy + R):
    for xx in range(cx - R, cx + R):
        v = logo((xx - cx) / R, -(yy - cy) / R)
        if v: px[xx, yy] = ORANGE if v == 1 else WHITE
# LEGION lettering with the banner's cyan-to-blue gradient.
font = ImageFont.truetype(sys.argv[1], 210*SS)
try: font.set_variation_by_name("Bold")
except Exception: pass
text = "LEGION"
mask = Image.new("L", big.size, 0)
ImageDraw.Draw(mask).text((330*SS, 150*SS), text, font=font, fill=255, anchor="lm")
grad = Image.new("RGBA", big.size)
gd = ImageDraw.Draw(grad)
top, bot = (0, 255, 255), (0, 95, 255)
for yy in range(big.size[1]):
    t = yy / big.size[1]
    gd.line([(0, yy), (big.size[0], yy)], fill=tuple(int(top[i] + (bot[i]-top[i])*t) for i in range(3)) + (255,))
big.paste(grad, (0, 0), mask)
img = big.resize((W, H), Image.LANCZOS)
bbox = img.getbbox(); img = img.crop((0, 0, bbox[2] + 20, H))
img.save(sys.argv[2])
print(img.size)


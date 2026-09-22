"""Build the self-contained deck: subset the three brand faces, base64 them in, write ../research-agenda.html."""
import base64, io, os, sys
from fontTools import subset
from fontTools.ttLib import TTFont

DS = "/Users/jimschwoebel/Desktop/ClaudeDesign/fonts"
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "research-agenda.src.html")
OUT = os.path.join(HERE, "..", "research-agenda.html")

FACES = [
    ("Jost", "Jost-Variable.ttf", "normal"),
    ("Inter", "Inter-Variable.ttf", "normal"),
    ("Atkinson Hyperlegible Next", "AtkinsonHyperlegibleNext-Variable.ttf", "normal"),
]
UNICODES = "U+0020-007E,U+00A0-00FF,U+2013-2014,U+2018-201D,U+2022,U+2026,U+00B7,U+2192,U+00D7,U+00B5,U+03BC,U+2190,U+2191,U+2193"

try:
    import brotli  # noqa
    FLAVOR, MIME = "woff2", "font/woff2"
except ImportError:
    FLAVOR, MIME = None, "font/ttf"

def subset_font(path):
    font = TTFont(path)
    opts = subset.Options()
    opts.flavor = FLAVOR
    opts.layout_features = ["*"]
    opts.name_IDs = ["*"]
    opts.notdef_outline = True
    opts.desubroutinize = False
    s = subset.Subsetter(options=opts)
    s.populate(unicodes=subset.parse_unicodes(UNICODES))
    s.subset(font)
    buf = io.BytesIO()
    font.flavor = FLAVOR
    font.save(buf)
    return buf.getvalue()

css = []
total = 0
for family, fn, style in FACES:
    data = subset_font(os.path.join(DS, fn))
    total += len(data)
    b64 = base64.b64encode(data).decode()
    fmt = "woff2" if FLAVOR == "woff2" else "truetype"
    css.append(f'@font-face{{font-family:"{family}";font-style:{style};font-weight:100 900;font-display:block;src:url("data:{MIME};base64,{b64}") format("{fmt}")}}')
    print(f"{fn}: {len(data)//1024} KB ({FLAVOR or 'ttf'})")

html = open(SRC, encoding="utf-8").read()
assert "/*FONTS*/" in html
html = html.replace("/*FONTS*/", "\n".join(css))
open(OUT, "w", encoding="utf-8").write(html)
print(f"wrote {OUT}: {os.path.getsize(OUT)//1024} KB, fonts {total//1024} KB")

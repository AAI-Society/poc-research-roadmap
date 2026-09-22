"""Build the self-contained decks: subset the three brand faces, base64 them in, write ../<name>.html.
Each deck is _head.html + <name>.slides.html + _tail.html, with fonts injected at /*FONTS*/."""
import base64, io, os, sys
from fontTools import subset
from fontTools.ttLib import TTFont

DS = "/Users/jimschwoebel/Desktop/ClaudeDesign/fonts"
HERE = os.path.dirname(os.path.abspath(__file__))
DECKS = {
    "research-agenda": ("research-agenda.slides.html", "Proof-of-Control Research Agenda"),
    "research-agenda-for-security-leaders": ("research-agenda-ciso.slides.html", "Proof-of-Control for Security Leaders"),
}
FACES = [
    ("Jost", "Jost-Variable.ttf"),
    ("Inter", "Inter-Variable.ttf"),
    ("Atkinson Hyperlegible Next", "AtkinsonHyperlegibleNext-Variable.ttf"),
]
UNICODES = "U+0020-007E,U+00A0-00FF,U+2011,U+2013-2014,U+2018-201D,U+2022,U+2026,U+00B7,U+2192,U+00D7,U+00B5,U+03BC,U+2190,U+2191,U+2193"

try:
    import brotli  # noqa
    FLAVOR, MIME, FMT = "woff2", "font/woff2", "woff2"
except ImportError:
    FLAVOR, MIME, FMT = None, "font/ttf", "truetype"

def subset_font(path):
    font = TTFont(path)
    opts = subset.Options(); opts.flavor = FLAVOR; opts.layout_features = ["*"]; opts.name_IDs = ["*"]; opts.notdef_outline = True
    s = subset.Subsetter(options=opts); s.populate(unicodes=subset.parse_unicodes(UNICODES)); s.subset(font)
    buf = io.BytesIO(); font.flavor = FLAVOR; font.save(buf); return buf.getvalue()

css = []
for family, fn in FACES:
    data = subset_font(os.path.join(DS, fn))
    css.append(f'@font-face{{font-family:"{family}";font-style:normal;font-weight:100 900;font-display:block;src:url("data:{MIME};base64,{base64.b64encode(data).decode()}") format("{FMT}")}}')
fonts = "\n".join(css)

head = open(os.path.join(HERE, "_head.html"), encoding="utf-8").read()
tail = open(os.path.join(HERE, "_tail.html"), encoding="utf-8").read()
for name, (slides_file, title) in DECKS.items():
    slides = open(os.path.join(HERE, slides_file), encoding="utf-8").read()
    h = head.replace("/*FONTS*/", fonts).replace("<title>Proof-of-Control Research Agenda</title>", f"<title>{title}</title>")
    t = tail.replace("'Proof-of-Control Research Agenda · '", f"'{title} · '")
    out = os.path.join(HERE, "..", name + ".html")
    open(out, "w", encoding="utf-8").write(h + '<div class="stage" id="stage">\n' + slides + t)
    print(f"wrote {out}: {os.path.getsize(out)//1024} KB")

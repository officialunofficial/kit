"""Export the favicon and white OG artwork from the brand contours."""
from copy import deepcopy
from pathlib import Path
import struct
import subprocess
import xml.etree.ElementTree as E

ROOT = Path(__file__).resolve().parent
NS = '{http://www.w3.org/2000/svg}'
E.register_namespace('', NS[1:-1])
logo = E.parse(ROOT / 'kit-logo-clean.svg').getroot()


def save(path, root):
    path.write_text(E.tostring(root, encoding='unicode') + '\n')


def icon(square=False):
    root = E.Element(NS + 'svg', {'viewBox': '0 0 64 64', 'width': '64', 'height': '64', 'role': 'img', 'aria-label': 'kit'})
    E.SubElement(root, NS + 'rect', {'width': '64', 'height': '64', 'rx': '0' if square else '14', 'fill': '#0067ed'})
    # One uniform scale preserves the 66.51 by 19.79 unit wordmark.
    scale = 60 / 66.51
    height = 19.79 * scale
    letters = E.SubElement(root, NS + 'g', {'transform': f'translate(2 {(64 - height) / 2}) scale({scale}) translate(-7.62 -50.66)'})
    for face in list(logo)[-3:]:
        glyph = deepcopy(face)
        glyph.set('fill', 'white')
        letters.append(glyph)
    return root


save(ROOT / 'favicon/favicon.svg', icon())
for size in [16, 32, 48, 64, 96, 128, 180, 192, 256, 512]:
    subprocess.run(['rsvg-convert', '-w', str(size), '-h', str(size), '-o', str(ROOT / f'favicon/favicon-{size}.png'), str(ROOT / 'favicon/favicon.svg')], check=True)
# ICO embeds the exact PNG images for each fallback size.
images = [(n, (ROOT / f'favicon/favicon-{n}.png').read_bytes()) for n in [16, 32, 48, 64, 128, 256]]
offset = 6 + 16 * len(images)
entries = []
for size, data in images:
    entries.append(struct.pack('<BBBBHHII', size % 256, size % 256, 0, 0, 1, 32, len(data), offset))
    offset += len(data)
(ROOT / 'favicon/favicon.ico').write_bytes(struct.pack('<HHH', 0, 1, len(images)) + b''.join(entries) + b''.join(data for _, data in images))
save(ROOT / 'favicon/apple-touch-icon.svg', icon(square=True))
subprocess.run(['rsvg-convert', '-w', '180', '-h', '180', '-o', str(ROOT / 'favicon/apple-touch-icon.png'), str(ROOT / 'favicon/apple-touch-icon.svg')], check=True)

shapes = E.parse(ROOT / 'shapes/composition-05.svg').getroot()
scene = next(e for e in shapes if e.tag == NS + 'svg')
root = E.Element(NS + 'svg', {'width': '860', 'height': '560', 'viewBox': '-430 -430 860 560'})
for child in scene:
    root.append(deepcopy(child))
save(ROOT / 'og/shapes.svg', root)
root = E.Element(NS + 'svg', {'width': '665', 'height': '197.9', 'viewBox': '7.62 50.66 66.5 19.79'})
for child in list(logo)[-3:]:
    glyph = deepcopy(child)
    glyph.set('fill', 'white')
    root.append(glyph)
save(ROOT / 'og/wordmark.svg', root)
print('Generated favicon files and white OG artwork.')

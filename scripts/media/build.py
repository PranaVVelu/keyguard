"""Turns capture.mjs output into docs/media: 1600 px page screenshots and a 1000 px demo GIF."""
import sys, glob, os
from PIL import Image
src, dst = sys.argv[1], sys.argv[2]
for name in ["garage","keys","inspector","attack-lab","proximity","analytics","account"]:
    im = Image.open(f"{src}/{name}.png").convert("RGB")
    w = 1600
    im = im.resize((w, round(im.height * w / im.width)), Image.LANCZOS)
    im = im.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
    im.save(f"{dst}/{name}.png", optimize=True)
frames = sorted(glob.glob(f"{src}/frame-*.png"))
imgs = []
for f in frames:
    im = Image.open(f).convert("RGB")
    im = im.resize((1000, 625), Image.LANCZOS)
    imgs.append(im.quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE))
durations = [1600,1400,1400,1600,2400,1600,2800,2800,2200]
imgs[0].save(f"{dst}/demo.gif", save_all=True, append_images=imgs[1:], duration=durations[:len(imgs)], loop=0, optimize=True)
for f in sorted(os.listdir(dst)): print(f, os.path.getsize(f"{dst}/{f}")//1024, "KB")

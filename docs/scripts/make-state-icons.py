#!/usr/bin/env python3
"""Draw the agent's five state icons as SVG, for the help site.

The help page has to show a user the icon they will actually see in their
taskbar. Nothing in the repository could produce that: `kerbridge_client::icon`
holds the mapping, the geometry, the halo and the glyph threshold and says
plainly that it has no rasterizer, and the two compositors that do the drawing
are each locked to a platform -- one ends in an `HICON`, the other in an
`NSImage`, and neither runs where a web page is built.

So this is a third compositor, and the cost of a third compositor is drift. It
is paid for by taking every number from the source rather than restating one:
the fractions and the condition mapping from `icon.rs`, the badge inks from the
Windows agent's `theme.rs`, the glyph proportions from its `sys.rs`, and the
headline each state is called from `strings/en.rs`. A constant that moves, or is
renamed, or stops matching between the two agents, fails this script rather than
quietly leaving the help page showing an icon the product no longer draws.

Output goes where `--out` says, which is a build directory rather than a
committed one: `website/` inlines these into every page it renders, so they are
regenerated on every build and there is no committed copy that could go stale.

The two platforms differ in exactly one thing, which is why both are emitted:
Windows colors the badge and draws the glyph in dark ink; macOS keeps a template
image, so the badge is the surface's own ink and the glyph is a hole taken out
of it. Everything else -- the fade, the shapes, the halo -- is shared, and this
draws both from the same numbers so that stays true.

The icons are `currentColor`, matching a tray icon that takes the taskbar's ink,
so a page in either theme inherits the right one. Both are drawn above
`GLYPH_MIN`; below it the product drops the glyph and leaves the shape bare.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ICON_RS = ROOT / "client/kerbridge-client/src/icon.rs"
THEME_RS = ROOT / "client/kerbridge-agent-windows/src/theme.rs"
SYS_RS = ROOT / "client/kerbridge-agent-windows/src/sys.rs"
MAC_RS = ROOT / "client/kerbridge-agent-macos/src/icon.rs"
STRINGS_RS = ROOT / "client/kerbridge-client/src/strings/en.rs"
LOGO_SVG = ROOT / "client/assets/app-icon.svg"

# The box the logo is drawn in. Every constant in `icon.rs` is a fraction of the
# icon's edge, so this is a choice of resolution and not of geometry.
BOX = 1024


def die(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def grab(text, pattern, what, flags=0):
    m = re.search(pattern, text, flags)
    if not m:
        die(f"{what} not found -- this script reads it and cannot guess it")
    return m


def read_geometry():
    """The fractions and the condition mapping, from `icon.rs`."""
    src = ICON_RS.read_text()
    g = {}
    for name in ("FADE", "BADGE", "DISC", "KNOCKOUT", "BANG_DOT"):
        g[name] = float(grab(src, rf"pub const {name}: f32 = ([\d.]+);", name).group(1))
    g["GLYPH_MIN"] = int(grab(src, r"pub const GLYPH_MIN: u32 = (\d+);", "GLYPH_MIN").group(1))

    verts = grab(
        src, r"pub const WARN_VERTICES: \[\(f32, f32\); 3\] = \[([^\]]+)\];", "WARN_VERTICES"
    ).group(1)
    g["WARN_VERTICES"] = [
        (float(x), float(y)) for x, y in re.findall(r"\(\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*\)", verts)
    ]
    if len(g["WARN_VERTICES"]) != 3:
        die("WARN_VERTICES did not parse as three points")

    stem = grab(
        src, r"pub const BANG_STEM: \(f32, f32\) = \(\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*\);", "BANG_STEM"
    )
    g["BANG_STEM"] = (float(stem.group(1)), float(stem.group(2)))

    # `mark()`'s arms, so a condition that is regrouped or added is drawn the way
    # the product draws it rather than the way this script last remembered.
    body = grab(
        src, r"pub fn mark\(condition: Condition\) -> Mark \{(.+?)\n\}", "mark()", re.S
    ).group(1)
    g["MARK"] = {}
    for m in re.finditer(
        r"((?:Condition::\w+(?:\s*\|\s*)?)+?)\s*=>\s*\(([\w.]+),\s*(None|Some\(Badge::(\w+)\))\)",
        body,
    ):
        conditions = re.findall(r"Condition::(\w+)", m.group(1))
        fade = 1.0 if m.group(2) == "1.0" else g["FADE"]
        badge = m.group(4)  # None -> None
        for c in conditions:
            g["MARK"][c] = (fade, badge)
    if not g["MARK"]:
        die("mark() did not parse into a condition mapping")
    return g


def read_inks():
    """The badge colors, from the Windows agent's `theme.rs`."""
    src = THEME_RS.read_text()
    inks = {}
    for name in ("warn", "danger"):
        m = grab(
            src,
            rf"fn {name}\(dark: bool\) -> u32 \{{\s*if dark \{{ rgb\(([^)]+)\) \}} "
            rf"else \{{ rgb\(([^)]+)\) \}}",
            f"theme::{name}()",
        )
        dark, light = (
            "#" + "".join(f"{int(v.strip(), 16):02x}" for v in group.split(","))
            for group in (m.group(1), m.group(2))
        )
        inks[name] = {"dark": dark, "light": light}
    return inks


def read_glyph():
    """The glyph proportions, from the Windows compositor -- and the assertion
    that the macOS one still agrees, since the two hold these numbers twice."""
    src = SYS_RS.read_text()
    stem = grab(src, r"Stroke \{ width: r \* ([\d.]+)", "the glyph stroke width").group(1)
    arm = grab(src, r"let a = r \* ([\d.]+);", "the cross arm length").group(1)
    ink = grab(
        src, r"set_color_rgba8\(0x(\w\w), 0x(\w\w), 0x(\w\w), 0xff\);\n\s*paint\.anti_alias", "the glyph ink"
    )

    mac = MAC_RS.read_text()
    for value, what in ((stem, "glyph stroke width"), (arm, "cross arm length")):
        if f"* {value}" not in mac:
            die(
                f"the {what} is {value} in the Windows compositor and not in the macOS one; "
                "the two are supposed to draw the same shapes"
            )
    return float(stem), float(arm), "#" + "".join(ink.group(i) for i in (1, 2, 3))


def read_headlines():
    """What each condition is called on screen, so the alt text is the product's."""
    src = STRINGS_RS.read_text()
    keys = {
        "Working": "cond_working",
        "Flaky": "cond_flaky",
        "WillStop": "cond_will_stop",
        "Stopped": "cond_stopped",
        "NotStarted": "cond_off",
    }
    return {
        cond: grab(src, rf'{key}: "([^"]*)"', key).group(1) for cond, key in keys.items()
    }


def read_logo():
    """The one committed artwork, as the single path it is."""
    src = LOGO_SVG.read_text()
    view = grab(src, r'viewBox="0 0 (\d+) (\d+)"', "the logo viewBox")
    if view.group(1) != view.group(2):
        die("the logo viewBox is not square; every constant here is a fraction of one edge")
    paths = re.findall(r'\sd="([^"]+)"', src)
    if len(paths) != 1:
        die(f"expected one path in the logo, found {len(paths)}")
    return paths[0], int(view.group(1))


def n(v):
    """A number with no trailing noise, so the output diffs cleanly."""
    return f"{v:.3f}".rstrip("0").rstrip(".")


def badge_path(kind, geo):
    r = BOX * geo["DISC"]
    c = BOX - BOX * geo["BADGE"] / 2.0
    if kind == "Stop":
        return f"M {n(c - r)} {n(c)} a {n(r)} {n(r)} 0 1 0 {n(2 * r)} 0 a {n(r)} {n(r)} 0 1 0 {n(-2 * r)} 0 Z"
    pts = " L ".join(f"{n(c + r * dx)} {n(c + r * dy)}" for dx, dy in geo["WARN_VERTICES"])
    return f"M {pts} Z"


def glyph_path(kind, geo, arm):
    r = BOX * geo["DISC"]
    c = BOX - BOX * geo["BADGE"] / 2.0
    if kind == "Stop":
        a = r * arm
        return (
            f"M {n(c - a)} {n(c - a)} L {n(c + a)} {n(c + a)} "
            f"M {n(c + a)} {n(c - a)} L {n(c - a)} {n(c + a)}"
        )
    top, bottom = geo["BANG_STEM"]
    dot = c + r * geo["BANG_DOT"]
    # The dot is a zero-length subpath under a round cap, exactly as both
    # compositors draw it; the nudge is what keeps it from degenerating away.
    return (
        f"M {n(c)} {n(c + r * top)} L {n(c)} {n(c + r * bottom)} "
        f"M {n(c)} {n(dot)} L {n(c)} {n(dot + 0.01)}"
    )


def render(condition, platform, geo, inks, glyph, headlines, logo):
    stem, arm, glyph_ink = glyph
    logo_d, _ = logo
    fade, kind = geo["MARK"][condition]
    slug = re.sub(r"(?<!^)(?=[A-Z])", "-", condition).lower()
    uid = f"{platform}-{slug}"
    ring = 2.0 * BOX * geo["DISC"] * (geo["KNOCKOUT"] - 1.0)
    stroke_w = BOX * geo["DISC"] * stem

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {BOX} {BOX}" '
        f'width="128" height="128" role="img" aria-labelledby="t-{uid}">',
        f"  <title id=\"t-{uid}\">{headlines[condition]}</title>",
    ]

    if kind:
        badge = badge_path(kind, geo)
        # The halo: a ring cleared along the badge's own silhouette, so the shape
        # keeps an edge where the mark behind it is the same ink.
        out += [
            "  <defs>",
            f'    <mask id="halo-{uid}">',
            f'      <rect width="{BOX}" height="{BOX}" fill="#fff"/>',
            f'      <path d="{badge}" fill="#000" stroke="#000" '
            f'stroke-width="{n(ring)}" stroke-linejoin="round"/>',
            "    </mask>",
        ]
        if platform == "macos":
            # A template image has one ink, so the glyph is a hole rather than a
            # second color.
            out += [
                f'    <mask id="glyph-{uid}">',
                f'      <path d="{badge}" fill="#fff"/>',
                f'      <path d="{glyph_path(kind, geo, arm)}" fill="none" stroke="#000" '
                f'stroke-width="{n(stroke_w)}" stroke-linecap="round"/>',
                "    </mask>",
            ]
        out.append("  </defs>")
        out.append(
            f'  <path d="{logo_d}" fill="currentColor" opacity="{n(fade)}" mask="url(#halo-{uid})"/>'
        )
        if platform == "macos":
            out.append(f'  <path d="{badge}" fill="currentColor" mask="url(#glyph-{uid})"/>')
        else:
            ink = inks["warn" if kind == "Warn" else "danger"]
            out += [
                "  <style>",
                f"    .b-{uid} {{ fill: {ink['light']} }}",
                f"    @media (prefers-color-scheme: dark) {{ .b-{uid} {{ fill: {ink['dark']} }} }}",
                "  </style>",
                f'  <path d="{badge}" class="b-{uid}"/>',
                f'  <path d="{glyph_path(kind, geo, arm)}" fill="none" stroke="{glyph_ink}" '
                f'stroke-width="{n(stroke_w)}" stroke-linecap="round"/>',
            ]
    else:
        out.append(f'  <path d="{logo_d}" fill="currentColor" opacity="{n(fade)}"/>')

    out.append("</svg>")
    return f"{uid}.svg", "\n".join(out) + "\n"


def main():
    args = sys.argv[1:]
    if len(args) != 2 or args[0] != "--out":
        die("usage: make-state-icons.py --out DIR")
    out = Path(args[1])

    geo = read_geometry()
    inks = read_inks()
    glyph = read_glyph()
    headlines = read_headlines()
    logo = read_logo()

    if BOX < geo["GLYPH_MIN"]:
        die(f"the drawing box {BOX} is below GLYPH_MIN {geo['GLYPH_MIN']}")

    files = {}
    for platform in ("windows", "macos"):
        for condition in headlines:
            if condition not in geo["MARK"]:
                die(f"mark() has no arm for Condition::{condition}")
            name, svg = render(condition, platform, geo, inks, glyph, headlines, logo)
            files[name] = svg

    out.mkdir(parents=True, exist_ok=True)
    for name, svg in files.items():
        (out / name).write_text(svg)
    print(f"state icons: wrote {len(files)} files to {out}")


if __name__ == "__main__":
    main()

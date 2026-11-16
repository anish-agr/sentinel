#!/usr/bin/env python
"""Is the paper's figure palette actually colourblind-safe? Measure it."""

import argparse
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FIGDIR = os.path.join(REPO, "paper", "figures")
MAIN = os.path.join(REPO, "paper", "main.tex")

# Fixed before the palette was measured. See the docstring for the derivation;
# the sensitivity band printed at the end is the evidence that the exact value
# is not load-bearing.
MIN_DE = 20.0

GREY_NOTE_DL = 10.0


# ----------------------------------------------------------- colour space ---

def srgb_to_linear(c):
    """sRGB EOTF. IEC 61966-2-1."""
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def linear_to_srgb(c):
    c = min(1.0, max(0.0, c))
    return 12.92 * c if c <= 0.0031308 else 1.055 * (c ** (1 / 2.4)) - 0.055


# sRGB primaries -> CIE XYZ, D65. IEC 61966-2-1.
_M_RGB_XYZ = ((0.4124564, 0.3575761, 0.1804375),
              (0.2126729, 0.7151522, 0.0721750),
              (0.0193339, 0.1191920, 0.9503041))

# CIE standard illuminant D65, 2 degree observer.
_WHITE = (0.95047, 1.00000, 1.08883)


def _mul(m, v):
    return tuple(sum(m[i][j] * v[j] for j in range(3)) for i in range(3))


def rgb_to_lab(rgb):
    """8-bit sRGB triple -> CIELAB (D65, 2 deg)."""
    lin = [srgb_to_linear(c / 255.0) for c in rgb]
    x, y, z = _mul(_M_RGB_XYZ, lin)

    def f(t):
        return t ** (1.0 / 3.0) if t > 216.0 / 24389.0 else \
            (841.0 / 108.0) * t + 4.0 / 29.0

    fx, fy, fz = f(x / _WHITE[0]), f(y / _WHITE[1]), f(z / _WHITE[2])
    return (116.0 * fy - 16.0, 500.0 * (fx - fy), 200.0 * (fy - fz))


def delta_e(lab1, lab2):
    """CIE76 dE*ab. Euclidean distance in CIELAB."""
    return sum((a - b) ** 2 for a, b in zip(lab1, lab2)) ** 0.5


# ------------------------------------------------------- dichromacy model ---
# Machado, Oliveira & Fernandes (2009), Table 1, severity 1.0. Applied to
# LINEAR RGB. Transcribed from the authors' supplementary page; see docstring.
CVD = {
    "protanopia": ((0.152286, 1.052583, -0.204868),
                   (0.114503, 0.786281, 0.099216),
                   (-0.003882, -0.048116, 1.051998)),
    "deuteranopia": ((0.367322, 0.860646, -0.227968),
                     (0.280085, 0.672501, 0.047413),
                     (-0.011820, 0.042940, 0.968881)),
    "tritanopia": ((1.255528, -0.076749, -0.178779),
                   (-0.078411, 0.930809, 0.147602),
                   (0.004733, 0.691367, 0.303900)),
}

VISIONS = ["normal", "protanopia", "deuteranopia", "tritanopia"]


def simulate(rgb, vision, domain="linear"):
    """8-bit sRGB triple as a dichromat sees it, back in 8-bit sRGB."""
    if vision == "normal":
        return tuple(rgb)
    m = CVD[vision]
    if domain == "linear":
        v = [srgb_to_linear(c / 255.0) for c in rgb]
        out = _mul(m, v)
        return tuple(int(round(255.0 * linear_to_srgb(c))) for c in out)
    v = [c / 255.0 for c in rgb]
    out = _mul(m, v)
    return tuple(int(round(255.0 * min(1.0, max(0.0, c)))) for c in out)


# ------------------------------------------------------------ tex parsing ---

class Unparsed(Exception):
    """The source does not have the shape this script knows how to read."""


# xcolor ships these; main.tex only \definecolor s the Okabe-Ito four, but the
# figures use `black` and `white` directly and `black!22` mixes against white.
BUILTIN = {"white": (255, 255, 255), "black": (0, 0, 0),
           "red": (255, 0, 0), "green": (0, 255, 0), "blue": (0, 0, 255),
           "gray": (128, 128, 128), "grey": (128, 128, 128)}


def read_definecolors(path):
    """{name: (r,g,b)} from every \\definecolor in a file."""
    with io.open(path, encoding="utf-8") as fh:
        src = fh.read()
    src = re.sub(r"(?<!\\)%.*", "", src)
    out = dict(BUILTIN)
    for m in re.finditer(r"\\definecolor\s*\{([^}]+)\}\s*\{([^}]+)\}\s*\{([^}]+)\}",
                         src):
        name, model, spec = m.group(1).strip(), m.group(2).strip(), m.group(3)
        if model == "HTML":
            s = spec.strip()
            if len(s) != 6:
                raise Unparsed("\\definecolor{%s}{HTML}{%s} is not 6 hex digits"
                               % (name, s))
            out[name] = tuple(int(s[i:i + 2], 16) for i in (0, 2, 4))
        elif model == "RGB":
            out[name] = tuple(int(float(p)) for p in spec.split(","))
        elif model == "rgb":
            out[name] = tuple(int(round(255 * float(p)))
                              for p in spec.split(","))
        else:
            raise Unparsed("\\definecolor{%s}: colour model %r is not one this "
                           "script can resolve, so its colour would go "
                           "unchecked" % (name, model))
    return out


def resolve(spec, palette):
    """An xcolor colour expression -> (r,g,b)."""
    spec = spec.strip()
    parts = [p.strip() for p in spec.split("!")]
    base = parts[0]
    if base not in palette:
        raise Unparsed("colour %r is used by a figure and is defined nowhere "
                       "this script reads (main.tex \\definecolor, or xcolor's "
                       "built-ins)" % base)
    rgb = palette[base]
    i = 1
    while i < len(parts):
        pct = parts[i]
        if not re.fullmatch(r"\d+(?:\.\d+)?", pct):
            raise Unparsed("cannot resolve colour expression %r" % spec)
        p = float(pct) / 100.0
        # `a!P` means `a!P!white`; `a!P!b` mixes against b. xcolor mixes in the
        # model's own coordinates, i.e. the gamma-encoded values as stored.
        other = palette["white"]
        if i + 1 < len(parts) and parts[i + 1] and \
                not re.fullmatch(r"\d+(?:\.\d+)?", parts[i + 1]):
            nxt = parts[i + 1]
            if nxt not in palette:
                raise Unparsed("colour %r in expression %r is undefined"
                               % (nxt, spec))
            other = palette[nxt]
            i += 1
        rgb = tuple(p * rgb[k] + (1 - p) * other[k] for k in range(3))
        i += 1
    return tuple(int(round(c)) for c in rgb)


def _balanced(src, start):
    """Slice of `src` from the bracket at `start` to its match, exclusive."""
    depth, i = 0, start
    while i < len(src):
        if src[i] == "[":
            depth += 1
        elif src[i] == "]":
            depth -= 1
            if depth == 0:
                return src[start + 1:i], i + 1
        elif src[i] == "{":
            # Skip a brace group wholesale so a `]` inside it cannot close us.
            d2, j = 0, i
            while j < len(src):
                if src[j] == "{":
                    d2 += 1
                elif src[j] == "}":
                    d2 -= 1
                    if d2 == 0:
                        break
                j += 1
            i = j
        i += 1
    raise Unparsed("unbalanced [ ] in a figure's option list")


# Option groups that style FURNITURE, not the series itself. Stripped before
# the series colour is read, and reported as excluded rather than dropped.
FURNITURE_KEYS = ("error bar style", "error mark options", "grid style",
                  "nodes near coords style", "legend style",
                  "tick label style", "label style", "xticklabel style",
                  "y tick label style", "every axis plot")


def _strip_groups(opts, keys):
    """Remove `key={...}` groups, returning (remainder, removed text)."""
    removed = []
    for key in keys:
        while True:
            m = re.search(re.escape(key) + r"\s*=\s*\{", opts)
            if not m:
                break
            d, j = 0, m.end() - 1
            while j < len(opts):
                if opts[j] == "{":
                    d += 1
                elif opts[j] == "}":
                    d -= 1
                    if d == 0:
                        break
                j += 1
            removed.append(opts[m.start():j + 1])
            opts = opts[:m.start()] + opts[j + 1:]
    return opts, removed


DASHES = ("densely dashed", "loosely dashed", "densely dotted",
          "loosely dotted", "dashdotted", "dashed", "dotted", "solid")


def parse_series(opts):
    """One \\addplot's option list -> dict describing the series."""
    body, furniture = _strip_groups(opts, FURNITURE_KEYS)
    mark_opts, mark_removed = _strip_groups(body, ("mark options",))
    body = mark_opts

    colour = None
    for key in ("fill", "color", "draw"):
        m = re.search(r"(?<![\w-])" + key + r"\s*=\s*([A-Za-z][\w!.]*)", body)
        if m:
            colour = m.group(1)
            break

    m = re.search(r"(?<![\w])mark\s*=\s*([\w*+-]+)", body)
    mark = m.group(1) if m else None
    if re.search(r"(?<![\w])mark\s*=\s*none", body or "", re.I):
        mark = None

    dash = "solid"
    for d in DASHES:
        if re.search(r"(?<![\w])" + d.replace(" ", r"\s+") + r"(?![\w])", body):
            dash = d
            break

    m = re.search(r"(?<![\w])pattern\s*=\s*([\w ]+)", body)
    pattern = m.group(1).strip() if m else None

    m = re.search(r"(?<![\w])(?:fill|draw)\s*=\s*([A-Za-z][\w!.]*)",
                  " ".join(mark_removed))
    mark_colour = m.group(1) if m else None

    return {"colour": colour, "mark": mark, "dash": dash, "pattern": pattern,
            "mark_colour": mark_colour, "bar": bool(re.search(r"[xy]bar", body)),
            "furniture": furniture}


def parse_figure(name, src):
    """A figure's source -> {name, series[], labelled, furniture[]}."""
    series, furniture = [], []
    i = 0
    while True:
        m = re.search(r"\\addplot\s*(?:\+\s*)?\[", src[i:])
        if not m:
            break
        start = i + m.end() - 1
        opts, nxt = _balanced(src, start)
        s = parse_series(opts)
        furniture.extend(s.pop("furniture"))
        if s["colour"] is None:
            raise Unparsed("%s: an \\addplot carries no fill/color/draw, so "
                           "its series colour cannot be read" % name)
        series.append(s)
        i = nxt

    labelled = bool(re.search(r"(?<![\w])nodes near coords(?![\w])", src))
    if not labelled:
        nodes = re.findall(r"\\node\b[^;]*?\baxis cs:[^;]*?\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}\s*;",
                           src)
        labelled = sum(1 for t in nodes if re.search(r"\d", t)) >= len(series) \
            and len(series) > 0

    return {"name": name, "series": series, "labelled": labelled,
            "furniture": sorted(set(furniture))}


def discover_figures():
    """Every figure the paper draws, from disk. Never a hand-written list."""
    figs = []
    for fn in sorted(os.listdir(FIGDIR)) if os.path.isdir(FIGDIR) else []:
        if not (fn.startswith("fig-") and fn.endswith(".tex")):
            continue
        with io.open(os.path.join(FIGDIR, fn), encoding="utf-8") as fh:
            src = fh.read()
        if "tikzpicture" not in src:
            continue
        figs.append(parse_figure("figures/" + fn, src))

    with io.open(MAIN, encoding="utf-8") as fh:
        main_src = fh.read()
    main_src = re.sub(r"(?<!\\)%.*", "", main_src)
    for m in re.finditer(r"\\begin\{figure\}(.*?)\\end\{figure\}",
                         main_src, re.S):
        block = m.group(1)
        if "tikzpicture" not in block:
            continue
        lab = re.search(r"\\label\{([^}]+)\}", block)
        figs.append(parse_figure("main.tex/" + (lab.group(1) if lab
                                                else "unlabelled"), block))
    return figs


# ---------------------------------------------------------------- checking ---

def pair_distances(rgb_a, rgb_b, domain="linear"):
    """{vision: dE} for one pair of 8-bit sRGB colours."""
    return {v: delta_e(rgb_to_lab(simulate(rgb_a, v, domain)),
                       rgb_to_lab(simulate(rgb_b, v, domain)))
            for v in VISIONS}


def check_figures(figs, palette, threshold, verbose):
    """(ok, rows, redundancy_rows). Prints nothing; the caller formats."""
    rows, red = [], []
    for fig in figs:
        cols = []
        for idx, s in enumerate(fig["series"]):
            cols.append((s["colour"], resolve(s["colour"], palette)))
        for a in range(len(cols)):
            for b in range(a + 1, len(cols)):
                (na, ra), (nb, rb) = cols[a], cols[b]
                d_lin = pair_distances(ra, rb, "linear")
                d_gam = pair_distances(ra, rb, "gamma")
                worst = min(d_lin[v] for v in VISIONS)
                worst_v = min(VISIONS, key=lambda v: d_lin[v])
                agree = (min(d_gam.values()) >= threshold) == \
                        (worst >= threshold)
                dl = abs(rgb_to_lab(ra)[0] - rgb_to_lab(rb)[0])
                rows.append({"fig": fig["name"], "a": na, "b": nb,
                             "rgb_a": ra, "rgb_b": rb, "d": d_lin,
                             "d_gamma": d_gam, "worst": worst,
                             "worst_vision": worst_v, "dl": dl,
                             "ok": worst >= threshold, "domain_agree": agree})

        if len(fig["series"]) >= 2:
            marks = [s["mark"] for s in fig["series"]]
            dashes = [s["dash"] for s in fig["series"]]
            pats = [s["pattern"] for s in fig["series"]]
            channels = []
            if all(marks) and len(set(marks)) == len(marks):
                channels.append("distinct marks (%s)" % ", ".join(marks))
            if len(set(dashes)) == len(dashes):
                channels.append("distinct dash patterns (%s)"
                                % ", ".join(dashes))
            if all(pats) and len(set(pats)) == len(pats):
                channels.append("distinct fill patterns")
            if fig["labelled"]:
                channels.append("value printed on every datum")
            red.append({"fig": fig["name"], "n": len(fig["series"]),
                        "channels": channels, "ok": bool(channels)})
    ok = all(r["ok"] for r in rows) and all(r["ok"] for r in red) \
        and all(r["domain_agree"] for r in rows)
    return ok, rows, red


def sensitivity_band(rows, red):
    """(lo, hi, binding_row): thresholds over which the verdict would not change."""
    if not all(r["ok"] for r in rows) or not all(r["ok"] for r in red):
        return None
    worst = min(rows, key=lambda r: r["worst"])
    return (0.0, worst["worst"], worst)


# -------------------------------------------------------------- controls ----

def controls(threshold):
    """The six positive controls. Returns [(id, description, passed)]."""
    out = []

    # C1. Published CIELAB of the sRGB primaries, D65/2deg. If the colour
    # conversion is wrong, every distance below is wrong and would still look
    # plausible.
    known = {(255, 0, 0): (53.2408, 80.0925, 67.2032),
             (0, 255, 0): (87.7347, -86.1827, 83.1793),
             (0, 0, 255): (32.2970, 79.1875, -107.8602),
             (255, 255, 255): (100.0, 0.0, 0.0),
             (0, 0, 0): (0.0, 0.0, 0.0)}
    worst = max(max(abs(g - w) for g, w in zip(rgb_to_lab(k), v))
                for k, v in known.items())
    out.append(("C1", "sRGB->CIELAB matches the published primaries "
                      "(max err %.4f)" % worst, worst < 0.01))

    # C2. The distance is a metric.
    p, q = (12, 34, 56), (200, 100, 30)
    lp, lq = rgb_to_lab(p), rgb_to_lab(q)
    out.append(("C2", "distance is symmetric and zero on identity",
                abs(delta_e(lp, lp)) < 1e-12
                and abs(delta_e(lp, lq) - delta_e(lq, lp)) < 1e-12
                and delta_e(lp, lq) > 0))

    # C3. A dichromacy matrix that had been transposed or mistyped would move
    # neutral greys off the neutral axis. This is the cheapest check that the
    # transcription in CVD is the transcription intended.
    grey_ok = True
    for v in CVD:
        for g in (64, 128, 192):
            sim = simulate((g, g, g), v)
            if delta_e(rgb_to_lab((g, g, g)), rgb_to_lab(sim)) > 3.0:
                grey_ok = False
    out.append(("C3", "the dichromacy matrices leave neutral greys neutral",
                grey_ok))

    # C4. THE ONE THAT MATTERS. matplotlib's default red and green: a pair
    # that any colourblind-safety guide names as a collision. If this passes
    # the threshold under deuteranopia, this whole script is decoration.
    bad_a, bad_b = (0xD6, 0x27, 0x28), (0x2C, 0xA0, 0x2C)
    d_bad = pair_distances(bad_a, bad_b)
    out.append(("C4", "a red/green pair collides under deuteranopia "
                      "(dE %.1f normal -> %.1f deuteranopic, threshold %.0f)"
                % (d_bad["normal"], d_bad["deuteranopia"], threshold),
                d_bad["normal"] >= threshold
                and d_bad["deuteranopia"] < threshold))

    # C5. ... and a pair that IS safe survives, so C4 is not a checker that
    # rejects every pair it is shown.
    good = pair_distances((0x00, 0x72, 0xB2), (0xD5, 0x5E, 0x00))
    out.append(("C5", "Okabe-Ito blue/vermillion survives all three "
                      "(worst dE %.1f)" % min(good.values()),
                min(good.values()) >= threshold))

    # C6. The non-colour-reliance test must be able to reject. Two bar series
    # with no mark, no dash difference and no printed value.
    naked = parse_figure("control", r"""
      \begin{tikzpicture}\begin{axis}[ybar]
        \addplot[ybar, fill=okBlue] coordinates {(1,2)};
        \addplot[ybar, fill=okVerm] coordinates {(1,3)};
      \end{axis}\end{tikzpicture}""")
    _ok, _r, red = check_figures([naked],
                                 {"okBlue": (0, 114, 178),
                                  "okVerm": (213, 94, 0),
                                  "white": (255, 255, 255)},
                                 threshold, False)
    out.append(("C6", "two series with no mark, dash or printed value are "
                      "rejected as colour-only", bool(red) and not red[0]["ok"]))
    return out


# ------------------------------------------------------------------ main ----

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verbose", action="store_true",
                    help="print every pair, every vision, and the excluded "
                         "furniture colours")
    ap.add_argument("--positive-control", action="store_true",
                    help="splice a known-colliding red/green pair into the "
                         "real figure set; this program must then FAIL")
    ap.add_argument("--threshold", type=float, default=MIN_DE,
                    help="dE*ab a same-figure pair must keep under every "
                         "vision (default %(default)s)")
    args = ap.parse_args()

    print("")
    print("  PALETTE CHECK - dichromacy separation and non-colour redundancy")
    print("  Machado, Oliveira & Fernandes 2009 (severity 1.0) over CIE76 "
          "dE*ab,")
    print("  threshold %.0f. Colours are read from the figures, never typed "
          "here." % args.threshold)
    print("")

    palette = read_definecolors(MAIN)
    figs = discover_figures()

    # A checker that finds nothing must not report success. Both of these are
    # the "passed by not looking" shape and both are fatal.
    if not figs:
        print("  FAIL  no figure was found in paper/figures/ or main.tex.")
        return 1
    if len(palette) <= len(BUILTIN):
        print("  FAIL  main.tex defines no colours; nothing was resolved.")
        return 1
    if not any(f["series"] for f in figs):
        print("  FAIL  figures were found but not one \\addplot was read.")
        return 1

    if args.positive_control:
        # END-TO-END control. Not a unit assertion: the colliding pair is put
        # into the real corpus and the whole program must come back FAIL.
        palette = dict(palette)
        palette["pcRed"], palette["pcGreen"] = (0xD6, 0x27, 0x28), (0x2C, 0xA0, 0x2C)
        figs.append(parse_figure("POSITIVE-CONTROL/red-green", r"""
          \begin{tikzpicture}\begin{axis}[ybar]
            \addplot[ybar, fill=pcRed, mark=*] coordinates {(1,2)};
            \addplot[ybar, fill=pcGreen, mark=square*] coordinates {(1,3)};
          \end{axis}\end{tikzpicture}"""))
        print("  positive control: a red/green pair has been spliced into the")
        print("  figure set. This run MUST report FAIL and exit 1.")
        print("")

    print("  palette, as \\definecolor s it (%d defined + %d xcolor built-ins)"
          % (len(palette) - len(BUILTIN), len(BUILTIN)))
    for name in sorted(n for n in palette if n not in BUILTIN):
        r, g, b = palette[name]
        lab = rgb_to_lab((r, g, b))
        print("    %-10s #%02X%02X%02X   L*=%5.1f" % (name, r, g, b, lab[0]))
    print("")

    ok, rows, red = check_figures(figs, palette, args.threshold, args.verbose)

    print("  figures found: %d, data series: %d, same-figure pairs: %d"
          % (len(figs), sum(len(f["series"]) for f in figs), len(rows)))
    print("")
    print("  %-28s %-13s %-13s %7s %7s %7s %7s  %s"
          % ("figure", "colour A", "colour B", "normal", "prot", "deut",
             "trit", ""))
    for r in rows:
        print("  %-28s %-13s %-13s %7.1f %7.1f %7.1f %7.1f  %s"
              % (r["fig"][-28:], r["a"], r["b"], r["d"]["normal"],
                 r["d"]["protanopia"], r["d"]["deuteranopia"],
                 r["d"]["tritanopia"],
                 "ok" if r["ok"] else "FAIL (%s)" % r["worst_vision"]))
        if not r["domain_agree"]:
            print("        FAIL  the verdict flips if the Machado matrix is "
                  "applied in gamma-encoded rather than linear RGB; that is "
                  "not a measurement, it is a coin toss")
    print("")

    print("  not relying on colour alone")
    for r in red:
        print("    %-28s %d series: %s"
              % (r["fig"][-28:], r["n"],
                 "; ".join(r["channels"]) if r["channels"]
                 else "COLOUR ONLY - no mark, dash, pattern or printed value"))
    print("")

    if args.verbose:
        print("  excluded as furniture (not a data-decoding comparison)")
        seen = set()
        for f in figs:
            for item in f["furniture"]:
                key = re.sub(r"\s+", " ", item)[:72]
                if key not in seen:
                    seen.add(key)
                    print("    %s  %s" % (f["name"][-24:], key))
        print("")
        print("  greyscale lightness separation (reported, not gated)")
        for r in rows:
            print("    %-28s %-13s %-13s dL* = %5.1f%s"
                  % (r["fig"][-28:], r["a"], r["b"], r["dl"],
                     "   <- close in greyscale" if r["dl"] < GREY_NOTE_DL
                     else ""))
        print("")

    print("  positive controls")
    ctl = controls(args.threshold)
    for cid, desc, passed in ctl:
        print("    %-4s %-4s %s" % (cid, "ok" if passed else "FAIL", desc))
    print("")

    controls_ok = all(p for _c, _d, p in ctl)
    if not controls_ok:
        print("  FAIL  a positive control did not fire. The palette result "
              "below")
        print("        is not evidence of anything: a checker whose controls "
              "fail")
        print("        cannot distinguish a safe palette from an unchecked "
              "one.")
        return 1

    band = sensitivity_band(rows, red)
    if band:
        lo, hi, worst = band
        print("  threshold sensitivity: the verdict is unchanged for any "
              "threshold")
        print("  in [%.0f, %.1f]; the binding pair is %s vs %s in %s, at %.1f"
              % (lo, hi, worst["a"], worst["b"], worst["fig"], hi))
        print("  under %s. The chosen %.0f is not what produced the verdict, "
              "but a" % (worst["worst_vision"], args.threshold))
        print("  threshold above %.1f would change it, so the margin is %.1f "
              "and not more." % (hi, hi - args.threshold))
        print("")

    if ok:
        print("  PASS  every same-figure pair stays >= %.0f dE*ab apart under"
              % args.threshold)
        print("        normal vision and all three dichromacies, and no "
              "figure")
        print("        distinguishes its series by colour alone.")
        return 0

    print("  FAIL  the palette is not colourblind-safe as drawn.")
    for r in rows:
        if not r["ok"]:
            print("        %s: %s vs %s collapses to %.1f dE*ab under %s"
                  % (r["fig"], r["a"], r["b"], r["worst"], r["worst_vision"]))
    for r in red:
        if not r["ok"]:
            print("        %s: %d series separated by colour alone"
                  % (r["fig"], r["n"]))
    return 1


if __name__ == "__main__":
    sys.exit(main())

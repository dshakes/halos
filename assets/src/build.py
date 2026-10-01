#!/usr/bin/env python3
"""Generate the Halos diagram set (README assets + docs diagrams).

Stdlib only. Every diagram is drawn once and emitted as a light/dark pair so
layout never drifts between themes:

    python3 assets/src/build.py

Writes assets/<name>-{light,dark}.svg and docs/public/diagrams/<name>-{light,dark}.svg.
Text widths are estimated and asserted, so a label that would overflow its box
fails the build instead of shipping.
"""

from __future__ import annotations

import math
import pathlib
from xml.sax.saxutils import escape

ROOT = pathlib.Path(__file__).resolve().parents[2]
ASSETS = ROOT / "assets"
DOCS = ROOT / "docs" / "public" / "diagrams"

SANS = "ui-sans-serif,-apple-system,Inter,'Segoe UI',sans-serif"
MONO = "ui-monospace,'SF Mono','JetBrains Mono',Menlo,Consolas,monospace"

THEMES = {
    "light": dict(
        canvas="#fbfcfd",
        canvas_line="#e6eaf0",
        card="#ffffff",
        card_line="#e2e8f0",
        zone="#f4f6f9",
        zone_line="#dfe5ec",
        text="#0b1220",
        text2="#475569",
        text3="#64748b",
        line="#94a3b8",
        a0="#0d9488",
        a1="#4f46e5",
        soft=0.07,
        danger="#dc2626",
        danger_soft="#fef2f2",
        shadow="#0f172a",
        shadow_op=0.07,
        chip="#f1f5f9",
        on_accent="#ffffff",
    ),
    "dark": dict(
        canvas="#0f141a",
        canvas_line="#232a33",
        card="#161b22",
        card_line="#2b3440",
        zone="#131921",
        zone_line="#262f3a",
        text="#e6edf3",
        text2="#9aa7b4",
        text3="#7d8794",
        line="#56606c",
        a0="#2dd4bf",
        a1="#818cf8",
        soft=0.12,
        danger="#f87171",
        danger_soft="#2a1517",
        shadow="#000000",
        shadow_op=0.45,
        chip="#1c232c",
        on_accent="#0b1220",
    ),
}


# --------------------------------------------------------------- text metrics
def tw(s: str, size: float, weight: int = 400, mono: bool = False) -> float:
    """Conservative width estimate for the sans/mono stacks above."""
    if mono:
        return len(s) * size * 0.61
    w = 0.0
    for ch in s:
        if ch in "il.,:;!|'`ıj":
            w += 0.27
        elif ch in " ()[]/-ft·":
            w += 0.34
        elif ch in "mwMW%@":
            w += 0.86
        elif ch.isupper() or ch in "×→←⇄":
            w += 0.67
        elif ch.isdigit():
            w += 0.58
        else:
            w += 0.54
    return w * size * (1.06 if weight >= 600 else 1.0)


def fits(s, size, maxw, weight=400, mono=False, what=""):
    w = tw(s, size, weight, mono)
    assert w <= maxw + 0.5, (
        f"text overflow ({what}): {s!r} needs {w:.0f}px, has {maxw:.0f}px"
    )


# --------------------------------------------------------------- svg builder
class D:
    def __init__(self, name, w, h, title, desc, *, frame=True, out=("docs",)):
        self.name, self.w, self.h = name, w, h
        self.title, self.desc, self.frame, self.out = title, desc, frame, out
        self.body: list[str] = []
        self.anim = False

    # primitives -------------------------------------------------------------
    def add(self, s):
        self.body.append(s)

    def text(
        self,
        x,
        y,
        s,
        cls="s",
        anchor="start",
        maxw=None,
        size=None,
        weight=400,
        mono=False,
    ):
        if maxw is not None:
            fits(s, size or 12, maxw, weight, mono, self.name)
        a = "" if anchor == "start" else f' text-anchor="{anchor}"'
        self.add(f'<text class="{cls}" x="{x:g}" y="{y:g}"{a}>{escape(s)}</text>')

    def kicker(self, x, y, s, accent=True, anchor="start"):
        cls = "k ka" if accent else "k"
        self.text(x, y, s.upper(), cls, anchor)

    def card(
        self,
        x,
        y,
        w,
        h,
        title=None,
        subs=(),
        kind="card",
        kicker=None,
        mono_sub=False,
        pad=16,
        rx=12,
        title_mono=False,
        center=False,
    ):
        """kind: card | accent | danger | ghost | chip"""
        if kind == "ghost":
            self.add(
                f'<rect class="ghost" x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}"/>'
            )
        else:
            self.add(
                f'<rect class="card" x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" filter="url(#sh)"/>'
            )
            if kind == "accent":
                self.add(
                    f'<rect class="soft" x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}"/>'
                )
                self.add(
                    f'<rect class="ring" x="{x + 0.75}" y="{y + 0.75}" width="{w - 1.5}" height="{h - 1.5}" rx="{rx - 0.75}"/>'
                )
            elif kind == "danger":
                self.add(
                    f'<rect class="dcard" x="{x + 0.75}" y="{y + 0.75}" width="{w - 1.5}" height="{h - 1.5}" rx="{rx - 0.75}"/>'
                )
        inner = w - 2 * pad
        # vertical rhythm: kicker 16, title 19, sub 16
        block = (16 if kicker else 0) + (19 if title else 0) + 16 * len(subs) - 4
        cy = y + (h - block) / 2 + 10
        tx = x + w / 2 if center else x + pad
        anchor = "middle" if center else "start"
        if kicker:
            fits(kicker.upper(), 10.5, inner, 600, False, self.name)
            self.kicker(tx, cy, kicker, accent=kind != "danger", anchor=anchor)
            cy += 16
        if title:
            cls = "tm" if title_mono else "t"
            self.text(
                tx,
                cy + 2,
                title,
                cls + (" td" if kind == "danger" else ""),
                anchor,
                maxw=inner,
                size=13.5 if not title_mono else 12.5,
                weight=600,
                mono=title_mono,
            )
            cy += 19
        for s in subs:
            self.text(
                tx,
                cy + 1,
                s,
                "m" if mono_sub else "s",
                anchor,
                maxw=inner,
                size=11 if mono_sub else 12,
                mono=mono_sub,
            )
            cy += 16
        return (x, y, w, h)

    def zone(self, x, y, w, h, label, danger=False, sub=None):
        self.add(
            f'<rect class="zone" x="{x}" y="{y}" width="{w}" height="{h}" rx="16"/>'
        )
        self.kicker(x + 16, y + 24, label, accent=not danger)
        if sub:
            self.text(x + w - 16, y + 24, sub, "xs", "end")

    def pill(self, cx, cy, s, kind="label", mono=False, size=10.5):
        """Label on top of a line: knocks out the line behind it."""
        w = tw(s, size, 500, mono) + 14
        cls = {"label": "pl", "accent": "pa", "danger": "pd", "solid": "ps"}[kind]
        tcls = {"label": "xs", "accent": "xs xa", "danger": "xs xd", "solid": "xs xw"}[
            kind
        ]
        if mono:
            tcls += " xm"
        self.add(
            f'<rect class="{cls}" x="{cx - w / 2:.1f}" y="{cy - 9}" width="{w:.1f}" height="18" rx="9"/>'
        )
        self.text(cx, cy + 3.6, s, tcls, "middle")
        return w

    def path(
        self,
        pts,
        kind="line",
        head=True,
        r=10,
        dashed=False,
        flow=False,
        start_dot=False,
    ):
        """Orthogonal polyline with rounded corners and a drawn chevron head.

        kind: line | accent | danger | muted
        """
        d = _rounded(pts, r)
        cls = {"line": "ln", "accent": "la", "danger": "ld", "muted": "lm"}[kind]
        if dashed:
            cls += " dash"
        if flow:
            cls += " flow"
            self.anim = True
        self.add(f'<path class="{cls}" d="{d}"/>')
        if head:
            (x0, y0), (x1, y1) = pts[-2], pts[-1]
            ang = math.atan2(y1 - y0, x1 - x0)
            s = 6.5
            p1 = (x1 - s * math.cos(ang - 0.55), y1 - s * math.sin(ang - 0.55))
            p2 = (x1 - s * math.cos(ang + 0.55), y1 - s * math.sin(ang + 0.55))
            hcls = {"line": "ln", "accent": "la", "danger": "ld", "muted": "lm"}[kind]
            self.add(
                f'<path class="{hcls} hd" d="M{p1[0]:.1f} {p1[1]:.1f}L{x1:g} {y1:g}L{p2[0]:.1f} {p2[1]:.1f}"/>'
            )
        if start_dot:
            x, y = pts[0]
            dc = {"line": "dl", "accent": "da", "danger": "dd", "muted": "dl"}[kind]
            self.add(f'<circle class="{dc}" cx="{x:g}" cy="{y:g}" r="2.6"/>')
        return d

    def packet(self, d, dur=4, begin=0, r=3.2, under=False):
        self.anim = True
        (self.body.insert if under else (lambda _i, x: self.body.append(x)))(
            0,
            f'<circle class="pkt" r="{r}"><animateMotion dur="{dur}s" begin="{-begin}s" '
            f'repeatCount="indefinite" rotate="auto" path="{d}"/></circle>',
        )

    def badge(self, cx, cy, n):
        self.add(f'<circle class="bdg" cx="{cx}" cy="{cy}" r="8"/>')
        self.add(
            f'<text class="bn" x="{cx}" y="{cy + 3.4}" text-anchor="middle">{n}</text>'
        )

    # output -----------------------------------------------------------------
    def render(self, theme):
        c = THEMES[theme]
        css = STYLE.format(SANS=SANS, MONO=MONO, **c)
        frame = (
            f'<rect class="cv" x=".75" y=".75" width="{self.w - 1.5}" height="{self.h - 1.5}" rx="16"/>'
            if self.frame
            else ""
        )
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" '
            f'height="{self.h}" role="img" aria-labelledby="t d" font-family="{SANS}">\n'
            f'<title id="t">{escape(self.title)}</title>\n<desc id="d">{escape(self.desc)}</desc>\n'
            f"<style>{css}</style>\n"
            f"<defs>\n"
            f'<linearGradient id="ga" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="{self.w}" y2="0">'
            f'<stop offset="0" stop-color="{c["a0"]}"/><stop offset="1" stop-color="{c["a1"]}"/></linearGradient>\n'
            f'<linearGradient id="gs" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="{self.w}" y2="0">'
            f'<stop offset="0" stop-color="{c["a0"]}" stop-opacity="{c["soft"]}"/>'
            f'<stop offset="1" stop-color="{c["a1"]}" stop-opacity="{c["soft"]}"/></linearGradient>\n'
            f'<filter id="sh" x="-10%" y="-10%" width="120%" height="140%">'
            f'<feDropShadow dx="0" dy="1" stdDeviation="1.6" flood-color="{c["shadow"]}" flood-opacity="{c["shadow_op"]}"/>'
            f"</filter>\n</defs>\n{frame}\n" + "\n".join(self.body) + "\n</svg>\n"
        )

    def write(self):
        for theme in THEMES:
            svg = self.render(theme)
            for where in self.out:
                d = ASSETS if where == "assets" else DOCS
                d.mkdir(parents=True, exist_ok=True)
                (d / f"{self.name}-{theme}.svg").write_text(svg)


STYLE = """
.cv{{fill:{canvas};stroke:{canvas_line};stroke-width:1.5}}
.card{{fill:{card};stroke:{card_line};stroke-width:1.5}}
.soft{{fill:url(#gs)}}
.ring{{fill:none;stroke:url(#ga);stroke-width:1.5}}
.dcard{{fill:{danger_soft};stroke:{danger};stroke-width:1.5}}
.ghost{{fill:none;stroke:{line};stroke-width:1.5;stroke-dasharray:4 4}}
.zone{{fill:{zone};stroke:{zone_line};stroke-width:1.5}}
.chip{{fill:{chip};stroke:{card_line};stroke-width:1}}
text{{font-family:{SANS}}}
.t{{font-size:13.5px;font-weight:600;fill:{text}}}
.tm{{font:600 12.5px {MONO};fill:{text}}}
.td{{fill:{danger}}}
.s{{font-size:12px;fill:{text2}}}
.m{{font:11px {MONO};fill:{text2}}}
.xs{{font-size:10.5px;font-weight:500;fill:{text3}}}
.xm{{font-family:{MONO};font-weight:400}}
.xa{{fill:url(#ga);font-weight:600}}
.xd{{fill:{danger};font-weight:600}}
.xw{{fill:{on_accent};font-weight:600}}
.k{{font-size:10.5px;font-weight:600;letter-spacing:.08em;fill:{text3}}}
.ka{{fill:url(#ga)}}
.h1{{font-size:42px;font-weight:700;letter-spacing:-.02em;fill:{text}}}
.ln,.la,.ld,.lm{{fill:none;stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round}}
.ln{{stroke:{line}}}.la{{stroke:url(#ga)}}.ld{{stroke:{danger}}}.lm{{stroke:{card_line}}}
.lane{{stroke:{card_line};stroke-width:1.5;stroke-dasharray:3 4}}
.dash{{stroke-dasharray:5 5}}
.dl{{fill:{line}}}.da{{fill:url(#ga)}}.dd{{fill:{danger}}}
.pl{{fill:{canvas}}}.pa{{fill:{canvas};stroke:url(#ga);stroke-width:1}}
.pd{{fill:{danger_soft};stroke:{danger};stroke-width:1}}.ps{{fill:url(#ga)}}
.fa{{fill:url(#ga)}}.fs{{fill:url(#gs)}}.fm{{fill:{chip}}}.fd{{fill:{danger}}}.ft{{fill:{text}}}
.bdg{{fill:url(#ga)}}.bn{{font-size:9.5px;font-weight:700;fill:{on_accent}}}
.ic{{fill:none;stroke:url(#ga);stroke-width:1.75;stroke-linecap:round;stroke-linejoin:round}}
.pkt{{fill:url(#ga)}}
.grow{{transform-box:fill-box;transform-origin:left;animation:grow 4.8s cubic-bezier(.6,0,.2,1) infinite}}
@keyframes grow{{0%{{transform:scaleX(.08)}}25%{{transform:scaleX(.3)}}50%{{transform:scaleX(.55)}}75%,100%{{transform:scaleX(1)}}}}
.flow{{stroke-dasharray:4 6;animation:flow 1.1s linear infinite}}
@keyframes flow{{to{{stroke-dashoffset:-20}}}}
.blink{{animation:blink 3.2s ease-in-out infinite}}
@keyframes blink{{0%,100%{{opacity:.18}}35%,65%{{opacity:1}}}}
.pulse{{transform-box:fill-box;transform-origin:center;animation:pulse 2.8s ease-out infinite}}
@keyframes pulse{{0%{{opacity:.55;transform:scale(.6)}}100%{{opacity:0;transform:scale(1.5)}}}}
@media (prefers-reduced-motion:reduce){{.flow,.blink,.pulse,.grow{{animation:none}}.blink{{opacity:1}}.pulse,.pkt{{display:none}}}}
"""


def _rounded(pts, r):
    if len(pts) == 2 or r == 0:
        return "M" + "L".join(f"{x:g} {y:g}" for x, y in pts)
    out = [f"M{pts[0][0]:g} {pts[0][1]:g}"]
    for i in range(1, len(pts) - 1):
        (x0, y0), (x1, y1), (x2, y2) = pts[i - 1], pts[i], pts[i + 1]
        l1 = math.hypot(x1 - x0, y1 - y0)
        l2 = math.hypot(x2 - x1, y2 - y1)
        rr = min(r, l1 / 2, l2 / 2)
        ax, ay = x1 - (x1 - x0) / l1 * rr, y1 - (y1 - y0) / l1 * rr
        bx, by = x1 + (x2 - x1) / l2 * rr, y1 + (y2 - y1) / l2 * rr
        out.append(f"L{ax:.1f} {ay:.1f}Q{x1:g} {y1:g} {bx:.1f} {by:.1f}")
    out.append(f"L{pts[-1][0]:g} {pts[-1][1]:g}")
    return "".join(out)


def hrow(
    d,
    y,
    h,
    items,
    x0=24,
    x1=None,
    gap=40,
    kind="card",
    arrows=True,
    akind="line",
    flow=False,
    **kw,
):
    """Equal-width cards in a row joined by arrows. items: (title, [subs]) or dict."""
    x1 = x1 or d.w - 24
    n = len(items)
    w = (x1 - x0 - gap * (n - 1)) / n
    boxes = []
    for i, it in enumerate(items):
        x = x0 + i * (w + gap)
        if isinstance(it, dict):
            args = dict(kw)
            args.update(it)
            d.card(round(x, 1), y, round(w, 1), h, **args)
        else:
            t, subs = it[0], it[1] if len(it) > 1 else ()
            k = it[2] if len(it) > 2 else kind
            d.card(round(x, 1), y, round(w, 1), h, t, subs, kind=k, **kw)
        boxes.append((x, y, w, h))
    if arrows:
        for a, b in zip(boxes, boxes[1:]):
            d.path(
                [(a[0] + a[2] + 6, y + h / 2), (b[0] - 6, y + h / 2)], akind, flow=flow
            )
    return boxes


# =============================================================== README set
def hero():
    d = D(
        "hero",
        880,
        318,
        "Halos",
        "Policy as code becomes a signed release, rolls out through rings 0, 1, 2 and GA to every "
        "environment, and evidence from evals and telemetry loops back to promote or roll back.",
        frame=False,
        out=("assets", "docs"),
    )
    # wordmark: three concentric rings = rollout rings
    cx, cy = 372, 54
    d.add(f'<circle class="pulse fs" cx="{cx}" cy="{cy}" r="22"/>')
    d.add(f'<circle class="ic" cx="{cx}" cy="{cy}" r="21" opacity=".35"/>')
    d.add(f'<circle class="ic" cx="{cx}" cy="{cy}" r="13.5" opacity=".7"/>')
    d.add(f'<circle class="fa" cx="{cx}" cy="{cy}" r="6"/>')
    d.text(cx + 34, cy + 15, "Halos", "h1")
    # flow row
    y, h, w, step = 112, 112, 168, 221
    xs = [24 + i * step for i in range(4)]
    d.card(
        xs[0],
        y,
        w,
        h,
        "Policy repo",
        ["profiles · rings", "experiments · YAML"],
        kicker="01 · Policy",
    )
    d.card(
        xs[1],
        y,
        w,
        h,
        "Signed release",
        ["OCI · ed25519", "content-addressed"],
        kind="accent",
        kicker="02 · Release",
    )
    d.card(xs[2], y, w, h, "Rollout rings", ["", ""], kicker="03 · Rings")
    d.card(
        xs[3],
        y,
        w,
        h,
        "Everywhere",
        ["laptops · containers", "CI · Kubernetes"],
        kicker="04 · Deliver",
    )
    # ring chips + exposure bar that fills ring by ring
    cw, cg = 30, 5.3
    for i, lab in enumerate(["r0", "r1", "r2", "GA"]):
        x = xs[2] + 16 + i * (cw + cg)
        d.add(
            f'<rect class="chip" x="{x:.1f}" y="{y + 56}" width="{cw}" height="22" rx="6"/>'
        )
        d.text(x + cw / 2, y + 71, lab, "xs xm", "middle")
    d.add(
        f'<rect class="fm" x="{xs[2] + 16}" y="{y + 86}" width="136" height="4" rx="2"/>'
    )
    d.add(
        f'<rect class="fa grow" x="{xs[2] + 16}" y="{y + 86}" width="136" height="4" rx="2"/>'
    )
    for i in range(3):
        d.path(
            [(xs[i] + w + 8, y + h / 2), (xs[i + 1] - 8, y + h / 2)],
            "accent",
            flow=True,
        )
    # evidence loop back
    by = y + h
    loop = [
        (xs[3] + w / 2, by + 6),
        (xs[3] + w / 2, by + 54),
        (xs[0] + w / 2, by + 54),
        (xs[0] + w / 2, by + 8),
    ]
    lp = d.path(loop, "accent", dashed=True, r=16)
    d.packet(lp, dur=5)
    for i in range(3):
        d.packet(
            f"M{xs[i] + w + 8} {y + h / 2}L{xs[i + 1] - 8} {y + h / 2}",
            dur=1.6,
            begin=i * 0.5,
        )
    d.pill(
        440,
        by + 54,
        "evidence: evals · telemetry · mSPRT  →  promote PR or auto-rollback",
        "accent",
    )
    d.write()


def architecture():
    d = D(
        "architecture",
        880,
        560,
        "Halos architecture",
        "Policy compiles to a signed release and ring pointers. The client plane (halod, MDM, Dev "
        "Container Feature, Coder, CI action) applies it; the traffic plane (halo-proxy or the Kong "
        "plugin) routes to Anthropic, Bedrock, Vertex or OpenAI; the evidence plane (OTEL, ClickHouse, "
        "halo eval, controller, console, MCP) proposes promotion PRs and fires the kill switch.",
        out=("assets", "docs"),
    )
    # control bar
    d.zone(24, 24, 832, 96, "Policy → release")
    hrow(
        d,
        52,
        52,
        [
            ("Policy repo", ["git · YAML · review"]),
            ("halo release", ["compile · validate · sign"]),
            ("Signed release", ["OCI · ed25519 · signed"], "accent"),
            ("Ring pointers", ["r0 → r1 → r2 → GA"]),
        ],
        x0=40,
        x1=840,
        gap=28,
        akind="accent",
    )
    cols = [24, 320, 616]
    pw, top, ph = 240, 168, 368
    planes = [
        (
            "Client plane",
            "on the machine",
            [
                ("halod", ["agent · macOS, Linux, Windows"]),
                ("MDM exports", ["Jamf · Kandji · Intune"]),
                ("Dev Container Feature", ["devcontainers · Codespaces"]),
                ("Coder module", ["cloud workspaces"]),
                ("CI action", ["runners · headless evals"]),
                ("Harnesses", ["Claude Code · Codex · Gemini"]),
            ],
        ),
        (
            "Traffic plane",
            "in the request path",
            [
                ("halo-proxy", ["OIDC · model routes · failover"], "accent"),
                ("Kong + halo-kong", ["drop-in gateway plugin"]),
                ("halo-shadow", ["async first-turn mirror"]),
            ],
        ),
        (
            "Evidence plane",
            "decides",
            [
                ("OTEL collector", ["normalize to halo.*"]),
                ("ClickHouse", ["halo.* tables"]),
                ("halo eval", ["pass@k · LLM judge · matrix"]),
                ("controller", ["mSPRT verdicts · rollback"], "accent"),
                ("halo-server console", ["portal · kill switch"]),
                ("MCP", ["halo mcp serve · agents"]),
            ],
        ),
    ]
    for (label, sub, items), x in zip(planes, cols):
        d.zone(x, top, pw, ph, label, sub=sub)
        for i, it in enumerate(items):
            kind = it[2] if len(it) > 2 else "card"
            d.card(x + 12, top + 40 + i * 54, pw - 24, 46, it[0], it[1], kind=kind)
    # providers block in traffic plane
    py = top + 40 + 3 * 54
    d.card(cols[1] + 12, py, pw - 24, 154)
    d.text(cols[1] + 28, py + 27, "Providers", "t")
    d.text(cols[1] + pw - 28, py + 27, "any, with failover", "xs", "end")
    for i, p in enumerate(
        ["Anthropic", "Amazon Bedrock", "Google Vertex", "OpenAI · Azure"]
    ):
        cy = py + 40 + i * 27
        d.add(
            f'<rect class="chip" x="{cols[1] + 28}" y="{cy}" width="{pw - 56}" height="21" rx="6"/>'
        )
        d.text(cols[1] + 40, cy + 14.5, p, "m")
    # connectors
    d.path([(cols[0] + 120, 126), (cols[0] + 120, top - 6)], "accent")
    d.pill(cols[0] + 120, 145, "signed pointers", "accent")
    d.path([(cols[1] + 120, 126), (cols[1] + 120, top - 6)], "accent")
    d.pill(cols[1] + 120, 145, "routes · allowlist", "accent")
    d.path([(cols[2] + 120, top - 6), (cols[2] + 120, 126)], "accent", dashed=True)
    d.pill(cols[2] + 120, 145, "promote PR · human merge", "accent")
    yy = top + 40 + 23
    d.path([(cols[0] + pw + 6, yy), (cols[1] - 6, yy)], "line", flow=True)
    d.pill(cols[0] + pw + 28, yy - 18, "JWT", mono=True)
    d.path([(cols[1] + pw + 6, yy), (cols[2] - 6, yy)], "line", flow=True)
    d.pill(cols[1] + pw + 28, yy - 18, "OTLP", mono=True)
    ky = top + 40 + 4 * 54 + 23
    d.path([(cols[2] - 6, ky), (cols[1] + pw + 6, ky)], "danger", dashed=True)
    d.pill(cols[1] + pw + 28, ky - 18, "kill", "danger")
    d.write()


def rollout_strategies():
    d = D(
        "rollout-strategies",
        880,
        236,
        "Rollout strategies",
        "Five strategies Halos supports: progressive rings, a canary ramp from 1 to 100 percent, "
        "blue-green cutover, dark launch through shadow traffic, and a holdout cohort.",
        out=("assets", "docs"),
    )
    w, gap = 152, 18
    caps = [
        ("Progressive rings", ["ring0 → GA, by cohort"]),
        ("Canary ramp", ["traffic % steps up"]),
        ("Blue-green", ["swap, swap back"]),
        ("Dark launch", ["mirror, never answer"]),
        ("Holdout", ["keep a control cohort"]),
    ]
    for i, (t, subs) in enumerate(caps):
        x = 24 + i * (w + gap)
        d.card(x, 24, w, 188)
        cx, vy = x + w / 2, 92
        if i == 0:
            for j, r in enumerate([50, 37, 24, 11]):
                cls = "fa" if j == 3 else "ic"
                if j == 3:
                    d.add(f'<circle class="fa" cx="{cx}" cy="{vy}" r="{r}"/>')
                else:
                    d.add(
                        f'<circle class="ic blink" style="animation-delay:{(2 - j) * 0.5:.1f}s" cx="{cx}" cy="{vy}" r="{r}"/>'
                    )
        elif i == 1:
            hs = [6, 14, 30, 48, 74]
            for j, (hh, lab) in enumerate(zip(hs, ["1", "5", "25", "50", "100"])):
                bx = x + 20 + j * 23.5
                d.add(
                    f'<rect class="chip" x="{bx}" y="{132 - 74}" width="17" height="74" rx="4"/>'
                )
                d.add(
                    f'<rect class="fa blink" style="animation-delay:{j * 0.35:.2f}s" x="{bx}" y="{132 - hh}" width="17" height="{hh}" rx="4"/>'
                )
                d.text(bx + 8.5, 146, lab, "xs xm", "middle")
        elif i == 2:
            d.add(f'<circle class="dl" cx="{x + 26}" cy="{vy}" r="5"/>')
            d.card(x + 72, 56, 64, 28, "v1", center=True, pad=8, rx=8)
            d.card(x + 72, 100, 64, 28, "v2", kind="accent", center=True, pad=8, rx=8)
            d.path(
                [(x + 32, vy), (x + 50, vy), (x + 50, 70), (x + 66, 70)],
                "muted",
                dashed=True,
                r=6,
                head=False,
            )
            d.path(
                [(x + 32, vy), (x + 50, vy), (x + 50, 114), (x + 66, 114)],
                "accent",
                flow=True,
                r=6,
            )
        elif i == 3:
            d.add(f'<circle class="dl" cx="{x + 26}" cy="{vy - 20}" r="5"/>')
            d.card(x + 64, 58, 72, 28, "primary", center=True, pad=6, rx=8)
            d.card(
                x + 64, 104, 72, 28, "shadow", kind="ghost", center=True, pad=6, rx=8
            )
            d.path([(x + 32, vy - 20), (x + 58, vy - 20)], "line")
            d.path(
                [(x + 26, vy - 14), (x + 26, 118), (x + 58, 118)],
                "accent",
                dashed=True,
                flow=True,
                r=6,
            )
        else:
            for row in range(5):
                for col in range(8):
                    hold = col == 7 and row < 3
                    cls = "chip" if hold else "fa"
                    op = "" if hold else ' opacity=".85"'
                    d.add(
                        f'<rect class="{cls}" x="{x + 22 + col * 14}" y="{60 + row * 14}" width="10" height="10" rx="3"{op}/>'
                    )
            d.text(x + w - 18, 146, "held out", "xs", "end")
        d.text(x + 14, 176, t, "t", maxw=w - 26, size=13.5, weight=600)
        d.text(x + 14, 194, subs[0], "s", maxw=w - 26, size=12)
    d.write()


def experiments():
    d = D(
        "experiments",
        880,
        300,
        "Experiment types",
        "A/B tests vary the client (CLI version, settings, MCP) through halod; canaries and shadow "
        "traffic vary the traffic route at halo-proxy. One hash of user and salt assigns variants "
        "on both axes.",
        out=("assets", "docs"),
    )
    cols = [24, 312, 600]
    w = 256
    heads = [
        ("A/B test", "Client axis · halod"),
        ("Canary", "Traffic axis · halo-proxy"),
        ("Shadow", "Traffic axis · halo-shadow"),
    ]
    for (t, k), x in zip(heads, cols):
        d.card(x, 24, w, 214)
        d.kicker(x + 16, 48, k)
        d.text(x + 16, 70, t, "t")
    # A/B
    x = cols[0]
    d.card(x + 16, 92, 72, 40, "cohort", center=True, pad=6, rx=8)
    d.card(x + 138, 84, 102, 36, "control", center=True, pad=6, rx=8)
    d.card(x + 138, 132, 102, 36, "treatment", kind="accent", center=True, pad=6, rx=8)
    d.path([(x + 94, 112), (x + 114, 112), (x + 114, 102), (x + 132, 102)], "line", r=5)
    d.path(
        [(x + 94, 112), (x + 114, 112), (x + 114, 150), (x + 132, 150)], "accent", r=5
    )
    d.text(x + 16, 196, "varies: CLI version, settings,", "s", maxw=w - 32, size=12)
    d.text(x + 16, 212, "MCP servers, hooks", "s")
    # Canary
    x = cols[1]
    d.card(x + 16, 92, 82, 40, "halo-proxy", center=True, pad=4, rx=8)
    d.card(x + 138, 84, 102, 36, "current", center=True, pad=6, rx=8)
    d.card(x + 138, 132, 102, 36, "candidate", kind="accent", center=True, pad=6, rx=8)
    d.path(
        [(x + 104, 112), (x + 120, 112), (x + 120, 102), (x + 132, 102)], "line", r=5
    )
    d.path(
        [(x + 104, 112), (x + 120, 112), (x + 120, 150), (x + 132, 150)],
        "accent",
        r=5,
        flow=True,
    )
    d.text(x + 222, 79, "95%", "xs xm", "end")
    d.text(x + 222, 182, "5%", "xs xa", "end")
    d.text(x + 16, 196, "varies: model route, upstream,", "s", maxw=w - 32, size=12)
    d.text(x + 16, 212, "user answered by either", "s")
    # Shadow
    x = cols[2]
    d.card(x + 16, 92, 82, 40, "halo-proxy", center=True, pad=4, rx=8)
    d.card(x + 138, 84, 102, 36, "primary", center=True, pad=6, rx=8)
    d.card(x + 138, 132, 102, 36, "candidate", kind="ghost", center=True, pad=6, rx=8)
    d.path([(x + 104, 102), (x + 132, 102)], "line")
    d.path(
        [(x + 57, 136), (x + 57, 150), (x + 132, 150)],
        "accent",
        dashed=True,
        flow=True,
        r=5,
    )
    d.text(x + 188, 182, "→ judge", "xs xa", "middle")
    d.text(x + 16, 196, "candidate never answers the user;", "s", maxw=w - 32, size=12)
    d.text(x + 16, 212, "first turn copied async", "s")
    # assignment strip
    d.card(24, 252, 832, 34, rx=10)
    d.text(40, 273, "assignment", "k ka")
    d.text(
        124,
        273,
        "hash(user, salt) % 10000 → variant, computed by internal/assign on the client and gateway alike",
        "m",
        maxw=716,
        size=11,
        mono=True,
    )
    d.write()


def measure_loop():
    d = D(
        "measure-loop",
        880,
        380,
        "The measure loop",
        "A change is evaluated offline (pass@k, LLM judge, harness by model matrix), exposed to a ring, "
        "measured through OTEL in ClickHouse, and judged by mSPRT. A pass opens a promotion PR a human "
        "merges; a guardrail breach rolls back automatically and fires the signed kill switch.",
        out=("assets", "docs"),
    )
    cols = [24, 320, 616]
    w, h = 240, 104
    ty, by = 32, 232
    d.card(
        cols[0],
        ty,
        w,
        h,
        "Change",
        ["edit YAML, open a PR", "halo validate · halo plan"],
        kicker="01 · Change",
    )
    d.card(
        cols[1],
        ty,
        w,
        h,
        "Offline evals",
        ["pass@k · LLM judge", "harness × model matrix"],
        kicker="02 · Eval",
    )
    d.card(
        cols[2],
        ty,
        w,
        h,
        "Ring exposure",
        ["ring0, then ring1 canary", "signed pointer moves"],
        kicker="03 · Expose",
    )
    d.card(
        cols[2],
        by,
        w,
        h,
        "Telemetry",
        ["OTEL → ClickHouse", "cost · latency · acceptance"],
        kicker="04 · Measure",
    )
    d.card(
        cols[1],
        by,
        w,
        h,
        "Sequential verdict",
        ["mSPRT · paired bootstrap", "guardrails, checked live"],
        kind="accent",
        kicker="05 · Decide",
    )
    d.card(
        cols[0],
        by,
        w,
        h,
        "Promote PR",
        ["opened by the controller", "merged by a human, never auto"],
        kicker="06 · Promote",
    )
    m = ty + h / 2
    mb = by + h / 2
    d.path([(cols[0] + w + 6, m), (cols[1] - 6, m)], "accent", flow=True)
    d.path([(cols[1] + w + 6, m), (cols[2] - 6, m)], "accent", flow=True)
    d.path(
        [(cols[2] + w / 2 + 40, ty + h + 6), (cols[2] + w / 2 + 40, by - 6)],
        "accent",
        flow=True,
    )
    d.path([(cols[2] - 6, mb), (cols[1] + w + 6, mb)], "accent", flow=True)
    d.path([(cols[1] - 6, mb), (cols[0] + w + 6, mb)], "accent", flow=True)
    d.path(
        [(cols[0] + w / 2, by - 6), (cols[0] + w / 2, ty + h + 6)], "accent", flow=True
    )
    d.pill(cols[0] + w / 2, (ty + h + by) / 2, "human merge", "solid")
    d.pill(cols[1] - 28, mb - 18, "pass", "accent")
    # rollback branch
    d.path(
        [
            (cols[1] + w / 2, by - 6),
            (cols[1] + w / 2, 184),
            (cols[2] + 60, 184),
            (cols[2] + 60, ty + h + 6),
        ],
        "danger",
        dashed=True,
        r=10,
    )
    d.pill(cols[1] + w / 2 + 104, 184, "breach → auto-rollback + kill switch", "danger")
    # loop packet
    loop = (
        f"M{cols[0] + w / 2} {m}L{cols[2] + w / 2 + 40} {m}L{cols[2] + w / 2 + 40} {mb}"
        f"L{cols[0] + w / 2} {mb}Z"
    )
    d.packet(loop, dur=8, under=True)
    d.text(
        440,
        362,
        "evidence over opinion: every change earns its ring, every ring can be undone in seconds",
        "xs",
        "middle",
    )
    d.write()


def toggles():
    d = D(
        "toggles",
        880,
        330,
        "Feature toggles",
        "A feature toggle with ordered targeting rules (ring, group, percentage) resolves to on or off "
        "per developer from verified identity, and a signed kill switch turns it off everywhere.",
        out=("assets", "docs"),
    )
    # toggle definition
    d.card(24, 24, 360, 282)
    d.kicker(40, 48, "toggle")
    d.text(40, 70, "mcp.linear", "tm")
    # switch glyph
    d.add('<rect class="fa" x="322" y="40" width="44" height="24" rx="12"/>')
    d.add('<circle cx="354" cy="52" r="9" fill="#fff"/>')
    rules = [
        ("1", "ring = ring0", "on"),
        ("2", "group = platform-eng", "on"),
        ("3", "10% of everyone else", "on"),
        ("·", "default", "off"),
    ]
    for i, (n, rule, out) in enumerate(rules):
        y = 92 + i * 44
        d.add(f'<rect class="chip" x="40" y="{y}" width="328" height="34" rx="8"/>')
        if n == "·":
            d.text(56, y + 21.5, "else", "xs", "middle")
        else:
            d.badge(56, y + 17, n)
        d.text(74, y + 21.5, rule, "m", maxw=230, size=11, mono=True)
        d.pill(340, y + 17, out.upper(), "accent" if out == "on" else "label")
    d.add('<rect class="dcard" x="40" y="270" width="328" height="24" rx="8"/>')
    d.text(
        54,
        286,
        "kill switch: one signed flip → OFF everywhere",
        "xs xd",
        maxw=300,
        size=10.5,
    )
    # resolution
    devs = [
        ("ana", "ring0", "rule 1", True),
        ("ben", "platform-eng", "rule 2", True),
        ("chen", "bucket 0412 < 1000", "rule 3", True),
        ("dee", "bucket 7311", "default", False),
    ]
    d.kicker(480, 48, "resolved per developer · from verified identity")
    for i, (who, why, rule, on) in enumerate(devs):
        y = 66 + i * 58
        d.card(480, y, 376, 48)
        d.add(f'<circle class="{"fa" if on else "fm"}" cx="504" cy="{y + 24}" r="12"/>')
        d.text(504, y + 28, who[0].upper(), "xs xw" if on else "xs", "middle")
        d.text(526, y + 21, who, "t")
        d.text(526, y + 37, why, "m", maxw=200, size=11, mono=True)
        d.text(760, y + 28, rule, "xs", "end")
        d.pill(812, y + 24, "ON" if on else "OFF", "accent" if on else "label")
        d.path(
            [
                (390, 92 + min(i, 3) * 44 + 17),
                (430, 92 + min(i, 3) * 44 + 17),
                (430, y + 24),
                (474, y + 24),
            ],
            "accent" if on else "line",
            r=8,
        )
    d.text(
        480, 306, "same hash as experiments: internal/assign, salted per toggle", "xs"
    )
    d.write()


def everywhere():
    d = D(
        "everywhere",
        880,
        148,
        "Runs everywhere",
        "One signed release delivered to macOS, Linux and Windows laptops, Dev Containers, Codespaces "
        "and Coder workspaces, CI runners, and Kubernetes.",
        frame=False,
        out=("assets", "docs"),
    )
    items = [
        ("macOS", "halod · MDM"),
        ("Linux", "halod"),
        ("Windows", "halod · Intune"),
        ("Dev Containers", "Feature"),
        ("Workspaces", "Codespaces · Coder"),
        ("CI runners", "action"),
        ("Kubernetes", "Helm chart"),
    ]
    w, gap = 116, 10
    for i, (t, s) in enumerate(items):
        x = 4 + i * (w + gap)
        d.card(x, 8, w, 128)
        cx, cy = x + w / 2, 52
        d.add(glyph(i, cx, cy))
        fits(t, 12.5, w - 12, 600, what="everywhere")
        d.text(cx, 102, t, "t", "middle")
        d.text(cx, 120, s, "xs", "middle", maxw=w - 12, size=10.5)
    d.add("<style>.everywhere .t{font-size:12.5px}</style>")
    d.write()


def glyph(i, x, y):
    """Geometric platform glyphs (no trademarked marks), absolute coords so the gradient spans the strip."""
    L = [
        # laptop
        f'<rect x="{x - 18}" y="{y - 16}" width="36" height="24" rx="3"/><path d="M{x - 24} {y + 14}H{x + 24}L{x + 20} {y + 8}H{x - 20}Z"/>',
        # terminal
        f'<rect x="{x - 20}" y="{y - 16}" width="40" height="32" rx="5"/><path d="M{x - 11} {y - 4}l6 5-6 5M{x + 1} {y + 8}h9"/>',
        # desktop monitor
        f'<rect x="{x - 20}" y="{y - 18}" width="40" height="27" rx="3"/><path d="M{x} {y + 9}v7M{x - 9} {y + 17}h18"/>',
        # container cube
        f'<path d="M{x} {y - 18}l17 9v19l-17 9-17-9v-19z"/><path d="M{x - 17} {y - 9}l17 9 17-9M{x} {y}v19"/>',
        # cloud workspace
        f'<path d="M{x - 12} {y + 12}h25a9 9 0 0 0 1-18 13 13 0 0 0-25-3 8 8 0 0 0-1 21z"/>'
        f'<path d="M{x - 4} {y - 1}l-4 4 4 4M{x + 5} {y - 1}l4 4-4 4"/>',
        # pipeline
        f'<circle cx="{x - 16}" cy="{y}" r="5"/><circle cx="{x}" cy="{y}" r="5"/><circle cx="{x + 16}" cy="{y}" r="5"/>'
        f'<path d="M{x - 11} {y}h6M{x + 5} {y}h6M{x - 20} {y + 15}h40"/>',
        # cluster: three nodes in a mesh
        f'<circle cx="{x}" cy="{y - 13}" r="6"/><circle cx="{x - 14}" cy="{y + 11}" r="6"/><circle cx="{x + 14}" cy="{y + 11}" r="6"/>'
        f'<path d="M{x - 3} {y - 8}l-8 13M{x + 3} {y - 8}l8 13M{x - 8} {y + 11}h16"/>',
    ]
    return f'<g class="ic">{L[i]}</g>'


# =============================================================== docs diagrams
W = 760


def seq(name, title, desc, parts, msgs, number=False):
    """parts: [(label, sub)]; msgs: (a, b, text, kind) | ('self', a, text) | ('note', text)
    | ('loop', label, [msgs])  kind: call | reply | async"""
    n = len(parts)
    colw = (W - 48) / n
    xs = [24 + colw * (i + 0.5) for i in range(n)]

    def rows(ms):
        c = 0
        for m in ms:
            c += rows(m[2]) + 1.6 if m[0] == "loop" else 1
        return c

    rh = 36
    top = 24 + 52 + 22
    H = top + rows(msgs) * rh + 14 + 24
    d = D(name, W, int(H), title, desc)
    for (lab, sub), x in zip(parts, xs):
        d.add(f'<path class="lane" d="M{x:.1f} {24 + 52}V{H - 24}"/>')
        d.card(
            round(x - colw / 2 + 5, 1),
            24,
            round(colw - 10, 1),
            52,
            lab,
            [sub] if sub else [],
            center=True,
            pad=8,
            mono_sub=True,
        )
    y = top
    k = [0]

    def emit(ms):
        nonlocal y
        for m in ms:
            if m[0] == "note":
                d.add(
                    f'<rect class="soft" x="24" y="{y + 4}" width="{W - 48}" height="{rh - 8}" rx="8"/>'
                )
                d.text(W / 2, y + 22, m[1], "s", "middle", maxw=W - 80, size=12)
                y += rh
            elif m[0] == "self":
                x = xs[m[1]]
                ww = tw(m[2], 11, mono=True) + 20
                cx = min(max(x, 40 + ww / 2), W - 40 - ww / 2)
                d.add(
                    f'<rect class="chip" x="{cx - ww / 2:.1f}" y="{y + 7}" width="{ww:.1f}" height="22" rx="6"/>'
                )
                d.text(cx, y + 22, m[2], "m", "middle")
                y += rh
            elif m[0] == "loop":
                y0 = y
                y += rh * 0.6
                emit(m[2])
                d.add(
                    f'<rect class="ghost" x="30" y="{y0 + 6}" width="{W - 60}" height="{y - y0 + 4}" rx="10"/>'
                )
                d.pill(30 + tw(m[1], 10.5) / 2 + 22, y0 + 6, m[1], "accent")
                y += rh
            else:
                a, b, t, kind = m
                xa, xb = xs[a], xs[b]
                sgn = 1 if xb > xa else -1
                pts = [(xa + 4 * sgn, y + 24), (xb - 4 * sgn, y + 24)]
                if kind == "call":
                    d.path(pts, "line")
                elif kind == "reply":
                    d.path(pts, "line", dashed=True)
                else:
                    d.path(pts, "accent", dashed=True)
                k[0] += 1
                tx = (xa + xb) / 2
                lw = tw(t, 11.5) + (22 if number else 0)
                tx = min(max(tx, 24 + lw / 2), W - 24 - lw / 2)
                assert lw < W - 48, (name, t)
                d.add(
                    f'<rect class="pl" x="{tx - lw / 2 - 4:.1f}" y="{y + 3}" width="{lw + 8:.1f}" height="17" rx="4"/>'
                )
                if number:
                    d.badge(tx - lw / 2 + 8, y + 12, k[0])
                    d.add(
                        f'<text class="s" x="{tx - lw / 2 + 22:.1f}" y="{y + 16}" style="font-size:11.5px">{escape(t)}</text>'
                    )
                else:
                    d.add(
                        f'<text class="s" x="{tx:.1f}" y="{y + 16}" text-anchor="middle" style="font-size:11.5px">{escape(t)}</text>'
                    )
                y += rh

    emit(msgs)
    d.write()


def state_box(d, x, y, w, h, label, kind="card", mono=True):
    d.card(x, y, w, h, label, center=True, pad=8, rx=h / 2, kind=kind, title_mono=mono)


def docs_diagrams():
    # ---------------------------------------------------------- request path
    seq(
        "request-path",
        "Request path through halo-proxy",
        "Claude Code sends a request with a bearer JWT; halo-proxy strips client x-halo headers, verifies "
        "the token against the issuer JWKS, assigns ring, experiment and variant, enforces the model "
        "allowlist, forwards with x-halo stamps, streams the response and mirrors the first turn to "
        "halo-shadow asynchronously.",
        [
            ("Claude Code", "client"),
            ("halo-proxy", "or Kong"),
            ("OIDC issuer", "JWKS"),
            ("Upstream", "provider"),
            ("halo-shadow", "mirror"),
        ],
        [
            (0, 1, "POST /v1/messages · Bearer JWT · spoofed x-halo-*", "call"),
            ("self", 1, "strip every x-halo-*"),
            (1, 2, "JWKS (cached, refetch on unknown kid)", "call"),
            ("self", 1, "verify iss · aud · exp · nbf · alg"),
            ("self", 1, "ring, experiment, variant ← user + groups"),
            ("self", 1, "model allowlist (fails closed) · alias → route"),
            (1, 3, "forward with x-halo-ring/release/experiment/variant", "call"),
            (3, 0, "streamed response, no buffering", "reply"),
            (1, 4, "async: experiment, variant, first-turn body", "async"),
        ],
        number=True,
    )

    # ---------------------------------------------------------- delivery
    d = D(
        "delivery",
        W,
        336,
        "Delivery paths",
        "A signed release and pointer reach disposable environments (Dev Container Feature, Coder module, "
        "Codespaces prebuild) and laptops (halod, MDM export). Every path verifies pointer and signature: "
        "invalid means refuse and keep the last good release; valid means atomic apply and report the digest.",
    )
    d.card(24, 132, 150, 64, "Signed release", ["+ signed pointer"], kind="accent")
    srcs = [
        "Dev Container Feature",
        "Coder module",
        "Codespaces prebuild",
        "halod",
        "MDM export",
    ]
    for i, s in enumerate(srcs):
        y = 24 + i * 58
        d.card(208, y, 188, 44, s)
        d.path([(180, 164), (194, 164), (194, y + 22), (202, y + 22)], "accent", r=8)
    d.zone(436, 24, 148, 104, "Disposable")
    d.text(452, 70, "firewall:", "s")
    d.text(452, 88, "gateway only", "s")
    d.zone(436, 212, 148, 92, "Laptop")
    d.text(452, 258, "root-owned paths", "s")
    for i in range(5):
        y = 24 + i * 58 + 22
        ty = 76 if i < 3 else 258
        d.path([(402, y), (418, y), (418, ty), (430, ty)], "line", r=6)
    d.card(612, 132, 124, 64, "valid?", ["pointer + signature"], center=True, pad=8)
    d.path([(590, 76), (600, 76), (600, 150), (606, 150)], "line", r=6)
    d.path([(590, 258), (600, 258), (600, 178), (606, 178)], "line", r=6)
    d.card(
        612,
        24,
        124,
        64,
        "atomic apply",
        ["report digest"],
        kind="accent",
        center=True,
        pad=8,
    )
    d.card(
        612,
        240,
        124,
        64,
        "refuse",
        ["keep last good"],
        kind="danger",
        center=True,
        pad=8,
    )
    d.path([(674, 126), (674, 94)], "accent")
    d.pill(674, 110, "yes", "accent")
    d.path([(674, 202), (674, 234)], "danger")
    d.pill(674, 218, "no", "danger")
    d.write()

    # ---------------------------------------------------------- evidence plane
    d = D(
        "evidence-flow",
        W,
        390,
        "Evidence plane",
        "OTEL from Claude Code, Codex and Gemini CLI plus halo-proxy gateway metrics flow through the "
        "collector into ClickHouse; shadow pairs are graded by an LLM judge and eval runs become "
        "scorecards. halo exp analyze opens promotion PRs; the controller fires the kill switch with a "
        "pause PR on rollback, or opens a conclude PR on promote or expiry.",
    )
    srcs = [
        ("Claude Code", "OTEL"),
        ("Codex", "OTEL · exec --json"),
        ("Gemini CLI", "OTEL"),
        ("halo-proxy", "halo.gateway.*"),
        ("halo-shadow", "response pairs"),
        ("halo eval", "replay runs"),
    ]
    for i, (t, s) in enumerate(srcs):
        y = 32 + i * 56
        d.card(24, y, 156, 44, t, [s], mono_sub=True)
        tgt = 138 if i < 4 else (278 if i == 4 else 334)
        if i < 4:
            d.path([(186, y + 22), (198, y + 22), (198, tgt), (210, tgt)], "line", r=6)
        else:
            d.path([(186, y + 22), (210, y + 22)], "line")
    d.card(216, 110, 154, 56, "OTEL collector", ["normalize → halo.*"])
    d.card(216, 256, 154, 44, "LLM judge", ["grades pairs"])
    d.card(216, 312, 154, 44, "Scorecards", ["pass@k · matrix"])
    d.card(406, 150, 146, 64, "ClickHouse", ["halo.* tables"], kind="accent")
    d.path([(376, 138), (388, 138), (388, 172), (400, 172)], "line", r=6)
    d.path([(376, 278), (388, 278), (388, 192), (400, 192)], "line", r=6)
    d.path([(376, 334), (479, 334), (479, 220)], "line", r=6)
    d.card(586, 32, 150, 48, "Analyze", ["halo exp analyze"], mono_sub=True)
    d.card(586, 104, 150, 44, "Promote PR", ["human merges"], kind="accent")
    d.card(586, 196, 150, 48, "Controller", ["halo-server"], mono_sub=True)
    d.card(586, 268, 150, 44, "Kill switch", ["rollback + pause PR"], kind="danger")
    d.card(586, 330, 150, 44, "Conclude PR", ["promote · expired"])
    d.path([(558, 166), (566, 166), (566, 56), (580, 56)], "line", r=6)
    d.path([(558, 198), (566, 198), (566, 220), (580, 220)], "line", r=6)
    d.path([(661, 86), (661, 98)], "accent")
    d.path([(661, 250), (661, 262)], "danger")
    d.path([(586, 236), (574, 236), (574, 352), (580, 352)], "line", r=6)
    d.write()

    # ---------------------------------------------------------- experiments
    d = D(
        "variant-assignment",
        W,
        192,
        "Variant assignment",
        "The verified identity is hashed with the experiment salt into 10,000 buckets; the weight "
        "bucket picks control (current route) or candidate (routes override), and the gateway stamps "
        "x-halo-variant.",
    )
    d.card(24, 72, 140, 56, "Verified identity", ["from the JWT"])
    d.card(196, 72, 180, 56, "hash(user, salt)", ["% 10000 → bucket"], title_mono=True)
    d.card(412, 32, 156, 56, "Current route", [], kicker="control")
    d.card(412, 112, 156, 56, "Routes override", [], kicker="candidate", kind="accent")
    d.card(604, 72, 132, 56, "Stamp", ["x-halo-variant"], mono_sub=True)
    d.path([(170, 100), (190, 100)], "line")
    d.path([(382, 100), (394, 100), (394, 60), (406, 60)], "line", r=6)
    d.path([(382, 100), (394, 100), (394, 140), (406, 140)], "accent", r=6)
    d.path([(574, 60), (586, 60), (586, 100), (598, 100)], "line", r=6)
    d.path([(574, 140), (586, 140), (586, 100), (598, 100)], "accent", r=6)
    d.write()

    d = D(
        "client-axis-channels",
        W,
        268,
        "Client-axis experiment channels",
        "halo release publish writes the ring release (with the experiment salt, weights and channels) "
        "and one channel per variant. halod verifies the ring pointer, computes the same hash as the "
        "gateway to pick a variant, then verifies and applies that variant's channel.",
    )
    d.card(24, 100, 176, 56, "Publish", ["halo release publish"], mono_sub=True)
    d.card(
        236,
        24,
        248,
        64,
        "Ring release",
        ["manifest.experiments:", "salt · weights · channels"],
        kind="accent",
    )
    d.card(
        236,
        112,
        248,
        52,
        "Control channel",
        ["ring1-ga.x-cli-upgrade.control"],
        mono_sub=True,
    )
    d.card(
        236,
        184,
        248,
        52,
        "Treatment channel",
        ["ring1-ga.x-cli-upgrade.treatment"],
        mono_sub=True,
    )
    for ty in (56, 138, 210):
        d.path([(206, 128), (218, 128), (218, ty), (230, ty)], "line", r=6)
    d.card(560, 24, 176, 64, "halod", ["verifies, hashes, pulls"])
    d.card(
        560,
        168,
        176,
        76,
        "Apply release",
        ["version pin", "OTEL attribution"],
        kind="accent",
    )
    d.path([(554, 56), (490, 56)], "line")
    d.badge(522, 56, 1)
    d.path([(648, 94), (648, 162)], "line")
    d.badge(648, 128, 2)
    d.text(662, 132, "variant", "xs")
    d.path([(490, 210), (554, 210)], "accent")
    d.badge(522, 210, 3)
    d.path([(490, 138), (522, 138), (522, 190), (554, 190)], "muted", dashed=True, r=6)
    d.write()

    d = D(
        "experiment-lifecycle",
        W,
        214,
        "Experiment lifecycle",
        "An experiment starts as draft, runs after halo exp start, can be paused and restarted, and "
        "ends concluded from running or paused.",
    )
    d.add('<circle class="dl" cx="32" cy="58" r="5"/>')
    d.path([(38, 58), (50, 58)], "line", head=False)
    state_box(d, 52, 40, 108, 36, "draft")
    state_box(d, 300, 40, 140, 36, "running", "accent")
    state_box(d, 596, 40, 140, 36, "concluded")
    state_box(d, 300, 152, 140, 36, "paused")
    d.path([(166, 58), (294, 58)], "line")
    d.pill(230, 58, "halo exp start", mono=True)
    d.path([(446, 58), (590, 58)], "line")
    d.pill(518, 58, "halo exp conclude", mono=True)
    d.path([(336, 82), (336, 146)], "line")
    d.pill(336, 114, "pause", mono=True)
    d.path([(404, 146), (404, 82)], "line")
    d.pill(404, 114, "start", mono=True)
    d.path([(446, 170), (666, 170), (666, 82)], "line", r=10)
    d.pill(556, 170, "halo exp conclude", mono=True)
    d.write()

    d = D(
        "controller-loop",
        W,
        252,
        "Controller loop",
        "Every five minutes the controller evaluates each running experiment from ClickHouse evidence: "
        "continue, roll back (kill switch, pause PR, notify), promote (conclude PR, notify) or expire "
        "(conclude PR, notify).",
    )
    d.card(24, 92, 140, 56, "Tick", ["every 5 minutes"])
    d.card(
        204,
        84,
        200,
        72,
        "Evaluate",
        ["each running experiment", "from ClickHouse evidence"],
        kind="accent",
    )
    d.card(
        470, 24, 266, 64, "Rollback", ["kill switch → pause PR → notify"], kind="danger"
    )
    d.card(470, 104, 266, 56, "Promote", ["conclude PR · notify"])
    d.card(470, 176, 266, 56, "Expired", ["conclude PR · notify"])
    d.path([(170, 120), (198, 120)], "line")
    d.path([(410, 120), (436, 120), (436, 56), (464, 56)], "danger", r=8)
    d.path([(410, 120), (436, 120), (436, 132), (464, 132)], "line", r=8)
    d.path([(410, 120), (436, 120), (436, 204), (464, 204)], "line", r=8)
    d.path([(304, 162), (304, 206), (94, 206), (94, 154)], "line", dashed=True, r=10)
    d.pill(200, 206, "continue")
    d.write()

    seq(
        "kill-switch",
        "Kill switch",
        "The controller or an admin kills an experiment at halo-server, which appends to killswitch.jsonl "
        "with an audit entry. Every 10 seconds each gateway fetches the signed list with its gateway token "
        "and verifies signature, freshness and that issuedAt is strictly newer; killed experiments get "
        "control routing and no shadow.",
        [
            ("Controller", "or admin"),
            ("halo-server", "kill list"),
            ("Gateway", "halo-proxy / kong"),
        ],
        [
            (
                0,
                1,
                "kill: controller verdict, or POST /api/v1/experiments/{name}/kill",
                "call",
            ),
            ("self", 1, "append killswitch.jsonl · audit entry"),
            (
                "loop",
                "every 10s",
                [
                    (2, 1, "GET /api/v1/gateway/killswitch · gateway token", "call"),
                    (1, 2, "signed list {version, experiments, issuedAt}", "reply"),
                    (
                        "self",
                        2,
                        "verify signature · freshness · issuedAt strictly newer",
                    ),
                ],
            ),
            ("note", "killed experiments get control routing and no shadow"),
        ],
    )

    # ---------------------------------------------------------- policy model
    d = D(
        "policy-model",
        W,
        372,
        "Policy model",
        "Rings point at a profile. Experiments target rings and vary either a profile (client axis) or "
        "gateway routes (traffic axis). Profiles extend other profiles.",
    )

    def entity(x, y, w, name, fields):
        lines, cur = [], ""
        for f in fields:
            cand = f if not cur else cur + " · " + f
            if tw(cand, 11, mono=True) > w - 32:
                lines.append(cur)
                cur = f
            else:
                cur = cand
        lines.append(cur)
        h = 52 + 16 * len(lines)
        d.card(x, y, w, h)
        d.text(x + 16, y + 28, name, "tm")
        d.add(f'<path class="lm" d="M{x} {y + 40}H{x + w}"/>')
        for i, ln in enumerate(lines):
            d.text(x + 16, y + 60 + i * 16, ln, "m")
        return h

    entity(24, 24, 280, "Ring", ["order", "profile", "release", "membership"])
    he = entity(
        420,
        24,
        316,
        "Experiment",
        [
            "type",
            "axis",
            "status",
            "rings",
            "variants",
            "sampleRate",
            "metrics",
            "stopping",
            "salt",
        ],
    )
    hp = entity(
        24,
        196,
        280,
        "Profile",
        [
            "extends",
            "harnesses",
            "models",
            "permissions",
            "mcp",
            "hooks",
            "telemetry",
            "egress",
            "instructions",
            "env",
        ],
    )
    entity(
        420,
        236,
        316,
        "Gateway",
        ["baseURL", "protocols", "auth", "models", "upstreams"],
    )
    d.path([(414, 52), (310, 52)], "line")
    d.pill(362, 52, "rings", mono=True)
    d.path([(164, 24 + 92 + 6), (164, 190)], "line")
    d.pill(164, 156, "profile", mono=True)
    d.path(
        [(500, 24 + he + 6), (500, 172), (380, 172), (380, 256), (310, 256)],
        "line",
        r=10,
    )
    d.pill(380, 208, "variant.profile", mono=True)
    d.text(370, 236, "client axis", "xs", "end")
    d.path([(640, 24 + he + 6), (640, 230)], "accent")
    d.pill(640, (24 + he + 236) / 2 - 8, "variant.routes", "accent", mono=True)
    d.text(650, (24 + he + 236) / 2 + 20, "traffic axis", "xs")
    d.path(
        [
            (84, 196 + hp + 6),
            (84, 196 + hp + 22),
            (224, 196 + hp + 22),
            (224, 196 + hp + 6),
        ],
        "line",
        r=8,
    )
    d.pill(154, 196 + hp + 22, "extends", mono=True)
    d.write()

    d = D(
        "validation-pipeline",
        W,
        216,
        "Validation pipeline",
        "YAML is strictly decoded, loaded (references, extends, ring order), schema-validated, checked "
        "by Go guardrails, rendered by adapters that warn on unsupported fields, and finally re-checked "
        "by the release backstop on the rendered files.",
    )
    row1 = hrow(
        d,
        24,
        72,
        [
            dict(title="YAML", subs=["strict decode"], kicker="01"),
            dict(title="Loader", subs=["refs · extends · ring order"], kicker="02"),
            dict(title="Schema", subs=["schema-level validation"], kicker="03"),
        ],
        gap=48,
    )
    row2 = hrow(
        d,
        128,
        72,
        [
            dict(title="Guardrails", subs=["Go checks, no OPA"], kicker="04"),
            dict(title="Adapter render", subs=["unsupported → warning"], kicker="05"),
            dict(
                title="Release backstop",
                subs=["re-checks rendered files"],
                kicker="06",
                kind="accent",
            ),
        ],
        gap=48,
    )
    x3 = row1[2][0] + row1[2][2] / 2
    x4 = row2[0][0] + row2[0][2] / 2
    d.path([(x3, 102), (x3, 112), (x4, 112), (x4, 122)], "line", r=5)
    d.write()

    # ---------------------------------------------------------- rings
    d = D(
        "rings",
        W,
        164,
        "Rings",
        "ring0 is the harness team by IdP group, ring1 a 5 percent hash, ring2 25 percent, ring3 the GA "
        "default; the bar under each ring shows its share of the fleet.",
    )
    rs = [
        ("ring0", "harness team", 0.02),
        ("ring1", "5% by hash", 0.05),
        ("ring2", "25% by hash", 0.25),
        ("ring3", "GA · default", 1.0),
    ]
    boxes = hrow(
        d,
        24,
        96,
        [
            dict(
                title=t,
                subs=[s, ""],
                title_mono=True,
                kind="accent" if i == 3 else "card",
            )
            for i, (t, s, _) in enumerate(rs)
        ],
        gap=36,
        akind="accent",
    )
    for (x, y, w, h), (_, _, f) in zip(boxes, rs):
        d.add(
            f'<rect class="fm" x="{x + 16:.1f}" y="{y + 70}" width="{w - 32:.1f}" height="4" rx="2"/>'
        )
        d.add(
            f'<rect class="fa" x="{x + 16:.1f}" y="{y + 70}" width="{max(4, (w - 32) * f):.1f}" height="4" rx="2"/>'
        )
    d.text(
        W / 2,
        146,
        "membership: explicit groups first, then a deterministic hash of the user (internal/assign)",
        "xs",
        "middle",
    )
    d.write()

    d = D(
        "release-lifecycle",
        W,
        464,
        "Release lifecycle",
        "A release moves from draft to eval-gated on publish, to ring0 when evals pass, ring1 when "
        "guardrails hold, ring2 when the canary passes and GA when the PR is merged. From any stage "
        "it can be rolled back, which re-points the ring at the last good release.",
    )
    states = ["draft", "eval_gated", "ring0", "ring1", "ring2", "GA"]
    trans = [
        "halo release publish",
        "evals pass",
        "guardrails hold",
        "canary passes",
        "PR merged",
    ]
    for i, s in enumerate(states):
        y = 24 + i * 76
        state_box(d, 120, y, 180, 36, s, "accent" if s == "GA" else "card")
        if i < 5:
            d.path([(210, y + 42), (210, y + 70)], "line")
            d.text(222, y + 60, trans[i], "xs")
        if i >= 1:
            d.path(
                [(306, y + 18), (440, y + 18), (440, 232), (500, 232)],
                "danger",
                dashed=True,
                r=10,
                head=False,
            )
    d.path([(500, 232), (514, 232)], "danger")
    d.pill(372, 24 + 76 + 18, "evals fail", "danger")
    d.pill(372, 24 + 3 * 76 + 18, "guardrail breach", "danger")
    d.card(
        520,
        202,
        216,
        60,
        "rolled_back",
        ["ring re-points to last good"],
        kind="danger",
        title_mono=True,
    )
    d.write()

    def gantt(name, title, desc, rows, days, mile):
        H = 56 + len(rows) * 40 + 24 + 20
        d = D(name, W, H, title, desc)
        x0, x1 = 228, 724
        px = (x1 - x0) / days
        for k in range(0, days + 1, 2):
            x = x0 + k * px
            d.add(f'<path class="lane" d="M{x:.1f} 44V{56 + len(rows) * 40}"/>')
            d.text(x, 36, f"d{k}", "xs xm", "middle")
        for i, (lab, a, b, st) in enumerate(rows):
            y = 56 + i * 40
            d.text(40, y + 24, lab, "s", maxw=180, size=12)
            if b == a:
                cx = x0 + a * px
                d.add(f'<path class="fa" d="M{cx:.1f} {y + 8}l11 11-11 11-11-11z"/>')
                d.text(cx - 18, y + 24, mile, "xs xa", "end")
                continue
            cls = {"done": "chip", "active": "fa", "next": "fs"}[st]
            d.add(
                f'<rect class="{cls}" x="{x0 + a * px + 2:.1f}" y="{y + 8}" width="{(b - a) * px - 4:.1f}" height="24" rx="7"/>'
            )
            if st == "next":
                d.add(
                    f'<rect class="ring" x="{x0 + a * px + 2.75:.1f}" y="{y + 8.75}" width="{(b - a) * px - 5.5:.1f}" height="22.5" rx="6.25"/>'
                )
            tcls = {"done": "xs", "active": "xs xw", "next": "xs xa"}[st]
            d.text(x0 + a * px + 12, y + 24, f"{b - a}d", tcls + " xm")
        d.text(
            40,
            H - 24,
            "illustrative durations; each ring holds until its gate passes",
            "xs",
        )
        d.write()

    gantt(
        "cli-rollout-timeline",
        "CLI upgrade rollout timeline",
        "Example CLI upgrade: eval scorecard for 2 days, ring0 harness team for 3 days, ring1 canary 5 percent "
        "for 5 days, ring2 25 percent for 5 days, then the GA PR is merged.",
        [
            ("Eval scorecard", 0, 2, "done"),
            ("ring0 · harness team", 2, 5, "active"),
            ("ring1 · canary 5%", 5, 10, "next"),
            ("ring2 · 25%", 10, 15, "next"),
            ("GA", 15, 15, ""),
        ],
        16,
        "PR merged",
    )
    gantt(
        "model-rollout-timeline",
        "Model upgrade rollout timeline",
        "Example model upgrade: shadow 5 percent on ring0 for 3 days, replay evals for 2 days, canary 5 percent "
        "on ring1 for 7 days, ramp to 50 percent across ring1 and ring2 for 4 days, then swap the alias by PR.",
        [
            ("Shadow 5% · ring0", 0, 3, "done"),
            ("Replay evals", 3, 5, "done"),
            ("Canary 5% · ring1", 5, 12, "active"),
            ("Ramp 50% · ring1+2", 12, 16, "next"),
            ("Swap alias", 16, 16, ""),
        ],
        16,
        "PR",
    )

    # ---------------------------------------------------------- security
    d = D(
        "security-boundaries",
        W,
        524,
        "Security boundaries",
        "Untrusted clients and networks; the gateway boundary that verifies OIDC JWTs, strips x-halo "
        "headers and fails closed on the model allowlist; a supply chain where a CI or HSM key signs "
        "releases into an OCI registry; halod as root verifying pointer and release before writing managed "
        "config; and halo-server issuing device tokens and a kill list signed with a separate key.",
    )
    d.zone(24, 24, 300, 164, "Untrusted", danger=True)
    d.card(
        40, 60, 268, 52, "Client + request headers", ["may send any x-halo-* header"]
    )
    d.card(
        40,
        124,
        268,
        52,
        "Network · CDN · vendor hosts",
        ["artifact bytes, hash-checked"],
    )
    d.zone(436, 24, 300, 164, "Gateway boundary")
    d.card(
        452,
        60,
        268,
        112,
        "halo-proxy / halo-kong",
        ["verify OIDC JWT", "strip every x-halo-*", "model allowlist fails closed"],
        kind="accent",
    )
    d.zone(24, 212, 300, 164, "Supply chain")
    d.card(40, 248, 268, 48, "ed25519 signing key", ["CI or HSM / KMS"])
    d.card(
        40, 316, 268, 48, "OCI registry", ["release + pointer · untrusted transport"]
    )
    d.path([(174, 302), (174, 310)], "line")
    d.zone(436, 212, 300, 164, "Root on the device")
    d.card(
        452,
        248,
        268,
        64,
        "halod",
        ["verifies pointer + release", "path allowlist · ownership checks"],
        kind="accent",
    )
    d.card(452, 328, 268, 36, "Managed config files")
    d.path([(586, 316), (586, 322)], "line")
    d.zone(24, 400, 712, 100, "halo-server")
    d.card(40, 436, 320, 56, "Portal", ["OIDC login · enrollment + device tokens"])
    d.card(
        452,
        436,
        268,
        56,
        "Kill list",
        ["signed with a separate ed25519 key"],
        kind="accent",
    )
    d.path([(314, 86), (446, 86)], "line")
    d.pill(380, 86, "request")
    d.path([(314, 150), (372, 150), (372, 268), (446, 268)], "line", r=8)
    d.path([(314, 340), (400, 340), (400, 288), (446, 288)], "line", r=8)
    d.path([(366, 464), (418, 464), (418, 302), (446, 302)], "line", r=8)
    d.path([(726, 464), (748, 464), (748, 116), (726, 116)], "accent", r=8)
    d.pill(372, 200, "verified before use")
    d.write()

    d = D(
        "trust-zones",
        W,
        616,
        "Trust zones",
        "Z0 internet and vendor hosts (untrusted), Z1 the developer machine with a root-owned area for "
        "halod and its config, Z2 the supply chain (policy repo, CI publish job holding the key, OCI "
        "registry), and Z3 your infrastructure (halo-proxy or halo-kong, model upstreams and IdP, "
        "halo-shadow, halo-server).",
    )
    d.zone(24, 24, 316, 248, "Z2 · Supply chain")
    d.card(40, 60, 284, 48, "Policy repo", ["review gate"])
    d.card(40, 132, 284, 48, "CI publish job", ["holds the signing key"])
    d.card(40, 204, 284, 48, "OCI registry", ["untrusted transport"])
    d.path([(182, 114), (182, 126)], "line")
    d.text(194, 124, "merge", "xs")
    d.path([(182, 186), (182, 198)], "line")
    d.text(194, 196, "signed release + pointer", "xs")
    d.zone(420, 24, 316, 248, "Z0 · Internet", danger=True, sub="untrusted")
    d.card(
        436,
        60,
        284,
        52,
        "Vendor download hosts",
        ["CLI tarballs, npm → halod, hash-checked"],
    )
    d.card(
        436,
        128,
        284,
        52,
        "Attacker on the network",
        ["targets registry · gateway · server"],
        kind="danger",
    )
    d.text(452, 216, "Nothing from Z0 is trusted without a", "s")
    d.text(452, 234, "signature or a pinned hash.", "s")
    d.zone(24, 296, 316, 296, "Z1 · Developer machine")
    d.card(108, 332, 216, 48, "Developer + agent", ["non-root · any header"])
    d.add('<rect class="ghost" x="40" y="396" width="284" height="180" rx="12"/>')
    d.kicker(308, 418, "Root-owned", accent=False, anchor="end")
    d.card(56, 432, 116, 48, "halod", ["as root"], kind="accent")
    d.card(196, 432, 112, 48, "Config", ["key · token"])
    d.card(196, 512, 112, 48, "Managed", ["mode 0644"])
    d.path([(190, 456), (178, 456)], "line")
    d.path([(160, 486), (160, 536), (190, 536)], "line", r=8)
    d.zone(420, 296, 316, 296, "Z3 · Your infrastructure")
    d.card(
        436,
        332,
        284,
        48,
        "halo-proxy / halo-kong",
        ["verifies JWT · strips headers"],
        kind="accent",
    )
    d.card(436, 400, 284, 44, "Model upstreams · IdP")
    d.card(436, 464, 284, 44, "halo-shadow", ["upstreams from its own policy"])
    d.card(436, 528, 284, 48, "halo-server", ["portal · device store · kill list"])
    d.path([(578, 386), (578, 394)], "line")
    d.path([(578, 464), (578, 450)], "line")
    d.path([(436, 368), (428, 368), (428, 486), (434, 486)], "line", r=6)
    d.path([(720, 552), (728, 552), (728, 356), (726, 356)], "accent", r=6)
    d.path([(90, 258), (90, 426)], "line")
    d.path([(330, 352), (430, 352)], "line")
    d.pill(380, 352, "JWT")
    d.path([(330, 368), (372, 368), (372, 540), (430, 540)], "line", r=8)
    d.pill(372, 456, "enroll")
    d.path([(114, 486), (114, 584), (396, 584), (396, 556), (430, 556)], "line", r=8)
    d.pill(250, 584, "device token")
    d.write()

    seq(
        "enrollment",
        "Self-service enrollment",
        "A developer logs in to the halo-server portal through OIDC, requests a laptop launch and gets a "
        "one-time token, enrolls the laptop to receive halod.yaml with a device token, and halod then "
        "resolves its ring live. Access requests are approved by an admin and become a policy PR, never a merge.",
        [
            ("Developer", ""),
            ("Portal", "halo-server"),
            ("IdP", "OIDC"),
            ("Admin", "adminGroups"),
            ("Policy repo", "git"),
            ("Laptop", "halod"),
        ],
        [
            (0, 1, "GET /auth/login", "call"),
            (1, 2, "authorization code flow", "call"),
            (2, 1, "id token (user, groups)", "reply"),
            (0, 1, "POST /api/v1/launch/laptop", "call"),
            (1, 0, "one-time token (15 min TTL) + enroll commands", "reply"),
            (0, 5, "run enroll.sh with the one-time TOKEN", "call"),
            (5, 1, "POST /api/v1/enroll {token}", "call"),
            (1, 5, "halod.yaml with device token (shown once)", "reply"),
            (5, 1, "GET /api/v1/fleet/ring · device token", "call"),
            (1, 5, '{"ring": "…"} resolved live from policy', "reply"),
            (0, 1, "POST /api/v1/requests (mcp-server linear)", "call"),
            (3, 1, "POST /api/v1/requests/ID/approve", "call"),
            (1, 4, "branch + PR, never merges", "async"),
        ],
        number=True,
    )

    seq(
        "shadow-sequence",
        "Shadow traffic",
        "The gateway forwards the request to the primary route, which answers the user. If it is a first "
        "turn and sampled, an async copy goes to halo-shadow, which replays it non-streaming against the "
        "candidate route, stores the pair and sends it to the judge in batches.",
        [
            ("Gateway", "proxy / kong"),
            ("Primary", "route"),
            ("halo-shadow", "mirror"),
            ("Candidate", "route"),
            ("Judge", "LLM"),
        ],
        [
            (0, 1, "request (the user waits on this)", "call"),
            (1, 0, "response", "reply"),
            (0, 2, "async copy if first turn and sampled", "async"),
            (2, 3, "replay, non-streaming", "call"),
            (3, 2, "candidate response", "reply"),
            ("self", 2, "store pair"),
            (2, 4, "batch grading", "async"),
        ],
    )

    d = D(
        "topologies",
        W,
        284,
        "Deployment topologies",
        "a. Edge: clients to halo-proxy with --next-hop to your existing gateway, then the provider. "
        "b. Behind a gateway: clients to your gateway, then halo-proxy, then the provider. "
        "c. Standalone: clients to halo-proxy to the providers.",
    )
    x0, sw, sg = 168, 114, 34
    slots = [x0 + i * (sw + sg) for i in range(4)]
    rows_ = [
        (
            "a · Edge",
            "in front of your gateway",
            [
                (0, "Clients", []),
                (1, "halo-proxy", ["--next-hop"]),
                (2, "Your gateway", []),
                (3, "Provider", []),
            ],
        ),
        (
            "b · Behind",
            "after your gateway",
            [
                (0, "Clients", []),
                (1, "Your gateway", []),
                (2, "halo-proxy", []),
                (3, "Provider", []),
            ],
        ),
        (
            "c · Standalone",
            "no other gateway",
            [(0, "Clients", []), (1, "halo-proxy", []), (3, "Providers", [])],
        ),
    ]
    for r, (lab, sub, cards) in enumerate(rows_):
        y = 24 + r * 84
        d.kicker(24, y + 26, lab)
        d.text(24, y + 44, sub, "s", maxw=160, size=12)
        prev = None
        for slot, t, s in cards:
            kind = "accent" if t == "halo-proxy" else "card"
            d.card(
                slots[slot],
                y,
                sw,
                60,
                t,
                s,
                kind=kind,
                mono_sub=True,
                pad=10,
                center=True,
            )
            if prev is not None:
                d.path(
                    [(slots[prev] + sw + 6, y + 30), (slots[slot] - 6, y + 30)], "line"
                )
            prev = slot
    d.write()

    # ---------------------------------------------------------- guides
    d = D(
        "bedrock-kong",
        W,
        120,
        "Bedrock through Kong",
        "Claude Code calls Kong with halo-kong, then your auth gateway, then an orchestrator that signs "
        "with SigV4 for Amazon Bedrock.",
    )
    hrow(
        d,
        28,
        64,
        [
            dict(title="Claude Code", subs=["client"]),
            dict(title="Kong", subs=["+ halo-kong"], kind="accent"),
            dict(title="Auth gateway", subs=["identity"]),
            dict(title="Orchestrator", subs=["SigV4"]),
            dict(title="Bedrock", subs=["Amazon"]),
        ],
        gap=32,
        pad=12,
        center=True,
    )
    d.write()

    d = D(
        "cli-upgrade-flow",
        W,
        280,
        "CLI upgrade A/B flow",
        "Pin a new CLI version in a profile, validate, run evals, and on pass publish ring1-canary with a "
        "ring release and two channels. halod picks the variant and pulls its channel. A promote verdict "
        "opens a PR setting the ring profile to treatment and concluding; a breach pauses and republishes "
        "or runs halo rollback.",
    )
    r1 = hrow(
        d,
        24,
        76,
        [
            dict(title="Pin version", subs=["in a profile"], kicker="01"),
            dict(title="Validate", subs=["halo validate"], kicker="02", mono_sub=True),
            dict(title="Eval", subs=["halo eval run"], kicker="03", mono_sub=True),
            dict(title="Publish", subs=["ring1-canary"], kicker="04", kind="accent"),
        ],
        gap=40,
    )
    d.pill(r1[2][0] + r1[2][2] + 20, 44, "pass", "accent")
    xp = r1[3][0] + r1[3][2] / 2
    d.card(
        r1[3][0],
        168,
        r1[3][2],
        76,
        "halod",
        ["picks variant", "pulls its channel"],
        kicker="05",
    )
    d.path([(xp, 106), (xp, 162)], "line")
    d.card(
        r1[1][0],
        140,
        r1[2][0] + r1[2][2] - r1[1][0],
        56,
        "Promote PR",
        ["ring profile = treatment · conclude"],
        kind="accent",
    )
    d.card(
        r1[1][0],
        208,
        r1[2][0] + r1[2][2] - r1[1][0],
        56,
        "Breach",
        ["pause + republish, or halo rollback"],
        kind="danger",
    )
    xb = r1[3][0] - 20
    d.path(
        [(r1[3][0] - 6, 206), (xb, 206), (xb, 168), (r1[2][0] + r1[2][2] + 6, 168)],
        "accent",
        r=6,
    )
    d.path(
        [(r1[3][0] - 6, 206), (xb, 206), (xb, 236), (r1[2][0] + r1[2][2] + 6, 236)],
        "danger",
        r=6,
    )
    d.write()

    d = D(
        "model-canary-flow",
        W,
        236,
        "Model upgrade canary flow",
        "Add a candidate route, shadow 5 percent of first turns, and when the judge is happy run replay "
        "evals; on pass canary 5 to 10 percent of ring1. mSPRT plus guardrails lead to a PR swapping the "
        "alias route; a breach pauses the experiment and recompiles policy in seconds.",
    )
    r1 = hrow(
        d,
        24,
        72,
        [
            dict(title="Candidate", subs=["new model route"]),
            dict(title="Shadow", subs=["5% of first turns"]),
            dict(title="Replay evals", subs=["halo eval run"], mono_sub=True),
            dict(title="Canary", subs=["5–10% of ring1"], kind="accent"),
        ],
        gap=56,
    )
    d.pill(r1[2][0] - 28, 42, "judge OK", "accent")
    d.pill(r1[3][0] - 28, 42, "pass", "accent")
    x3, w3 = r1[3][0], r1[3][2]
    d.card(x3, 156, w3, 56, "Swap alias", ["by PR, merged"], kind="accent")
    d.card(r1[2][0], 156, r1[2][2], 56, "Pause", ["takes seconds"], kind="danger")
    d.path([(x3 + w3 - 40, 102), (x3 + w3 - 40, 150)], "accent")
    d.pill(x3 + w3 - 40, 126, "mSPRT ✓", "accent")
    xc2 = r1[2][0] + r1[2][2] / 2
    d.path([(x3 + 30, 102), (x3 + 30, 128), (xc2, 128), (xc2, 150)], "danger", r=8)
    d.pill((x3 + 30 + xc2) / 2, 128, "breach", "danger")
    d.write()

    d = D(
        "header-stripping",
        W,
        152,
        "Gateway header handling",
        "The client sends a forged x-halo-ring header; the gateway deletes every x-halo header, verifies "
        "the JWT for user and groups, decides ring, release, experiment and variant, then sets x-halo "
        "stamps on the upstream request.",
    )
    hrow(
        d,
        24,
        104,
        [
            dict(
                title="Client",
                subs=["sends a forged", "x-halo-ring"],
                kind="danger",
                kicker="in",
            ),
            dict(title="Strip", subs=["deletes every", "x-halo-* header"], kicker="1"),
            dict(
                title="Verify JWT", subs=["user + groups", "from the token"], kicker="2"
            ),
            dict(title="Decide", subs=["ring · release", "exp · variant"], kicker="3"),
            dict(
                title="Stamp",
                subs=["sets x-halo-*", "on the upstream"],
                kind="accent",
                kicker="out",
            ),
        ],
        gap=22,
        pad=12,
    )
    d.write()


def more_diagrams():
    d = D(
        "upgrade-watch",
        W,
        236,
        "Upgrade watch",
        "halo upgrade watch finds a new CLI version on npm or a new model in a provider list, verifies the "
        "install artifacts, pins the candidate on a branch and runs the eval gate. Ship or hold opens a PR a "
        "human merges; block opens nothing.",
    )
    r = hrow(
        d,
        24,
        76,
        [
            dict(
                title="Discover",
                subs=["npm latest", "provider model list"],
                kicker="01",
            ),
            dict(title="Verify", subs=["sha256 / npm", "integrity"], kicker="02"),
            dict(
                title="Pin on a branch",
                subs=["profile version", "or gateway model"],
                kicker="03",
            ),
            dict(
                title="Eval gate",
                subs=["candidate vs", "current pin"],
                kicker="04",
                kind="accent",
            ),
        ],
        gap=36,
    )
    x3, w3 = r[3][0], r[3][2]
    xa = r[2][0]
    d.card(
        xa, 148, r[2][2], 64, "Open PR", ["ship · hold", "human merges"], kind="accent"
    )
    d.card(x3, 148, w3, 64, "No PR", ["block", "recorded in state"], kind="danger")
    d.path(
        [
            (x3 + 36, 106),
            (x3 + 36, 126),
            (xa + r[2][2] / 2, 126),
            (xa + r[2][2] / 2, 142),
        ],
        "accent",
        r=8,
    )
    d.path([(x3 + w3 - 36, 106), (x3 + w3 - 36, 142)], "danger")
    d.text(24, 196, "never merges, publishes", "xs")
    d.text(24, 212, "or retags a ring", "xs")
    d.write()

    d = D(
        "route-failover",
        W,
        212,
        "Model route failover",
        "A model alias resolves to priority tiers. Within tier 0 a weighted pick, sticky per user and "
        "session, goes first and the rest of the tier follows. On a connect error, 5xx or 429, before any "
        "byte reaches the client, halo-proxy tries the next target, then the next tier.",
    )
    d.card(24, 72, 136, 56, "alias", ["opus · default"], title_mono=True, mono_sub=True)
    d.zone(188, 24, 300, 164, "Tier 0 · priority 0")
    d.card(
        204,
        60,
        268,
        52,
        "Weighted pick",
        ["90 / 10, sticky per user+session"],
        kind="accent",
    )
    d.card(204, 124, 268, 48, "Rest of tier", ["policy order"])
    d.zone(536, 24, 200, 164, "Tier 1 · priority 1")
    d.card(552, 60, 168, 52, "Failover target", ["other provider"])
    d.path([(166, 100), (182, 100)], "line")
    d.path([(338, 112), (338, 118)], "line")
    d.path([(478, 86), (546, 86)], "danger", dashed=True)
    d.pill(512, 86, "5xx", "danger")
    d.text(552, 140, "connect error, 5xx or 429,", "xs")
    d.text(552, 156, "before the first byte", "xs")
    d.write()


def main():
    hero()
    architecture()
    rollout_strategies()
    experiments()
    measure_loop()
    toggles()
    everywhere()
    docs_diagrams()
    more_diagrams()


if __name__ == "__main__":
    main()

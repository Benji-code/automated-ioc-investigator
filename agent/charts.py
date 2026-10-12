"""Charts in the report, chosen by the model.

Two ways in, both chosen by the model:
  - ready-made charts: prepared() builds a menu from data the evidence step
    already fetched (no extra queries). The case file lists them and the
    model places the ones it wants with [[chart <name>]], with no tool call
    (small models rarely call tools).
  - its own: the add_chart tool takes a SQL query (checked by the same
    guardrails as run_sql) and how to draw it; it is placed as [[chart N]].
Code draws every chart as a self-contained SVG, so the report needs no
internet or chart library.

  add_chart()    the tool: check, query, build, store (at most MAX_CHARTS per case)
  prepared()     the ready-made menu for one case
  build_chart()  rows -> chart dict (pure, so it is testable offline)
  render_svg()   chart dict -> SVG text
"""
from __future__ import annotations

import html
import math
import re
from datetime import datetime, timezone

import pandas as pd

from . import analysis, config, db

CHART_MAX_ROWS = 2000
MAX_SERIES = 3           # the first three palette slots stay distinct for colour-blind readers
MAX_BARS = 25
MAX_HOVER_BANDS = 300
KINDS = ("line", "bar")
UNITS = ("bytes", "count", "seconds", "other")

SPEC = {
    "type": "function",
    "function": {
        "name": "add_chart",
        "description": (
            "Add a chart to the report (at most 3 per case). Give a read-only SQL query (the same rules as "
            "run_sql: allowed tables, filter on this case's client_ip or a flagged server_ip, a time column "
            "within the table's span) and how to draw it. 'line': x is a time (or number) column, one line per "
            "y column, or one line per value of 'series' (at most 3). 'bar': one bar per row of x (at most 25, "
            "in the query's order), one bar per y column. Aggregate in SQL (toStartOfHour(time), "
            "toStartOfDay(time), sum(...)): at most 2000 rows. Returns the chart number and a summary of its "
            "data; put it in the report on its own line as [[chart N]]. Call again with chart_id to replace one. "
            "Try the case file's ready-made charts first."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "short title saying what is plotted"},
                "sql": {"type": "string", "description": "one read-only SELECT returning the plotted columns"},
                "kind": {"type": "string", "enum": list(KINDS)},
                "x": {"type": "string", "description": "column for the x axis (time for line charts)"},
                "y": {"type": "array", "items": {"type": "string"},
                      "description": "1-3 numeric columns to plot (one if 'series' is given)"},
                "labels": {"type": "array", "items": {"type": "string"},
                           "description": "optional legend names for the y columns, e.g. [\"upload\", \"download\"]"},
                "series": {"type": "string", "description": "optional column whose values split y into lines"},
                "unit": {"type": "string", "enum": list(UNITS), "description": "unit of the y values"},
                "log_scale": {"type": "boolean", "description": "log y axis (line charts only), for values "
                              "that differ by orders of magnitude"},
                "caption": {"type": "string", "description": "one or two sentences: what the reader should see"},
                "chart_id": {"type": "string", "description": "replace this existing chart instead of adding one"},
            },
            "required": ["title", "sql", "kind", "x", "y"],
        },
    },
}


# --- the tool --------------------------------------------------------------------------

def add_chart(arguments: dict, *, client_ip: str, server_ips: list[str], charts: list[dict]) -> dict:
    """Check the request, run its query and store the chart in `charts`.
    Every problem comes back as {"error": ...} the model can act on."""
    spec, error = _spec(arguments)
    if error:
        return {"error": error}
    replace = arguments.get("chart_id")
    replace = str(replace).strip() if replace not in (None, "") else None
    ids = [c["id"] for c in charts]
    if replace is not None and replace not in ids:
        return {"error": f"there is no chart {replace} to replace (charts so far: {ids or 'none'})."}
    if replace is None and len(charts) >= config.MAX_CHARTS:
        return {"error": f"the report already has {config.MAX_CHARTS} charts; pass chart_id to replace one."}

    error, sql = db.check_sql(spec["sql"], client_ip, server_ips, row_cap=CHART_MAX_ROWS + 1)
    if error:
        return {"error": error}
    try:
        frame = db.query(sql)
    except Exception as exc:  # noqa: BLE001 - the ClickHouse error is what the model needs
        return {"error": f"Error running query: {exc}"}

    chart_id = replace if replace is not None else str(max((int(i) for i in ids if i.isdigit()), default=0) + 1)
    chart, error = build_chart({**spec, "id": chart_id}, frame, client_ip)
    if error:
        return {"error": error}
    if replace is not None:
        charts[ids.index(replace)] = chart
    else:
        charts.append(chart)
    return summary(chart)


def _spec(arguments: dict) -> tuple[dict, str | None]:
    title = str(arguments.get("title") or "").strip()
    sql = str(arguments.get("sql") or "").strip()
    kind = str(arguments.get("kind") or "").strip().lower()
    x = str(arguments.get("x") or "").strip()
    y = arguments.get("y") or []
    if isinstance(y, str):
        y = [part.strip() for part in y.split(",")]
    y = [str(col).strip() for col in y if str(col).strip()]
    series = str(arguments.get("series") or "").strip() or None
    unit = str(arguments.get("unit") or "").strip().lower() or None
    log_scale = bool(arguments.get("log_scale"))
    labels = arguments.get("labels") or []
    labels = [str(label).strip() for label in (labels if isinstance(labels, list) else [labels])]
    missing = [name for name, value in (("title", title), ("sql", sql), ("x", x), ("y", y)) if not value]
    if missing:
        return {}, f"missing: {', '.join(missing)}."
    if kind not in KINDS:
        return {}, f"kind must be one of {', '.join(KINDS)}."
    if len(y) > MAX_SERIES:
        return {}, f"at most {MAX_SERIES} y columns."
    if series and len(y) != 1:
        return {}, "with 'series', give exactly one y column."
    if labels and len(labels) != len(y):
        return {}, "give one label per y column, or none."
    if unit and unit not in UNITS:
        return {}, f"unit must be one of {', '.join(UNITS)}."
    if log_scale and kind != "line":
        return {}, "log_scale is only for line charts: a bar on a log axis has no true baseline."
    return {"title": title, "sql": sql, "kind": kind, "x": x, "y": y, "series_column": series,
            "unit": unit, "log_scale": log_scale, "labels": labels, "caption": str(arguments.get("caption") or "").strip()}, None


# --- rows -> chart ---------------------------------------------------------------------

DATE_LIKE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _x_type(values: pd.Series) -> str:
    if pd.api.types.is_datetime64_any_dtype(values):
        return "time"
    if pd.api.types.is_numeric_dtype(values) and not pd.api.types.is_bool_dtype(values):
        return "number"
    text = values.astype(str)
    if text.map(lambda v: bool(DATE_LIKE_RE.match(v))).all():
        return "time"
    return "category"


def _guess_unit(columns: list[str]) -> str:
    joined = " ".join(columns).lower()
    if "byte" in joined or "_total" in joined or "volume" in joined:
        return "bytes"
    if "sec" in joined or "duration" in joined:
        return "seconds"
    return "count"


def build_chart(spec: dict, frame: pd.DataFrame, client_ip: str = "",
                highlight: list[str] | None = None) -> tuple[dict, str | None]:
    """Turn query rows into a chart dict, or explain why they cannot be drawn.
    In a one-series bar chart, bars named in `highlight` (default: the case's
    host) are coloured and the rest are grey."""
    if frame is None or frame.empty:
        return {}, "the query returned 0 rows, so there is nothing to plot. Check the filters and time window."
    if len(frame) > CHART_MAX_ROWS:
        return {}, (f"the query returned more than {CHART_MAX_ROWS} rows. Aggregate into larger buckets "
                    "(toStartOfHour(time), toStartOfDay(time)) or narrow the window.")
    needed = [spec["x"], *spec["y"]] + ([spec["series_column"]] if spec.get("series_column") else [])
    absent = [col for col in needed if col not in frame.columns]
    if absent:
        return {}, f"columns not in the result: {', '.join(absent)} (the result has {', '.join(map(str, frame.columns))})."

    frame = frame.copy()
    for col in spec["y"]:
        frame[col] = pd.to_numeric(frame[col], errors="coerce")
        if frame[col].isna().all():
            return {}, f"column {col} is not numeric."
    x_type = _x_type(frame[spec["x"]])
    if spec["kind"] == "line" and x_type == "category":
        return {}, f"a line chart needs a time or numeric x; {spec['x']} is neither. Use kind 'bar'."
    if x_type == "time":
        frame[spec["x"]] = pd.to_datetime(frame[spec["x"]], utc=True, errors="coerce")
        frame = frame.dropna(subset=[spec["x"]])

    series, omitted = _series(spec, frame, x_type)
    truncated = 0
    if spec["kind"] == "bar" and x_type == "category":
        categories = list(dict.fromkeys(str(v) for v in frame[spec["x"]]))
        truncated = max(len(categories) - MAX_BARS, 0)
        keep = set(categories[:MAX_BARS])
        for s in series:
            s["points"] = [p for p in s["points"] if p[0] in keep]
    if spec["kind"] == "line" and not any(len(s["points"]) >= 2 for s in series):
        return {}, "a line chart needs at least two points; use a bar chart or a wider window."

    unit = spec.get("unit") or _guess_unit(spec["y"])
    chart = {
        "id": str(spec["id"]), "title": spec["title"], "kind": spec["kind"], "caption": spec.get("caption", ""),
        "sql": spec["sql"], "x": spec["x"], "y": spec["y"], "series_column": spec.get("series_column"),
        "unit": unit, "log_scale": spec.get("log_scale", False), "x_type": x_type, "series": series,
        "omitted_series": omitted, "truncated_bars": truncated,
        "highlight": highlight if highlight is not None else ([client_ip] if client_ip else []),
        "markers": spec.get("markers") or [], "source": spec.get("source", ""),
        "columns": [str(c) for c in frame.columns], "rows": _json_rows(frame),
    }
    return chart, None


def _x_value(value, x_type: str):
    if x_type == "time":
        return pd.Timestamp(value).isoformat()
    if x_type == "number":
        return float(value)
    return str(value)


def _series(spec: dict, frame: pd.DataFrame, x_type: str) -> tuple[list[dict], int]:
    x = spec["x"]
    if spec.get("series_column"):
        col, y = spec["series_column"], spec["y"][0]
        totals = frame.groupby(frame[col].astype(str))[y].sum().abs().sort_values(ascending=False)
        names = list(totals.index[:MAX_SERIES])
        groups = [(name, frame[frame[col].astype(str) == name], y) for name in names]
        omitted = max(len(totals) - MAX_SERIES, 0)
    else:
        labels = spec.get("labels") or [_tidy(y) for y in spec["y"]]
        groups = [(label, frame, y) for label, y in zip(labels, spec["y"])]
        omitted = 0
    series = []
    for name, rows, y in groups:
        rows = rows.dropna(subset=[y])
        if x_type != "category":
            rows = rows.sort_values(x)
        points = [[_x_value(xv, x_type), float(yv)] for xv, yv in zip(rows[x], rows[y])]
        series.append({"name": str(name), "points": points})
    return series, omitted


def _tidy(column: str) -> str:
    """A column name as a legend label: up_bytes -> up bytes."""
    return column.replace("__", " ").replace("_", " ").strip()


def _json_rows(frame: pd.DataFrame) -> list[list]:
    rows = []
    for record in frame.itertuples(index=False):
        row = []
        for value in record:
            if isinstance(value, (pd.Timestamp, datetime)):
                row.append(pd.Timestamp(value).isoformat())
            elif value is None or (isinstance(value, float) and math.isnan(value)):
                row.append(None)
            elif hasattr(value, "item"):
                row.append(value.item())  # numpy scalar
            elif isinstance(value, (int, float, str, bool)):
                row.append(value)
            else:
                row.append(str(value))
        rows.append(row)
    return rows


def summary(chart: dict) -> dict:
    """What the model gets back: enough to describe the chart in the text,
    with values formatted the way the chart shows them."""
    per_series = []
    for s in chart["series"]:
        values = [p[1] for p in s["points"]]
        if not values:
            continue
        entry = {"name": s["name"], "points": len(values), "min": fmt_value(min(values), chart["unit"]),
                 "max": fmt_value(max(values), chart["unit"])}
        if chart["unit"] in ("bytes", "count"):
            entry["total"] = fmt_value(sum(values), chart["unit"])
        if chart["x_type"] != "category":
            entry["from"], entry["to"] = s["points"][0][0], s["points"][-1][0]
            peak = max(s["points"], key=lambda p: p[1])
            entry["peak_at"] = peak[0]
        per_series.append(entry)
    notes = []
    if chart["omitted_series"]:
        notes.append(f"{chart['omitted_series']} smaller series left out (at most {MAX_SERIES} lines).")
    if chart["truncated_bars"]:
        notes.append(f"only the first {MAX_BARS} bars are drawn; {chart['truncated_bars']} more left out.")
    return {"chart_id": chart["id"], "title": chart["title"], "rows": len(chart["rows"]), "series": per_series,
            "notes": notes, "place_it": f"Put [[chart {chart['id']}]] on its own line in the report."}


# --- formatting --------------------------------------------------------------------------

def fmt_bytes(value: float) -> str:
    """Compact, for axis ticks: 200 MB, 1.5 GB."""
    size = abs(value)
    for unit, scale in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if size >= scale:
            number = value / scale
            return f"{number:.0f} {unit}" if abs(number) >= 100 or number == int(number) else f"{number:.1f} {unit}"
    return f"{value:.0f} B"


def fmt_tick(value: float, unit: str) -> str:
    return fmt_bytes(value) if unit == "bytes" else fmt_value(value, unit)


def fmt_count(value: float) -> str:
    """1,234 / 12.3K / 4.5M: compact from 10,000 up."""
    size = abs(value)
    for suffix, scale, threshold in (("B", 1e9, 1e9), ("M", 1e6, 1e6), ("K", 1e3, 1e4)):
        if size >= threshold:
            return f"{value / scale:.1f}".rstrip("0").rstrip(".") + suffix
    if value == int(value):
        return f"{int(value):,}"
    return f"{value:,.2f}".rstrip("0").rstrip(".")


def fmt_seconds(value: float) -> str:
    if abs(value) < 120:
        return f"{value:.0f} s"
    if abs(value) < 7200:
        return f"{value / 60:.0f} min"
    if abs(value) < 172800:
        return f"{value / 3600:.1f} h".replace(".0 h", " h")
    return f"{value / 86400:.1f} d".replace(".0 d", " d")


def fmt_value(value: float, unit: str) -> str:
    """A value as the case file writes it (97.0 MB), so quoted numbers match the evidence."""
    if unit == "bytes":
        return analysis.fmt_bytes(value)
    if unit == "seconds":
        return fmt_seconds(value)
    return fmt_count(value)


# --- drawing -------------------------------------------------------------------------------

WIDTH = 720
PLOT_HEIGHT = 220
FONT = 11
CHAR_W = 6.4          # rough width of one 11px character, for label space
LINE_H = 13           # line height of a wrapped label
LABEL_CHARS = 30      # characters per line of a bar label before it wraps
LEGEND_CHARS = 60
BAR_BAND = 28
BAR_MAX = 24

STYLE = """<style>
.ioc-chart{--s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;--dim:#c4c2ba;--ink:#0b0b0b;--ink2:#52514e;--muted:#6f6d68;
--grid:#e6e5df;--axis:#c3c2b7;--surf:var(--card,#fcfcfb);font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
@media (prefers-color-scheme:dark){.ioc-chart{--s1:#3987e5;--s2:#d95926;--s3:#199e70;--dim:#4d4c48;--ink:#fff;
--ink2:#c3c2b7;--muted:#9a9890;--grid:#2c2c2a;--axis:#45453f;--surf:var(--card,#1a1a19)}}
.ioc-chart text{font-size:11px;fill:var(--muted)}
.ioc-chart .lg{fill:var(--ink2)}
.ioc-chart .val{fill:var(--ink2);font-variant-numeric:tabular-nums}
.ioc-chart .grid{stroke:var(--grid);stroke-width:1}
.ioc-chart .base{stroke:var(--axis);stroke-width:1}
.ioc-chart .mark-line{stroke:var(--ink2);stroke-width:1;opacity:.7}
.ioc-chart .mark-band{fill:var(--ink2);opacity:.12}
.ioc-chart .mark-text{fill:var(--ink2);font-weight:600}
.ioc-chart .hit{fill:var(--ink);opacity:0}
.ioc-chart .hit:hover{opacity:.06}
.ioc-chart .bar:hover{opacity:.8}
</style>"""


def _e(text) -> str:
    return html.escape(str(text), quote=True)


def _color(i: int) -> str:
    return f"var(--s{i % MAX_SERIES + 1})"


def nice_step(span: float, target: int = 5) -> float:
    if span <= 0:
        return 1.0
    raw = span / target
    power = 10 ** math.floor(math.log10(raw))
    for mult in (1, 2, 2.5, 5, 10):
        if raw <= mult * power:
            return mult * power
    return 10 * power


def linear_ticks(lo: float, hi: float, unit: str) -> list[float]:
    if unit == "bytes" and hi > 0:
        scale = 10 ** (3 * math.floor(math.log10(hi) / 3))  # ticks in whole KB/MB/GB
        step = nice_step((hi - lo) / scale) * scale
    else:
        step = nice_step(hi - lo)
    start = math.floor(lo / step) * step
    ticks = []
    value = start
    while value <= hi + step * 0.999:
        ticks.append(round(value, 10))
        value += step
    return ticks


def log_ticks(lo: float, hi: float) -> list[float]:
    first, last = math.floor(math.log10(lo)), math.ceil(math.log10(hi))
    powers = list(range(first, last + 1))
    stride = max(1, math.ceil(len(powers) / 6))
    return [10.0 ** p for p in powers[::stride]]


TIME_STEPS = [60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 2 * 86400, 7 * 86400,
              14 * 86400, 30 * 86400]


def time_ticks(lo: datetime, hi: datetime) -> tuple[list[datetime], str]:
    span = max((hi - lo).total_seconds(), 60)
    step = next((s for s in TIME_STEPS if span / s <= 6), TIME_STEPS[-1])
    epoch = lo.timestamp()
    first = math.ceil(epoch / step) * step
    ticks = []
    t = first
    while t <= hi.timestamp():
        ticks.append(datetime.fromtimestamp(t, tz=timezone.utc))
        t += step
    fmt = "%d %b" if step >= 86400 else "%H:%M"
    return ticks, fmt


def _parse_time(text: str) -> datetime:
    moment = datetime.fromisoformat(text)
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _legend(chart: dict, top: int, left: int) -> tuple[str, int]:
    """Legend keys, moving to a new row at the chart's edge rather than
    cutting a name short. Returns (svg, extra height used below `top`)."""
    if len(chart["series"]) < 2:
        return "", 0
    parts, x, y = [], left, top
    for i, s in enumerate(chart["series"]):
        lines = wrap_label(s["name"], LEGEND_CHARS)
        key_w = 22 if chart["kind"] == "line" else 15
        width = key_w + max(len(line) for line in lines) * CHAR_W + 18
        if x > left and x + width > WIDTH:
            x, y = left, y + LINE_H + 4
        if chart["kind"] == "line":
            key = f'<line x1="{x}" y1="{y - 4}" x2="{x + 16}" y2="{y - 4}" style="stroke:{_color(i)}" stroke-width="2" stroke-linecap="round"/>'
        else:
            key = f'<rect x="{x}" y="{y - 9}" width="10" height="10" rx="2" style="fill:{_color(i)}"/>'
        parts.append(f'{key}<text class="lg" x="{x + key_w}" y="{y}">{_tspans(lines, x + key_w)}</text>')
        x += width
        if len(lines) > 1:  # a wrapped name takes its rows to itself
            x, y = left, y + LINE_H * len(lines) + 4
    return "".join(parts), y - top


def wrap_label(text: str, width: int) -> list[str]:
    """Break a label into lines of at most `width` characters, at spaces where
    possible; a long word (a domain) is cut after a dot or hyphen, else
    anywhere. Never shortens the label."""
    lines: list[str] = []
    current = ""
    for word in str(text).split():
        while len(word) > width:
            cut = max(word.rfind(".", 0, width), word.rfind("-", 0, width)) + 1 or width
            if current:
                lines.append(current)
                current = ""
            lines.append(word[:cut])
            word = word[cut:]
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current or not lines:
        lines.append(current)
    return lines


def _tspans(lines: list[str], x: float) -> str:
    """Lines of one text element, each below the last."""
    return "".join(f'<tspan x="{x:.1f}" dy="{0 if i == 0 else LINE_H}">{_e(line)}</tspan>'
                   for i, line in enumerate(lines))


def _y_scale(chart: dict, values: list[float]):
    unit, log = chart["unit"], chart["log_scale"]
    if log:
        positive = [v for v in values if v > 0] or [1.0]
        ticks = log_ticks(min(positive), max(positive))
        lo, hi = math.log10(ticks[0]), math.log10(ticks[-1])
        hi = hi if hi > lo else lo + 1

        def scale(v: float) -> float:
            return (math.log10(max(v, ticks[0])) - lo) / (hi - lo)
        return scale, ticks
    lo = min(0.0, min(values, default=0.0))
    hi = max(values, default=1.0)
    hi = hi if hi > lo else lo + 1
    ticks = linear_ticks(lo, hi, unit)
    top = ticks[-1] if ticks[-1] > lo else lo + 1

    def scale(v: float) -> float:
        return (v - ticks[0]) / (top - ticks[0])
    return scale, ticks


def _fill_gaps(points: list[tuple[float, float]], unit: str) -> list[tuple[float, float]]:
    """Traffic rows only exist for active buckets: a gap means zero, so for
    bytes and counts the line drops to zero across it instead of drawing a
    straight line over the quiet time."""
    if unit not in ("bytes", "count") or len(points) < 3:
        return points
    gaps = sorted(b[0] - a[0] for a, b in zip(points, points[1:]) if b[0] > a[0])
    if not gaps:
        return points
    step = gaps[0] if gaps[0] > 0 else gaps[len(gaps) // 2]
    filled = [points[0]]
    for a, b in zip(points, points[1:]):
        if b[0] - a[0] > 1.5 * step:
            filled.append((a[0] + step, 0.0))
            if b[0] - step > a[0] + step:
                filled.append((b[0] - step, 0.0))
        filled.append(b)
    return filled


def _line_svg(chart: dict) -> str:
    is_time = chart["x_type"] == "time"
    raw = []
    for s in chart["series"]:
        pts = [((_parse_time(x).timestamp() if is_time else float(x)), y) for x, y in s["points"]]
        raw.append(_fill_gaps(pts, chart["unit"]))
    all_x = [p[0] for pts in raw for p in pts]
    all_y = [p[1] for pts in raw for p in pts]
    y_scale, y_ticks = _y_scale(chart, all_y)
    tick_labels = [fmt_tick(t, chart["unit"]) for t in y_ticks]
    left = int(max(len(t) for t in tick_labels) * CHAR_W + 14)
    right = 18
    legend, extra = _legend(chart, 14, left)
    top = (30 + extra if len(chart["series"]) >= 2 else 10) + (16 if is_time and chart.get("markers") else 0)
    plot_w, plot_h = WIDTH - left - right, PLOT_HEIGHT
    height = top + plot_h + 34
    x_lo, x_hi = min(all_x), max(all_x)
    x_span = (x_hi - x_lo) or 1.0

    def px(x: float) -> float:
        return left + (x - x_lo) / x_span * plot_w

    def py(y: float) -> float:
        return top + plot_h - y_scale(y) * plot_h

    out = [legend]
    for tick, label in zip(y_ticks, tick_labels):
        y = py(tick)
        css = "base" if tick == y_ticks[0] else "grid"
        out.append(f'<line class="{css}" x1="{left}" x2="{left + plot_w}" y1="{y:.1f}" y2="{y:.1f}"/>'
                   f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{_e(label)}</text>')
    if is_time:
        lo_t, hi_t = datetime.fromtimestamp(x_lo, timezone.utc), datetime.fromtimestamp(x_hi, timezone.utc)
        ticks, fmt = time_ticks(lo_t, hi_t)
        for i, t in enumerate(ticks):
            label = t.strftime(fmt)
            if fmt == "%H:%M" and (i == 0 or t.date() != ticks[i - 1].date()):
                label = t.strftime("%d %b %H:%M")
            out.append(f'<text x="{px(t.timestamp()):.1f}" y="{top + plot_h + 18}" text-anchor="middle">{_e(label)}</text>')
        out.append(f'<text x="{left + plot_w}" y="{top + plot_h + 32}" text-anchor="end">UTC</text>')
    else:
        for t in linear_ticks(x_lo, x_hi, "count"):
            if x_lo <= t <= x_hi:
                out.append(f'<text x="{px(t):.1f}" y="{top + plot_h + 18}" text-anchor="middle">{_e(fmt_count(t))}</text>')
        out.append(f'<text x="{left + plot_w}" y="{top + plot_h + 32}" text-anchor="end">{_e(chart["x"])}</text>')

    if is_time:
        out.append(_markers_svg(chart, px, x_lo, x_hi, top, plot_h, left + plot_w))
    base_y = py(y_ticks[0])
    for i, pts in enumerate(raw):
        if not pts:
            continue
        coords = " ".join(f"{px(x):.1f},{py(y):.1f}" for x, y in pts)
        if len(raw) == 1 and not chart["log_scale"]:
            out.append(f'<polygon points="{px(pts[0][0]):.1f},{base_y:.1f} {coords} {px(pts[-1][0]):.1f},{base_y:.1f}" '
                       f'style="fill:{_color(i)}" opacity="0.1"/>')
        out.append(f'<polyline points="{coords}" fill="none" style="stroke:{_color(i)}" stroke-width="2" '
                   'stroke-linejoin="round" stroke-linecap="round"/>')
        last = pts[-1]
        out.append(f'<circle cx="{px(last[0]):.1f}" cy="{py(last[1]):.1f}" r="4" style="fill:{_color(i)};'
                   'stroke:var(--surf)" stroke-width="2"/>')
    out.append(_hover_bands(chart, px, top, plot_h, is_time))
    return _wrap(chart, height, "".join(out))


def _markers_svg(chart: dict, px, x_lo: float, x_hi: float, top: float, plot_h: float, right: float) -> str:
    """Times to point out, e.g. the flagged contact: a hairline, or a light
    band for a span, with a short label at the top."""
    out = []
    for marker in chart.get("markers") or []:
        start = _parse_time(marker["start"]).timestamp()
        end = _parse_time(marker.get("end") or marker["start"]).timestamp()
        if end < x_lo or start > x_hi:
            continue
        x0, x1 = px(max(start, x_lo)), px(min(end, x_hi))
        if x1 - x0 >= 3:
            out.append(f'<rect x="{x0:.1f}" y="{top}" width="{x1 - x0:.1f}" height="{plot_h}" class="mark-band"/>')
        else:
            out.append(f'<line x1="{x0:.1f}" x2="{x0:.1f}" y1="{top}" y2="{top + plot_h}" class="mark-line"/>')
        label = _e(marker.get("label", ""))
        if x1 - x0 >= 110:
            anchor, tx = "start", x0             # above a wide band
        elif x0 > right - 110:
            anchor, tx = "end", x0 - 4          # left of a mark near the right edge
        else:
            anchor, tx = "start", x1 + 4
        out.append(f'<text class="mark-text" x="{tx:.1f}" y="{top - 5}" text-anchor="{anchor}">{label}</text>')
    return "".join(out)


def _hover_bands(chart: dict, px, top: float, plot_h: float, is_time: bool) -> str:
    """Invisible full-height bands, one per x position, each with a tooltip
    listing every series there."""
    by_x: dict[str, dict[str, float]] = {}
    for s in chart["series"]:
        for x, y in s["points"]:
            by_x.setdefault(x, {})[s["name"]] = y
    keys = sorted(by_x, key=lambda k: _parse_time(k).timestamp() if is_time else float(k))
    if len(keys) > MAX_HOVER_BANDS:
        stride = math.ceil(len(keys) / MAX_HOVER_BANDS)
        keys = keys[::stride]
    positions = [px(_parse_time(k).timestamp() if is_time else float(k)) for k in keys]
    out = []
    for i, (key, pos) in enumerate(zip(keys, positions)):
        x0 = (positions[i - 1] + pos) / 2 if i else pos - 3
        x1 = (pos + positions[i + 1]) / 2 if i + 1 < len(positions) else pos + 3
        label = _parse_time(key).strftime("%Y-%m-%d %H:%M UTC") if is_time else fmt_count(float(key))
        lines = [label] + [f"{name}: {fmt_value(v, chart['unit'])}" for name, v in by_x[key].items()]
        out.append(f'<rect class="hit" x="{x0:.1f}" y="{top}" width="{max(x1 - x0, 1):.1f}" height="{plot_h}">'
                   f'<title>{_e(chr(10).join(lines))}</title></rect>')
    return "".join(out)


def _bar_svg(chart: dict) -> str:
    if chart["x_type"] == "category":
        return _hbar_svg(chart)
    return _column_svg(chart)


def _rounded_bar(x: float, y: float, w: float, h: float, horizontal: bool, style: str, title: str) -> str:
    """A bar with a 4px rounded data end and a square baseline end."""
    r = min(4.0, (h if horizontal else w) / 2, (w if horizontal else h))
    if horizontal:  # baseline on the left, data end on the right
        d = (f"M{x:.1f},{y:.1f}h{max(w - r, 0):.1f}a{r},{r} 0 0 1 {r},{r}v{max(h - 2 * r, 0):.1f}"
             f"a{r},{r} 0 0 1 {-r},{r}h{-max(w - r, 0):.1f}z")
    else:  # baseline at the bottom, data end on top
        d = (f"M{x:.1f},{y + h:.1f}v{-max(h - r, 0):.1f}a{r},{r} 0 0 1 {r},{-r}h{max(w - 2 * r, 0):.1f}"
             f"a{r},{r} 0 0 1 {r},{r}v{max(h - r, 0):.1f}z")
    return f'<path class="bar" d="{d}" style="{style}"><title>{_e(title)}</title></path>'


def _hbar_svg(chart: dict) -> str:
    categories = list(dict.fromkeys(p[0] for s in chart["series"] for p in s["points"]))
    values = {s["name"]: dict((p[0], p[1]) for p in s["points"]) for s in chart["series"]}
    all_v = [v for s in values.values() for v in s.values()]
    hi = max(max(all_v, default=1.0), 0.0) or 1.0
    ticks = linear_ticks(0.0, hi, chart["unit"])
    top_v = ticks[-1]
    single = len(chart["series"]) == 1
    marked = chart.get("highlight") or []
    marked = [marked] if isinstance(marked, str) else marked  # results saved before highlights were lists
    highlight = set(marked) & set(categories) if single else set()
    labels = [wrap_label(c, LABEL_CHARS) for c in categories]
    left = int(max(len(line) for lines in labels for line in lines) * CHAR_W + 16)
    right = 70 if single else 24
    legend, extra = _legend(chart, 14, left)
    top = 30 + extra if not single else 10
    plot_w = WIDTH - left - right
    n = len(chart["series"])
    band = max(BAR_BAND, n * 14 + 8, max(len(lines) for lines in labels) * LINE_H + 8)
    plot_h = band * len(categories)
    height = top + plot_h + 30

    def px(v: float) -> float:
        return left + max(v, 0.0) / top_v * plot_w

    out = [legend]
    for t in ticks:
        x = px(t)
        css = "base" if t == 0 else "grid"
        out.append(f'<line class="{css}" x1="{x:.1f}" x2="{x:.1f}" y1="{top}" y2="{top + plot_h}"/>'
                   f'<text x="{x:.1f}" y="{top + plot_h + 18}" text-anchor="middle">{_e(fmt_tick(t, chart["unit"]))}</text>')
    thick = min(BAR_MAX, (band - 8 - 2 * (n - 1)) / n)
    for row, (category, lines) in enumerate(zip(categories, labels)):
        y0 = top + row * band + (band - (thick * n + 2 * (n - 1))) / 2
        first_y = top + row * band + band / 2 + 4 - (len(lines) - 1) * LINE_H / 2
        out.append(f'<text class="lg" x="{left - 8}" y="{first_y:.1f}" text-anchor="end">'
                   f'<title>{_e(category)}</title>{_tspans(lines, left - 8)}</text>')
        for i, s in enumerate(chart["series"]):
            value = values[s["name"]].get(category)
            if value is None:
                continue
            fill = _color(i)
            if highlight and category not in highlight:
                fill = "var(--dim)"
            y = y0 + i * (thick + 2)
            width = px(value) - left
            title = f"{category}\n{s['name']}: {fmt_value(value, chart['unit'])}"
            out.append(_rounded_bar(left, y, max(width, 1.0), thick, True, f"fill:{fill}", title))
            if single:
                out.append(f'<text class="val" x="{left + max(width, 1.0) + 6:.1f}" y="{y + thick / 2 + 4:.1f}">'
                           f'{_e(fmt_value(value, chart["unit"]))}</text>')
    return _wrap(chart, height, "".join(out))


def _column_svg(chart: dict) -> str:
    is_time = chart["x_type"] == "time"
    keys = sorted({p[0] for s in chart["series"] for p in s["points"]},
                  key=lambda k: _parse_time(k).timestamp() if is_time else float(k))
    xs = [(_parse_time(k).timestamp() if is_time else float(k)) for k in keys]
    values = {s["name"]: dict((p[0], p[1]) for p in s["points"]) for s in chart["series"]}
    all_v = [v for s in values.values() for v in s.values()]
    ticks = linear_ticks(0.0, max(max(all_v, default=1.0), 0.0) or 1.0, chart["unit"])
    top_v = ticks[-1]
    labels = [fmt_tick(t, chart["unit"]) for t in ticks]
    left = int(max(len(t) for t in labels) * CHAR_W + 14)
    right = 18
    legend, extra = _legend(chart, 14, left)
    top = 30 + extra if len(chart["series"]) >= 2 else 10
    plot_w, plot_h = WIDTH - left - right, PLOT_HEIGHT
    height = top + plot_h + 34
    n = len(chart["series"])
    step = min((b - a for a, b in zip(xs, xs[1:]) if b > a), default=1.0)
    span = (xs[-1] - xs[0]) + step
    slot = plot_w / max(span / step, 1)
    thick = max(min(BAR_MAX, (slot * 0.8 - 2 * (n - 1)) / n), 1.0)
    group = thick * n + 2 * (n - 1)

    def px(x: float) -> float:
        return left + (x - xs[0] + step / 2) / span * plot_w

    def py(v: float) -> float:
        return top + plot_h - max(v, 0.0) / top_v * plot_h

    out = [legend]
    for t, label in zip(ticks, labels):
        css = "base" if t == 0 else "grid"
        out.append(f'<line class="{css}" x1="{left}" x2="{left + plot_w}" y1="{py(t):.1f}" y2="{py(t):.1f}"/>'
                   f'<text x="{left - 8}" y="{py(t) + 4:.1f}" text-anchor="end">{_e(label)}</text>')
    if is_time:
        lo_t = datetime.fromtimestamp(xs[0], timezone.utc)
        hi_t = datetime.fromtimestamp(xs[-1], timezone.utc)
        tick_times, fmt = time_ticks(lo_t, hi_t) if len(xs) > 1 else ([lo_t], "%d %b")
        for t in tick_times:
            out.append(f'<text x="{px(t.timestamp()):.1f}" y="{top + plot_h + 18}" text-anchor="middle">'
                       f'{_e(t.strftime(fmt))}</text>')
        out.append(f'<text x="{left + plot_w}" y="{top + plot_h + 32}" text-anchor="end">UTC</text>')
    for key, x in zip(keys, xs):
        x0 = px(x) - group / 2
        for i, s in enumerate(chart["series"]):
            value = values[s["name"]].get(key)
            if value is None or value <= 0:
                continue
            label = _parse_time(key).strftime("%Y-%m-%d %H:%M UTC") if is_time else key
            title = f"{label}\n{s['name']}: {fmt_value(value, chart['unit'])}"
            y = py(value)
            out.append(_rounded_bar(x0 + i * (thick + 2), y, thick, top + plot_h - y, False,
                                    f"fill:{_color(i)}", title))
    return _wrap(chart, height, "".join(out))


def _wrap(chart: dict, height: float, body: str) -> str:
    title = _e(chart["title"])
    return (f'<svg class="ioc-chart" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height:.0f}" '
            f'width="100%" role="img" aria-label="{title}"><title>{title}</title>{STYLE}{body}</svg>')


def render_svg(chart: dict) -> str:
    """The chart as self-contained SVG (its own styles, light and dark)."""
    if chart["kind"] == "line":
        return _line_svg(chart)
    return _bar_svg(chart)


def notes(chart: dict) -> list[str]:
    """Footnotes under a chart: what was left out."""
    out = []
    if chart.get("omitted_series"):
        out.append(f"{chart['omitted_series']} smaller series not shown.")
    if chart.get("truncated_bars"):
        out.append(f"First {MAX_BARS} rows shown; {chart['truncated_bars']} more not shown.")
    if chart.get("log_scale"):
        out.append("Log scale.")
    return out


# --- ready-made charts ------------------------------------------------------------------------

def prepared(ev: dict) -> list[dict]:
    """The menu of ready-made charts for one case, from data the evidence
    step already holds. Each builder returns None when its data is too thin
    to be worth a chart."""
    host = ev["identity"]["affected_asset"]
    options = []
    for builder in (_contact_chart, _load_chart, _usage_chart, _host_type_chart, _sites_chart, _peers_chart,
                    _destinations_chart, _apps_chart):
        try:
            chart = builder(ev, host)
        except Exception:  # noqa: BLE001 - a chart is never worth failing a case over
            chart = None
        if chart:
            chart["prepared"] = True
            options.append(chart)
    return options


def _match_markers(ev: dict) -> list[dict]:
    identity = ev["identity"]
    first, last = identity.get("evidence_first_seen"), identity.get("evidence_last_seen")
    return [{"start": first, "end": last or first, "label": "flagged contact"}] if first else []


def _series_frame(series: dict | None) -> pd.DataFrame:
    rows = (series or {}).get("rows") or []
    return pd.DataFrame(rows, columns=["time", "up_bytes", "down_bytes"]) if rows else pd.DataFrame()


BUCKET_WORDS = {"hour": "per hour", "day": "per day", "1min": "per minute", "5min": "per 5 minutes"}


def _contact_chart(ev: dict, host: str) -> dict | None:
    contact = ev.get("contact") or {}
    frame = _series_frame(contact.get("series"))
    if frame.empty:
        return None
    bucket = BUCKET_WORDS.get(contact["series"].get("bucket"), "")
    kind = "line" if len(frame) >= 3 else "bar"
    chart, error = build_chart({
        "id": "contact", "kind": kind, "x": "time", "y": ["up_bytes", "down_bytes"], "labels": ["upload", "download"],
        "unit": "bytes", "title": f"Traffic between the host and the flagged address, {bucket}".rstrip(", "),
        "sql": "", "source": contact.get("source", ""), "markers": _match_markers(ev),
        "caption": "Every active period of contact with the flagged address that the data still holds."}, frame, host)
    return None if error else chart


def _load_chart(ev: dict, host: str) -> dict | None:
    load = ev.get("load") or {}
    frame = _series_frame(load.get("series"))
    if len(frame) < 6:
        return None
    chart, error = build_chart({
        "id": "host_load", "kind": "line", "x": "time", "y": ["up_bytes", "down_bytes"],
        "labels": ["upload", "download"], "unit": "bytes",
        "title": f"The host's total traffic per hour, {load.get('period', '')}".rstrip(", "),
        "sql": "", "source": load.get("sources", ""), "markers": _match_markers(ev),
        "caption": "All of the host's traffic, to every destination, with the flagged contact marked: does it "
                   "stand out from the host's normal day?"}, frame, host)
    return None if error else chart


def _usage_chart(ev: dict, host: str) -> dict | None:
    """The host's traffic by kind of use (adult content, gaming, ...)."""
    other = ev.get("other_traffic") or {}
    categories = (other.get("activity_profile") or {}).get("categories") or []
    if not categories:
        return None
    frame = pd.DataFrame([{"use": c["category"], "traffic": c["bytes"]} for c in categories])
    chart, error = build_chart({
        "id": "usage", "kind": "bar", "x": "use", "y": ["traffic"], "unit": "bytes",
        "title": "What the host is used for: its traffic by kind of use", "sql": "",
        "source": f"subscriber_activity_1m, {(other.get('window') or {}).get('subscriber_activity_1m', '')}".rstrip(", "),
        "caption": "Sites grouped by kind of use from a local list; traffic to unlisted sites is not shown."},
        frame, host, highlight=[])
    return None if error else chart


def _host_type_chart(ev: dict, host: str) -> dict | None:
    """Where the host sits among measured hosts of its type, per feature."""
    kind = ev.get("host_type") or {}
    comparison = kind.get("comparison") or {}
    rows = [r for r in comparison.get("rows", []) if r.get("percentile") is not None]
    if not comparison.get("measured") or len(rows) < 3:
        return None
    frame = pd.DataFrame([{"feature": r["description"], "percentile": r["percentile"]} for r in rows])
    unusual = [r["description"] for r in rows if r["position"] != "typical"]
    chart, error = build_chart({
        "id": "host_vs_type", "kind": "bar", "x": "feature", "y": ["percentile"], "unit": "other",
        "title": f"Where the host sits among typical {kind.get('label', '')} hosts (percentile)",
        "sql": "", "source": comparison.get("source", ""),
        "caption": "50 is the median host of its type; below 5 or above 95 (highlighted) is unusual for the type."},
        frame, host, highlight=unusual)
    return None if error else chart


def _sites_chart(ev: dict, host: str) -> dict | None:
    entry = next((n for n in ev.get("names_on_ip") or [] if n.get("domains")), None)
    if not entry or len(entry["domains"]) < 2:
        return None
    frame = pd.DataFrame([{"site": d["root_domain"], "hosts": d["hosts"]} for d in entry["domains"]])
    own = (ev.get("names") or {}).get("registered_domains") or []
    chart, error = build_chart({
        "id": "sites_on_ip", "kind": "bar", "x": "site", "y": ["hosts"], "unit": "count",
        "title": f"Sites on {entry.get('server_ip', 'the flagged address')}, by campus hosts that used them",
        "sql": "", "source": f"subscriber_activity_1m, {entry.get('period', '')}".rstrip(", "),
        "caption": "Every site seen on the flagged address; the site this host used is highlighted."},
        frame, host, highlight=own)
    return None if error else chart


def _peers_chart(ev: dict, host: str) -> dict | None:
    entry = next((p for p in ev.get("peers") or [] if len(p.get("hosts") or []) >= 2), None)
    if not entry:
        return None
    hosts = sorted(entry["hosts"], key=lambda h: -(h["up_bytes"] + h["down_bytes"]))
    frame = pd.DataFrame([{"host": h["host"], "upload": h["up_bytes"], "download": h["down_bytes"]} for h in hosts])
    chart, error = build_chart({
        "id": "campus_hosts", "kind": "bar", "x": "host", "y": ["upload", "download"], "unit": "bytes",
        "title": f"Campus hosts with flows over 1 MB to {entry['server_ip']}, last {entry.get('lookback_days', '?')} days",
        "sql": "", "source": "long_flow_summary (flows over 1 MB only)",
        "caption": "This host against every other campus host with large flows to the flagged address."}, frame, host)
    return None if error else chart


def _destinations_chart(ev: dict, host: str) -> dict | None:
    other = ev.get("other_traffic") or {}
    rows = other.get("top_destinations_by_bytes") or []
    if len(rows) < 3:
        return None
    frame = pd.DataFrame([{"destination": f"{_destination_name(r)} {r.get('port', '')}/{r.get('protocol', '')}".strip(),
                           "upload": r["up_bytes"], "download": r["down_bytes"]} for r in rows])
    chart, error = build_chart({
        "id": "destinations", "kind": "bar", "x": "destination", "y": ["upload", "download"], "unit": "bytes",
        "title": "The host's busiest other destinations", "sql": "",
        "source": f"subscriber_activity_1m, {(other.get('window') or {}).get('subscriber_activity_1m', '')}".rstrip(", "),
        "caption": "What else the host spends its traffic on: what kind of machine it is."}, frame, host,
        highlight=[])
    return None if error else chart


def _destination_name(row: dict) -> str:
    root = str(row.get("root_domain") or "")
    if root and not root.startswith("("):  # "(no domain)" placeholder
        return root
    return str((row.get("server_ips") or ["unnamed"])[0])


def _apps_chart(ev: dict, host: str) -> dict | None:
    categories = (ev.get("host_apps") or {}).get("categories") or []
    if len(categories) < 2:
        return None
    frame = pd.DataFrame([{"category": c["category"], "minutes": c["minutes"]} for c in categories])
    chart, error = build_chart({
        "id": "apps", "kind": "bar", "x": "category", "y": ["minutes"], "unit": "count",
        "title": "The host's traffic by app category, in active minutes", "sql": "",
        "source": (ev.get("host_apps") or {}).get("sources", ""),
        "caption": "SuperNetFlow's app labels for everything the host did."}, frame, host, highlight=[])
    return None if error else chart


def describe(chart: dict) -> str:
    """One line for the case file: what the chart shows and its key values,
    formatted as the chart shows them."""
    parts = []
    for s in chart["series"]:
        points = s["points"]
        if not points:
            continue
        unit = chart["unit"]
        if chart["x_type"] == "category":
            top = ", ".join(f"{x} {fmt_value(y, unit)}" for x, y in points[:6])
            parts.append(f"{s['name']}: {top}" if len(chart["series"]) > 1 else top)
            continue
        peak = max(points, key=lambda p: p[1])
        text = f"{s['name']} peak {fmt_value(peak[1], unit)} at {str(peak[0])[:16].replace('T', ' ')} UTC"
        if unit in ("bytes", "count"):
            text += f", total {fmt_value(sum(p[1] for p in points), unit)}"
        parts.append(text)
    when = ""
    if chart["x_type"] == "time":
        xs = [p[0] for s in chart["series"] for p in s["points"]]
        when = f" from {min(xs)[:16].replace('T', ' ')} to {max(xs)[:16].replace('T', ' ')} UTC;"
    marked = " The flagged contact is marked." if chart.get("markers") else ""
    # The marker comes last: a line that starts with it was pasted whole into reports.
    return (f"{chart['id']}: {chart['title']} ({chart['kind']}):{when} {'; '.join(parts)}.{marked} "
            f"Place as [[chart {chart['id']}]].")

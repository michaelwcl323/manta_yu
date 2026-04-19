"""Y-axis helpers for latency plots: log scale with optional compression below a cutoff."""

from __future__ import annotations

import numpy as np
from matplotlib.axes import Axes
from matplotlib.ticker import MaxNLocator, ScalarFormatter


def apply_log_scale_latency(
    ax: Axes,
    *,
    subunity_compression: float = 1.0,
) -> None:
    """
    Log-like scale for positive latency (seconds).

    ``subunity_compression`` scales ``log10(y)`` when ``y < 1`` (i.e. when
    ``log10(y) < 0``). ``1.0`` is standard log (equal height per decade).
    Values in ``(0, 1)`` vertically compress the region below 1 s so that
    ``y >= 1`` uses a larger share of the axis.
    """
    c = float(subunity_compression)
    if c <= 0 or c > 1:
        raise ValueError("subunity_compression must be in (0, 1]")
    if abs(c - 1.0) < 1e-15:
        ax.set_yscale("log")
        return

    alpha = c

    def forward(y):
        y = np.asarray(y, dtype=float)
        y = np.maximum(y, 1e-300)
        L = np.log10(y)
        return np.where(L >= 0, L, alpha * L)

    def inverse(z):
        z = np.asarray(z, dtype=float)
        L = np.where(z >= 0, z, z / alpha)
        return np.power(10.0, L)

    ax.set_yscale("function", functions=(forward, inverse))


def apply_log_scale_latency_below_cut(
    ax: Axes,
    *,
    cut_s: float = 2.0,
    below_scale: float = 0.35,
) -> None:
    """
    Piecewise scale in ``log10(y)``: compress ``(0, cut_s]``, standard log above ``cut_s``.

    With ``below_scale < 1``, latencies in ``(0, cut_s]`` use less vertical space;
    ``y > cut_s`` keeps full log spacing so the tail is visually emphasized.
    ``below_scale == 1`` is identical to ``ax.set_yscale('log')``.
    """
    cut_s = float(cut_s)
    b = float(below_scale)
    if cut_s <= 0:
        raise ValueError("cut_s must be > 0")
    if b <= 0 or b > 1:
        raise ValueError("below_scale must be in (0, 1]")
    if abs(b - 1.0) < 1e-15:
        ax.set_yscale("log")
        return

    t_cut = np.log10(cut_s)

    def forward(y):
        y = np.asarray(y, dtype=float)
        y = np.maximum(y, 1e-300)
        t = np.log10(y)
        return np.where(t <= t_cut, t_cut + b * (t - t_cut), t)

    def inverse(z):
        z = np.asarray(z, dtype=float)
        t = np.where(z <= t_cut, t_cut + (z - t_cut) / b, z)
        return np.power(10.0, t)

    ax.set_yscale("function", functions=(forward, inverse))


def apply_linear_latency_axis(ax: Axes) -> None:
    """
    Ordinary linear y-axis: equal spacing in seconds (not log). Call after ``set_ylim``
    so major ticks are evenly distributed across the visible range.
    """
    ax.set_yscale("linear")
    ax.yaxis.set_major_locator(MaxNLocator(nbins=10, min_n_ticks=4))
    ax.yaxis.set_major_formatter(ScalarFormatter())


def latency_yaxis_label(
    base: str,
    *,
    y_log_scale: bool,
    below_cut_scale: float = 1.0,
    cut_s: float = 2.0,
) -> str:
    if not y_log_scale:
        return base
    if below_cut_scale < 0.999:
        return f"{base}, log (0–{cut_s:g} s compressed)"
    return f"{base}, log scale"

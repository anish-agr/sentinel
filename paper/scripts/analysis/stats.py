"""Interval and test helpers shared by every analysis in this directory."""

import math


def wilson(k, n, z=1.96):
    """95% Wilson score interval for k successes in n trials."""
    if not n:
        return (0.0, 0.0)
    p = k / float(n)
    d = 1 + z * z / n
    centre = (p + z * z / (2.0 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4.0 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def rule_of_three(n):
    """Upper 95% bound on a rate after n trials with zero events."""
    return 1.0 - 0.05 ** (1.0 / n) if n else 1.0


def fmt(k, n, width=None):
    """`39.9% [35.3, 44.6] (169/424)` — the form every table in the paper uses."""
    if not n:
        return "n/a (0/0)"
    lo, hi = wilson(k, n)
    s = "%.1f%% [%.1f, %.1f] (%d/%d)" % (
        100.0 * k / n, 100.0 * lo, 100.0 * hi, k, n)
    return s.ljust(width) if width else s


def newcombe(k1, n1, k2, n2, z=1.96):
    """95% interval for the difference of two proportions, p1 - p2."""
    l1, u1 = wilson(k1, n1, z)
    l2, u2 = wilson(k2, n2, z)
    p1 = k1 / float(n1) if n1 else 0.0
    p2 = k2 / float(n2) if n2 else 0.0
    lo = (p1 - p2) - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2)
    hi = (p1 - p2) + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)
    return (max(-1.0, lo), min(1.0, hi))


# z for the 99% intervals reported alongside the 95%.
Z95 = 1.959964
Z99 = 2.575829


def zero_bound(n, k_tests=1, alpha=0.05):
    """Upper bound on a rate after n trials with zero events, corrected for"""
    if not n:
        return 1.0
    return 1.0 - (alpha / float(k_tests)) ** (1.0 / n)


def cluster_ci(cluster_counts, z=Z95):
    """Proportion with a cluster-robust interval, plus the design effect."""
    clusters = [(x, m) for x, m in cluster_counts if m > 0]
    K = len(clusters)
    M = sum(m for _x, m in clusters)
    X = sum(x for x, _m in clusters)
    if not M or K < 2:
        return (X / float(M) if M else 0.0, 0.0, 1.0, 1.0, K, M)
    p = X / float(M)
    # Sum of squared cluster residuals x_i - p*m_i, with the standard
    # K/(K-1) small-sample correction.
    s2 = sum((x - p * m) ** 2 for x, m in clusters)
    var = s2 * K / float(K - 1) / float(M) ** 2
    iid = p * (1 - p) / float(M)
    deff = var / iid if iid > 0 else 1.0
    half = z * math.sqrt(var)
    return (p, max(0.0, p - half), min(1.0, p + half), deff, K, M)


# t_{K-1} at 95%, for the small-cluster sensitivity described in `cluster_ci`.
# Tabulated rather than computed so this module keeps no new dependency; K-1
# beyond 30 is within 0.5% of the normal and falls back to it.
_T95 = {1: 12.7062, 2: 4.3027, 3: 3.1824, 4: 2.7764, 5: 2.5706, 6: 2.4469,
        7: 2.3646, 8: 2.3060, 9: 2.2622, 10: 2.2281, 11: 2.2010, 12: 2.1788,
        13: 2.1604, 14: 2.1448, 15: 2.1314, 16: 2.1199, 17: 2.1098,
        18: 2.1009, 19: 2.0930, 20: 2.0860, 21: 2.0796, 22: 2.0739,
        23: 2.0687, 24: 2.0639, 25: 2.0595, 26: 2.0555, 27: 2.0518,
        28: 2.0484, 29: 2.0452, 30: 2.0423}


def cluster_ci_t(cluster_counts):
    """`cluster_ci` referred to t_{K-1} instead of the normal. (p, lo, hi, t)."""
    p, lo, hi, _deff, K, _M = cluster_ci(cluster_counts)
    if K < 2:
        return p, lo, hi, Z95
    t = _T95.get(K - 1, Z95)
    half = (hi - lo) / 2.0 * (t / Z95)
    return p, max(0.0, p - half), min(1.0, p + half), t


def cluster_diff_paired(cluster_counts, z=Z95):
    """Cluster-robust interval for a WITHIN-cluster difference of proportions."""
    rows = [(x1, m1, x2, m2) for x1, m1, x2, m2 in cluster_counts
            if m1 > 0 or m2 > 0]
    K = len(rows)
    M1 = sum(r[1] for r in rows)
    M2 = sum(r[3] for r in rows)
    if not M1 or not M2 or K < 2:
        return (0.0, 0.0, 0.0, -1.0, 1.0, K)
    p1 = sum(r[0] for r in rows) / float(M1)
    p2 = sum(r[2] for r in rows) / float(M2)
    # Influence of cluster i on delta; covariance between the two rates within
    # a cluster is captured because both terms sit in the same residual.
    s2 = sum(((x1 - p1 * m1) / float(M1) - (x2 - p2 * m2) / float(M2)) ** 2
             for x1, m1, x2, m2 in rows)
    var = s2 * K / float(K - 1)
    half = z * math.sqrt(var)
    d = p1 - p2
    return (p1, p2, d, max(-1.0, d - half), min(1.0, d + half), K)


def tango(b, c, n, z=Z95, tol=1e-8):
    """Tango's score interval for a paired difference of proportions."""
    if not n:
        return (0.0, 0.0)

    def score(delta):
        # Constrained MLE of the no/yes cell probability under
        # H0: p1 - p2 = delta, from the profile-likelihood quadratic
        # 2n q^2 - [(b+c) - delta(2n - b + c)] q - c delta (1 - delta) = 0.
        a_ = 2.0 * n
        b_ = -b - c + (2.0 * n - b + c) * delta
        c_ = -c * delta * (1.0 - delta)
        disc = max(0.0, b_ * b_ - 4.0 * a_ * c_)
        q = (-b_ + math.sqrt(disc)) / (2.0 * a_)
        denom = n * (2.0 * q + delta * (1.0 - delta))
        num = b - c - n * delta
        if denom <= 0:
            # Limit by continuity: at b = c = 0 and delta = 0 the statistic
            # is 0/0 but approaches 0 from both sides.
            if num == 0:
                return 0.0
            return float("inf") if num > 0 else float("-inf")
        return num / math.sqrt(denom)

    def solve(target, lo_, hi_):
        # score() is decreasing in delta; bisect for score(delta) = target.
        f_lo = score(lo_) - target
        for _ in range(200):
            mid = (lo_ + hi_) / 2.0
            f_mid = score(mid) - target
            if abs(hi_ - lo_) < tol:
                break
            if (f_lo > 0) == (f_mid > 0):
                lo_, f_lo = mid, f_mid
            else:
                hi_ = mid
        return (lo_ + hi_) / 2.0

    return (solve(z, -1.0 + 1e-12, 1.0 - 1e-12),
            solve(-z, -1.0 + 1e-12, 1.0 - 1e-12))


def chi2_sf(x, df):
    """Survival function of the chi-square distribution."""
    if x <= 0:
        return 1.0
    a, xx = df / 2.0, x / 2.0
    gln = math.lgamma(a)
    if xx < a + 1.0:
        # Series for P(a, x); SF = 1 - P.
        term = total = 1.0 / a
        ap = a
        for _ in range(500):
            ap += 1.0
            term *= xx / ap
            total += term
            if abs(term) < abs(total) * 1e-14:
                break
        return max(0.0, 1.0 - total * math.exp(-xx + a * math.log(xx) - gln))
    # Continued fraction for Q(a, x) directly.
    tiny = 1e-300
    b_ = xx + 1.0 - a
    c_ = 1.0 / tiny
    d_ = 1.0 / b_
    h = d_
    for i in range(1, 500):
        an = -i * (i - a)
        b_ += 2.0
        d_ = an * d_ + b_
        d_ = tiny if abs(d_) < tiny else d_
        c_ = b_ + an / c_
        c_ = tiny if abs(c_) < tiny else c_
        d_ = 1.0 / d_
        delta = d_ * c_
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break
    return min(1.0, h * math.exp(-xx + a * math.log(xx) - gln))


def chi2_test(table):
    """Pearson chi-square on an r x c contingency table."""
    r = len(table)
    c = len(table[0])
    row = [sum(table[i]) for i in range(r)]
    col = [sum(table[i][j] for i in range(r)) for j in range(c)]
    N = sum(row)
    if not N:
        return (0.0, (r - 1) * (c - 1), 1.0)
    stat = 0.0
    for i in range(r):
        for j in range(c):
            e = row[i] * col[j] / float(N)
            if e > 0:
                stat += (table[i][j] - e) ** 2 / e
    df = (r - 1) * (c - 1)
    return (stat, df, chi2_sf(stat, df))


def mdd(n1, n2, p_bar, alpha=0.05, power=0.80):
    """Minimum detectable difference for a two-proportion comparison."""
    if not n1 or not n2:
        return 1.0
    if alpha in (0.05, 0.01):
        za = Z95 if alpha == 0.05 else Z99
        zb = {0.80: 0.841621, 0.90: 1.281552}.get(power, 0.841621)
        q = p_bar * (1.0 - p_bar)
        return (za + zb) * math.sqrt(q * (1.0 / n1 + 1.0 / n2))

    # Bisection on erfc, the same method `pilot_contrasts.z_for` already uses,
    # because there is no scipy on the collection machine.
    lo_z, hi_z = 0.0, 40.0
    for _ in range(200):
        mid = (lo_z + hi_z) / 2.0
        if math.erfc(mid / math.sqrt(2.0)) > alpha:
            lo_z = mid
        else:
            hi_z = mid
    za = (lo_z + hi_z) / 2.0
    zb = {0.80: 0.841621, 0.90: 1.281552}.get(power, 0.841621)
    q = p_bar * (1.0 - p_bar)
    return (za + zb) * math.sqrt(q * (1.0 / n1 + 1.0 / n2))


def gwet_ac1(pairs):
    """Gwet's AC1 chance-corrected agreement for two raters."""
    n = len(pairs)
    if not n:
        return 0.0, 0.0, 0
    labels = sorted({a for a, _ in pairs} | {b for _, b in pairs})
    po = sum(1 for a, b in pairs if a == b) / float(n)
    # pi_k: mean of the two raters' marginal shares for category k.
    import collections as _c
    ca = _c.Counter(a for a, _ in pairs)
    cb = _c.Counter(b for _, b in pairs)
    pe = sum(
        ((ca[l] + cb[l]) / (2.0 * n)) * (1.0 - (ca[l] + cb[l]) / (2.0 * n))
        for l in labels
    ) / max(1, len(labels) - 1)
    return ((po - pe) / (1.0 - pe) if pe < 1 else 1.0, po, n)


def manski(k_obs, n_uncensored, n_censored):
    """Sharp partial-identification bounds for a rate under informative"""
    n = n_uncensored + n_censored
    if not n:
        return (0.0, 1.0)
    return (k_obs / float(n), (k_obs + n_censored) / float(n))

"""
SAUDI WAR TRACKER
Tactical OSINT situational-awareness dashboard — Saudi Arabia / Yemen theater.

Classification : UNCLASSIFIED // OPEN SOURCE
Purpose        : Situational awareness only. Not an intelligence product.
Sourcing       : Verified wire services, major broadcasters and official
                 government statements ONLY. No unverified social media.

Run:
    pip install streamlit folium streamlit-folium
    streamlit run app.py
"""

import html
import json
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import folium
import streamlit as st
import streamlit.components.v1 as components
from streamlit_folium import st_folium

# ---------------------------------------------------------------------------
# PALETTE — intentionally restricted. Do not add colors.
# ---------------------------------------------------------------------------
# Switch THEME to change the whole display. Add your own by adding a key.
PALETTES = {
    "green": {
        "BG":        "#000000",   # true black field
        "PANEL":     "#040704",   # panel fill, barely lifted off the field
        "TEXT":      "#2bff66",   # bright green — primary text
        "TEXT_DIM":  "#17a843",   # dimmed green — labels, secondary
        "BORDER":    "#c8b400",   # yellow — borders, rules, reference markers
        "BORDER_LT": "#e6d24a",   # brighter yellow — emphasis, hover
        "ALERT":     "#ff2a2a",   # red — HIGH/CRITICAL incidents only
    },
    "amber": {
        "BG":        "#000000",
        "PANEL":     "#050705",
        "TEXT":      "#c5b358",
        "TEXT_DIM":  "#8a7d3d",
        "BORDER":    "#3d4f1c",
        "BORDER_LT": "#55692a",
        "ALERT":     "#cc2222",
    },
}
THEME = "green"

_P = PALETTES[THEME]
BG = _P["BG"]
PANEL = _P["PANEL"]
TEXT = _P["TEXT"]
TEXT_DIM = _P["TEXT_DIM"]
BORDER = _P["BORDER"]
BORDER_LT = _P["BORDER_LT"]
ALERT = _P["ALERT"]

# Severities that are rendered in red.
RED_SEVERITIES = ("HIGH", "CRITICAL")

# ---------------------------------------------------------------------------
# THREAT LEVEL
#
# Derived from logged activity near a point — never set by hand. The inputs are
# shown alongside the verdict so it can be checked rather than trusted.
#
#   score = sum over incidents within RADIUS and LOOKBACK of
#           severity weight x recency multiplier
#
# Add entries to THREAT_WATCH to track more locations.
# ---------------------------------------------------------------------------
THREAT_WATCH = [
    ("RIYADH", 24.7136, 46.6753),
]
THREAT_RADIUS_KM = 150
THREAT_LOOKBACK_H = 168          # 7 days
THREAT_RECENT_H = 72             # inside this, an event counts double
SEVERITY_WEIGHT = {"CRITICAL": 3.0, "HIGH": 2.0, "MODERATE": 1.0, "LOW": 0.5}
THREAT_THRESHOLDS = [("HIGH", 4.0), ("MEDIUM", 1.5)]      # else LOW

MONO = "Consolas, 'Courier New', Courier, monospace"

# Seconds between automatic page refreshes. Set to 0 to disable.
AUTO_REFRESH_SECONDS = 600

# Rolling windows, in hours.
#   INCIDENT_WINDOW_HOURS — how far back the incident feed and map reach.
#   WIRE_WINDOW_HOURS     — how far back raw wire headlines are pulled.
# The wire window is deliberately shorter: RSS feeds only carry recent items,
# so asking for 7 days of headlines returns whatever the outlet still lists.
INCIDENT_WINDOW_HOURS = 240          # 10 days — covers the whole
                                     # October airport campaign.
                                     # Set to 168 for a 7-day window.
WIRE_WINDOW_HOURS = 48

# Continuous scroll speed for the incident feed, pixels per second. 0 stops it.
FEED_SCROLL_PX_PER_SEC = 18

# Footer X watch. Prefer posts from the last 5 minutes. If the account is
# quiet in that window, the newest posts on hand are shown and labelled as such.
# This strip is unverified social intake. It is never plotted on the map.
X_HANDLE = "Osint613"
X_LOOKBACK_MIN = 5
X_SCROLL_PX_PER_SEC = 18
X_TICKER_H = 168
# FxTwitter publishes a real RSS feed for a public account. No API key.
# Nitter mirrors are left as fallbacks; most of them are dead or bot-walled.
X_RSS_URLS = [
    "https://fxtwitter.com/Osint613/feed.xml?count=20",
    "https://fxtwitter.com/Osint613/feed.xml",
]
# Used only when every live source fails and no fresher cache exists.
X_SEED = [
    {"text": "US Treasury Secretary Bessent: The noose is tightening around Iran's economy, and not even Iran's so-called allies can save it.",
     "when": "20261015T2008Z", "id": "2110825185339125920"},
    {"text": "The U.S. Treasury has sanctioned an Iraqi bank used by Iran to access the international financial system and to fund its proxy militias.",
     "when": "20261015T2007Z", "id": "2110824852529525039"},
    {"text": "Steps are being taken to prevent a surprise attack, an Israeli defense official told Kan News, as Israel watches recent Iranian missile and UAV tests.",
     "when": "20261015T2003Z", "id": "2110823921541169610"},
    {"text": "Black Sea security will get a dedicated North Atlantic Council discussion next week. Two chemical tankers were struck by drones off Romania.",
     "when": "20261015T2001Z", "id": "2110823302507765955"},
    {"text": "Saudi Civil Defence: the danger in Jazan has passed.",
     "when": "20261015T1956Z", "id": "2110822175561470272"},
    {"text": "A car-ramming was reported near the settlement of Ateret. At least one person was injured. The driver fled.",
     "when": "20261015T1954Z", "id": "2110821546201841871"},
    {"text": "Five people were killed and 16 wounded in a Houthi attack on the presidential palace compound in Aden, according to Yemen's health minister.",
     "when": "20261015T1945Z", "id": "2110819429600649591"},
    {"text": "Report: the first call between a Syrian president and an Israeli prime minister since 1948 was an ultimatum over Sweida.",
     "when": "20261015T1943Z", "id": "2110818791936401519"},
    {"text": "NOW: Initial reports of a Houthi attack on Jazan, Saudi Arabia. Saudi Civil Defense published an air raid alert.",
     "when": "20261015T1940Z", "id": "2110818092720836919"},
]

# Clocks shown in the chronometer bar: (label, IANA zone, suffix)
CLOCKS = [
    ("ZULU", "UTC", "Z"),
    ("RIYADH", "Asia/Riyadh", "AST"),
    ("ADEN", "Asia/Aden", "AST"),
    ("WASHINGTON", "America/New_York", "EST/EDT"),
]

THEATER = "SAUDI ARABIA / YEMEN"
CLASSIFICATION = "UNCLASSIFIED // OSINT"
MAP_CENTER = (19.0, 45.0)
MAP_ZOOM = 6

# ---------------------------------------------------------------------------
# BASEMAP
# Change BASEMAP below if a tile source goes down or you want a different look.
# Only key-free sources are listed. CartoDB dark_matter is deliberately NOT
# used: as of folium 0.20 it requires a Carto API key and renders blank without
# one.
# ---------------------------------------------------------------------------
BASEMAPS = {
    "esri_dark": {
        "label": "ESRI DARK GRAY CANVAS",
        "base": "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/"
                "World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}",
        "reference": "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/"
                     "World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}",
        "attr": "Esri",
        "max_zoom": 16,
    },
    "esri_imagery": {
        "label": "ESRI WORLD IMAGERY",
        "base": "https://server.arcgisonline.com/ArcGIS/rest/services/"
                "World_Imagery/MapServer/tile/{z}/{y}/{x}",
        "reference": None,
        "attr": "Esri",
        "max_zoom": 18,
    },
    "osm": {
        "label": "OPENSTREETMAP (FALLBACK — LIGHT)",
        "base": "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
        "reference": None,
        "attr": "OpenStreetMap contributors",
        "max_zoom": 19,
    },
}
BASEMAP = "esri_dark"


def dtg_now() -> str:
    """Current Zulu Date-Time Group, DDG format YYYYMMDDTHHMMZ."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%MZ")


def parse_dtg(dtg: str) -> datetime:
    """Parse a Zulu DTG (YYYYMMDDTHHMMZ) into an aware UTC datetime."""
    return datetime.strptime(dtg, "%Y%m%dT%H%MZ").replace(tzinfo=timezone.utc)


def hours_since(dtg: str) -> float:
    return (datetime.now(timezone.utc) - parse_dtg(dtg)).total_seconds() / 3600.0


def age_label(dtg: str) -> str:
    """Elapsed time since the DTG, as H+nn or D+n."""
    h = hours_since(dtg)
    if h < 0:
        return "H-00"
    if h < 24:
        return f"H+{int(h):02d}"
    return f"D+{int(h // 24)} H+{int(h % 24):02d}"


THEATER_TZ = timezone(timedelta(hours=3))     # AST — Riyadh and Aden alike


def local_stamp(dtg: str) -> str:
    """Theater local time, e.g. '15 OCT 26  17:30 AST'."""
    d = parse_dtg(dtg).astimezone(THEATER_TZ)
    return d.strftime("%d %b %y  %H:%M AST").upper()


def day_bucket(dtg: str) -> str:
    return dtg[:8]


def day_label(dtg: str) -> str:
    return parse_dtg(dtg).strftime("%d %b %Y").upper()


def dtg_display(inc) -> str:
    """DTG, marked when only the date is established."""
    if inc.get("dtg_precision") == "DATE":
        return f"{inc['dtg'][:8]} — TIME NOT ESTABLISHED"
    return inc["dtg"]


def local_display(inc) -> str:
    if inc.get("dtg_precision") == "DATE":
        return parse_dtg(inc["dtg"]).strftime("%d %b %y").upper() + "  DATE ONLY"
    return local_stamp(inc["dtg"])


def km_between(lat1, lon1, lat2, lon2) -> float:
    """Great-circle distance in km."""
    import math
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = (math.sin(dp / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2)
    return 2 * r * math.asin(math.sqrt(a))


def threat_level(incidents, lat, lon):
    """Assess threat near a point from logged activity.

    Returns the level plus every input behind it, so the figure can be
    audited instead of taken on faith.
    """
    score, count, nearest_age = 0.0, 0, None

    for inc in incidents:
        age = hours_since(inc["dtg"])
        if age > THREAT_LOOKBACK_H or age < 0:
            continue
        if km_between(lat, lon, inc["lat"], inc["lon"]) > THREAT_RADIUS_KM:
            continue
        count += 1
        if nearest_age is None or age < nearest_age:
            nearest_age = age
        weight = SEVERITY_WEIGHT.get(inc.get("severity", "LOW"), 0.5)
        score += weight * (2.0 if age <= THREAT_RECENT_H else 1.0)

    level = "LOW"
    for name, floor in THREAT_THRESHOLDS:
        if score >= floor:
            level = name
            break

    return {
        "level": level,
        "score": round(score, 1),
        "count": count,
        "last_age": None if nearest_age is None else int(nearest_age),
    }


def threat_color(level) -> str:
    return {"HIGH": ALERT, "MEDIUM": BORDER_LT}.get(level, TEXT)


def is_red(inc) -> bool:
    """Red is reserved for HIGH and CRITICAL severity."""
    return inc.get("severity") in RED_SEVERITIES


def sev_color(inc) -> str:
    return ALERT if is_red(inc) else BORDER_LT


def cas_line(inc) -> str:
    """Per-incident KIA / injured figures, or an explicit no-figures marker."""
    def one(v):
        if not v:
            return "\u2014"
        lo, hi = v.get("low", 0), v.get("high", v.get("low", 0))
        return str(lo) if lo == hi else f"{lo}\u2013{hi}"
    if not inc.get("kia") and not inc.get("wia"):
        return "NOT REPORTED"
    return f"{one(inc.get('kia'))} / {one(inc.get('wia'))}"


def casualty_totals(incidents):
    """Aggregate KIA/WIA across incidents, preserving disputed ranges.

    Returns low/high totals, how many incidents carry no figures at all, and
    whether any figure is disputed. A single number is never invented from a
    range, and incidents with nothing reported are counted separately rather
    than silently treated as zero.
    """
    kia_lo = kia_hi = wia_lo = wia_hi = 0
    unreported = 0
    disputed = False

    for inc in incidents:
        k, w = inc.get("kia"), inc.get("wia")
        if not k and not w:
            unreported += 1
            continue
        for field, lo_hi in (("kia", k), ("wia", w)):
            if not lo_hi:
                continue
            lo = lo_hi.get("low", 0)
            hi = lo_hi.get("high", lo)
            if hi != lo:
                disputed = True
            if field == "kia":
                kia_lo += lo
                kia_hi += hi
            else:
                wia_lo += lo
                wia_hi += hi

    def span(lo, hi):
        return str(lo) if lo == hi else f"{lo}\u2013{hi}"

    return {
        "kia": span(kia_lo, kia_hi),
        "wia": span(wia_lo, wia_hi),
        "kia_hi": kia_hi,
        "unreported": unreported,
        "disputed": disputed,
    }


def in_window(inc) -> bool:
    return hours_since(inc["dtg"]) <= INCIDENT_WINDOW_HOURS


# ---------------------------------------------------------------------------
# REFERENCE POINTS — fixed infrastructure. Olive. Not events.
# ---------------------------------------------------------------------------
REFERENCE_POINTS = [
    # (full label, on-map short label, ref, lat, lon, kind)
    ("RIYADH / KING KHALID INTL", "RIYADH", "OERK", 24.9576, 46.6988, "APT"),
    ("JEDDAH / KING ABDULAZIZ INTL", "JEDDAH", "OEJN", 21.6796, 39.1565, "APT"),
    ("ABHA INTL", "ABHA", "OEAB", 18.2404, 42.6566, "APT"),
    ("JIZAN / KING ABDULLAH BIN ABDULAZIZ", "JIZAN", "OEGN", 16.9011, 42.5858, "APT"),
    ("MEDINA / PRINCE MOHAMMAD BIN ABDULAZIZ", "MEDINA", "OEMA", 24.5534, 39.7051, "APT"),
    ("SANAA INTL", "SANAA", "OYSN", 15.4763, 44.2197, "APT"),
    ("ADEN INTL", "ADEN", "OYAA", 12.8295, 45.0288, "APT"),
    ("KHAMIS MUSHAIT", "KHAMIS MUSHAIT", "CITY", 18.3000, 42.7333, "CITY"),
    ("TAIZ", "TAIZ", "CITY", 13.5789, 44.0178, "CITY"),
    ("MARIB", "MARIB", "CITY", 15.4700, 45.3200, "CITY"),
]

COUNTRY_LABELS = [
    ("SAUDI ARABIA", 23.60, 44.20),
    ("YEMEN", 15.40, 47.60),
]

# ---------------------------------------------------------------------------
# INCIDENTS
#
# Add new entries to this list. Required keys are documented inline. Every
# entry MUST carry at least one verified source with a working URL — if a
# claim cannot be sourced to a wire service, major broadcaster or an official
# statement, it does not go in the file.
#
# severity : LOW | MODERATE | HIGH | CRITICAL
# status   : ACTIVE | MONITORING | CLOSED
# ---------------------------------------------------------------------------
INCIDENTS = [
    {
        "id": "YEM-20261015-001",
        "dtg": "20261015T1430Z",   # time of first wire report, not impact
        "name": "AL-MAASHIQ PALACE COMPLEX",
        "locality": "ADEN, YEMEN",
        "lat": 12.7644,
        "lon": 45.0542,
        "type": "MISSILE STRIKE",
        "severity": "HIGH",
        "status": "ACTIVE",
        "attribution": (
            "Claimed by Ansar Allah (Houthi). Military spokesman Yahya Saree "
            "stated the target was a Saudi military operations headquarters "
            "sited within the compound, together with associated weapons "
            "storage. The claim is not independently verified."
        ),
        "summary": (
            "Houthi forces struck the Al-Maashiq presidential palace complex in "
            "Aden — the seat of Yemen's internationally recognised, Saudi-backed "
            "government. Yemeni Information Minister Moammar al-Eryani reported "
            "five missiles. A later Council of Ministers statement said the "
            "attack involved both missiles and drones. The Yemeni government "
            "stated that Prime Minister Shaya al-Zindani and cabinet members "
            "present in the complex were unharmed, and that government "
            "operations in Aden continue. Witnesses reported detonations and "
            "smoke rising from the vicinity of the palace. This is assessed as "
            "the first strike on Al-Maashiq in the current phase of the conflict."
        ),
        "casualties": (
            "Two members of the Prime Minister's security detail killed "
            "(Yemeni government / Reuters)."
        ),
        # Structured figures feed the tally. Use a low/high range whenever
        # outlets disagree — never collapse a dispute to a single number.
        # Omit the key entirely when nothing has been reported.
        "kia": {"low": 2, "high": 4},
        "wia": {"low": 0, "high": 10},
        "conflicting_reports": [
            "Yemeni government and Reuters: 2 security personnel killed.",
            "Yemeni government military sources via AFP: at least 4 killed, "
            "10 wounded.",
            "Casualty figures remain unreconciled. Treat the lower figure as "
            "the officially stated number and the higher as unconfirmed.",
        ],
        "confidence": "CONFIRMED — multiple independent outlets + official statement",
        "sources": [
            {
                "outlet": "REUTERS",
                "title": "Houthis fire missiles at presidential palace in Yemen's Aden, officials say",
                "url": "https://www.yahoo.com/news/world/articles/houthis-fire-missiles-presidential-palace-144346754.html",
                "note": "Reuters wire copy (syndicated)",
            },
            {
                "outlet": "REUTERS",
                "title": "Yemen's Houthis hit palace in Aden; coalition details attacks on Saudi infrastructure",
                "url": "https://www.al-monitor.com/originals/2026/10/yemens-houthis-hit-palace-aden-coalition-details-attacks-saudi-infrastructure",
                "note": "Reuters wire copy (syndicated)",
            },
            {
                "outlet": "AL JAZEERA",
                "title": "Houthis target Yemen's presidential palace in Aden with missiles",
                "url": "https://www.yahoo.com/news/world/articles/houthis-target-yemen-presidential-palace-165042185.html",
                "note": "Al Jazeera copy (syndicated)",
            },
            {
                "outlet": "CNN",
                "title": "Iran-aligned Houthis strike Yemeni presidential palace in escalating campaign against Saudi Arabia",
                "url": "https://www.cnn.com/2026/10/15/middleeast/yemeni-houthi-strikes-on-aden-presidential-palace-kill-two-latam-intl",
                "note": "First-party",
            },
            {
                "outlet": "THE NATIONAL",
                "title": "Yemen's Houthi rebels hit Presidential Palace in Aden",
                "url": "https://www.thenationalnews.com/news/mena/2026/10/15/yemens-houthi-rebels-hit-presidential-palace-in-aden/",
                "note": "First-party",
            },
            {
                "outlet": "YEMENI MINISTRY OF INFORMATION",
                "title": "Statement of Information Minister Moammar al-Eryani; Council of Ministers statement",
                "url": "",
                "note": "Official statement, carried by the outlets above. No direct permalink held.",
            },
        ],
    },
    # ---- October 2026 campaign against Saudi airports ----------------------
    # Dates are firm; times of impact are not published in the sources held,
    # so these carry "dtg_precision": "DATE" and a 0000Z placeholder. The card
    # says so rather than implying a precision that does not exist.
    {
        "id": "KSA-20261006-001",
        "dtg": "20261006T0000Z",
        "dtg_precision": "DATE",
        "name": "KING KHALID INTL AIRPORT",
        "locality": "RIYADH, SAUDI ARABIA",
        "lat": 24.9576, "lon": 46.6988,
        "type": "MISSILE / DRONE STRIKE",
        "severity": "HIGH",
        "status": "CLOSED",
        "attribution": "Attributed to Ansar Allah (Houthi).",
        "summary": (
            "Combined missile and drone attack on King Khalid International "
            "Airport, opening the October campaign against Saudi civil "
            "aviation. One Sudanese national killed, eight civilians wounded."
        ),
        "casualties": "1 killed (Sudanese national), 8 civilians wounded.",
        "kia": {"low": 1, "high": 1},
        "wia": {"low": 8, "high": 8},
        "confidence": "CONFIRMED — Saudi authorities via major broadcaster",
        "sources": [
            {"outlet": "AL JAZEERA",
             "title": "Three killed, 36 injured in Houthi attacks on Saudi airports, Riyadh says",
             "url": "https://www.aljazeera.com/news/2026/10/7/saudi-arabia-says-three-foreign-nationals-killed-in-attacks-on-airports",
             "note": "First-party — covers 6–7 Oct Riyadh and Abha together"},
            {"outlet": "WIKIPEDIA",
             "title": "October 2026 attacks on Saudi Arabia airports",
             "url": "https://en.wikipedia.org/wiki/October_2026_attacks_on_Saudi_Arabia_airports",
             "note": "Tertiary — chronology and cross-reference only"},
        ],
    },
    {
        "id": "KSA-20261006-002",
        "dtg": "20261006T0000Z",
        "dtg_precision": "DATE",
        "name": "ABHA INTL AIRPORT",
        "locality": "ABHA, SAUDI ARABIA",
        "lat": 18.2404, "lon": 42.6566,
        "type": "MISSILE / DRONE STRIKE",
        "severity": "HIGH",
        "status": "CLOSED",
        "attribution": "Attributed to Ansar Allah (Houthi).",
        "summary": (
            "Combined missile and drone attack on Abha International Airport, "
            "concurrent with the strike on Riyadh. Two women, nationals of "
            "Algeria and Morocco, were killed and 28 people wounded."
        ),
        "casualties": "2 killed (Algerian and Moroccan nationals), 28 wounded.",
        "kia": {"low": 2, "high": 2},
        "wia": {"low": 28, "high": 28},
        "confidence": "CONFIRMED — Saudi authorities via major broadcaster",
        "sources": [
            {"outlet": "AL JAZEERA",
             "title": "Three killed, 36 injured in Houthi attacks on Saudi airports, Riyadh says",
             "url": "https://www.aljazeera.com/news/2026/10/7/saudi-arabia-says-three-foreign-nationals-killed-in-attacks-on-airports",
             "note": "First-party"},
            {"outlet": "WIKIPEDIA",
             "title": "October 2026 attacks on Saudi Arabia airports",
             "url": "https://en.wikipedia.org/wiki/October_2026_attacks_on_Saudi_Arabia_airports",
             "note": "Tertiary — chronology only"},
        ],
    },
    {
        "id": "KSA-20261008-001",
        "dtg": "20261008T0000Z",
        "dtg_precision": "DATE",
        "name": "KING KHALID INTL — FACILITIES AND AIRCRAFT",
        "locality": "RIYADH, SAUDI ARABIA",
        "lat": 24.9576, "lon": 46.6988,
        "type": "BALLISTIC MISSILE STRIKE",
        "severity": "CRITICAL",
        "status": "CLOSED",
        "attribution": (
            "Houthi forces claimed firing a ballistic missile at the airport."
        ),
        "summary": (
            "Two strikes on King Khalid International: one on airport "
            "facilities, one that destroyed a parked Saudia Airbus A321-200. "
            "Three Saudi citizens were killed, among them a Saudia pilot, per "
            "the General Authority of Civil Aviation. The airport was "
            "subsequently reopened."
        ),
        "casualties": "3 Saudi citizens killed, including a Saudia pilot. 10+ wounded.",
        "kia": {"low": 3, "high": 3},
        "wia": {"low": 10, "high": 10},
        "conflicting_reports": [
            "Injured count is a floor, not a total: GACA described 'dozens' "
            "wounded of various nationalities while summary tallies give 10+.",
            "The tally therefore understates injuries for this event.",
        ],
        "confidence": "CONFIRMED — GACA statement via major broadcaster",
        "sources": [
            {"outlet": "AL JAZEERA",
             "title": "Houthi attack on Riyadh airport killed three Saudi nationals",
             "url": "https://www.aljazeera.com/news/2026/10/9/saudi-arabia-reopens-riyadh-airport-after-houthi-attack-kills-three",
             "note": "First-party"},
            {"outlet": "WIKIPEDIA",
             "title": "October 2026 attacks on Saudi Arabia airports",
             "url": "https://en.wikipedia.org/wiki/October_2026_attacks_on_Saudi_Arabia_airports",
             "note": "Tertiary — chronology only"},
        ],
    },
    {
        "id": "KSA-20261010-001",
        "dtg": "20261010T0000Z",
        "dtg_precision": "DATE",
        "name": "KING KHALID INTL — TERMINALS 3 AND 4",
        "locality": "RIYADH, SAUDI ARABIA",
        "lat": 24.9576, "lon": 46.6988,
        "type": "BALLISTIC MISSILE STRIKE",
        "severity": "CRITICAL",
        "status": "CLOSED",
        "attribution": (
            "Ansar Allah (Houthi). Official Mohammed al-Bukhaiti claimed "
            "responsibility for the airport campaign."
        ),
        "summary": (
            "Ballistic missile strike on the King Khalid International "
            "terminal complex, hitting Terminals 3 and 4. The deadliest single "
            "event of the campaign and the one that moved Saudi civil aviation "
            "into a new threat category — mass civilian casualties inside a "
            "working international terminal."
        ),
        "casualties": "12 killed initially, raised to 13 after an Indian national died of wounds. 308 injured.",
        "kia": {"low": 12, "high": 13},
        "wia": {"low": 308, "high": 308},
        "conflicting_reports": [
            "Initial reporting: 12 killed. Revised to 13 the following day "
            "when an injured Indian man died.",
            "Both figures are shown as a range; neither has been retracted.",
        ],
        "confidence": "CONFIRMED — Saudi authorities, multiple independent outlets",
        "sources": [
            {"outlet": "AL JAZEERA",
             "title": "Saudi Arabia says 12 killed, 300 wounded in Houthi attack on Riyadh airport",
             "url": "https://www.aljazeera.com/news/2026/10/10/attack-on-airport-in-saudi-capital-riyadh-leaves-several-injured",
             "note": "First-party"},
            {"outlet": "WASHINGTON POST",
             "title": "12 killed in Saudi Arabia airport attack, underscoring peril in Houthi strikes",
             "url": "https://www.washingtonpost.com/world/2026/10/10/saudi-arabia-faces-new-level-peril-houthi-attacks-amid-wider-iran-war/",
             "note": "First-party"},
            {"outlet": "WIKIPEDIA",
             "title": "October 2026 attacks on Saudi Arabia airports",
             "url": "https://en.wikipedia.org/wiki/October_2026_attacks_on_Saudi_Arabia_airports",
             "note": "Tertiary — revised death toll"},
        ],
    },
    {
        "id": "KSA-20261011-001",
        "dtg": "20261011T0000Z",
        "dtg_precision": "DATE",
        "name": "KING KHALID INTL — TERMINAL 4",
        "locality": "RIYADH, SAUDI ARABIA",
        "lat": 24.9576, "lon": 46.6988,
        "type": "MISSILE STRIKE",
        "severity": "HIGH",
        "status": "CLOSED",
        "attribution": "Not established in sources held. Weapon type not stated.",
        "summary": (
            "Further strike on Terminal 4 of King Khalid International, one "
            "day after the mass-casualty attack on the terminal complex. "
            "Neither the weapon used nor a claim of responsibility is stated "
            "in the sources held."
        ),
        "casualties": "1 killed, 11 injured.",
        "kia": {"low": 1, "high": 1},
        "wia": {"low": 11, "high": 11},
        "conflicting_reports": [
            "Detailed reporting gives 1 killed and 11 injured; summary tallies "
            "say only 'several injured' for this date.",
        ],
        "confidence": "REPORTED — single broadcaster, attribution not established",
        "sources": [
            {"outlet": "AL JAZEERA",
             "title": "Saudi Arabia says 1 dead, 11 injured in latest attack on Riyadh airport",
             "url": "https://www.aljazeera.com/news/2026/10/12/saudi-arabia-says-1-dead-11-injured-in-latest-attack-on-riyadh-airport",
             "note": "First-party"},
            {"outlet": "WIKIPEDIA",
             "title": "October 2026 attacks on Saudi Arabia airports",
             "url": "https://en.wikipedia.org/wiki/October_2026_attacks_on_Saudi_Arabia_airports",
             "note": "Tertiary — chronology only"},
        ],
    },
    {
        "id": "KSA-20261011-002",
        "dtg": "20261011T0000Z",
        "dtg_precision": "DATE",
        "name": "KING FAHD INTL AIRPORT",
        "locality": "DAMMAM, SAUDI ARABIA",
        "lat": 26.4712, "lon": 49.7979,
        "type": "MISSILE / DRONE STRIKE",
        "severity": "MODERATE",
        "status": "CLOSED",
        "attribution": (
            "Houthi claims of strikes on Saudi aviation and oil facilities "
            "cover this date. Not separately confirmed."
        ),
        "summary": (
            "King Fahd International Airport at Dammam listed among targets in "
            "the campaign, extending it to the Eastern Province. No casualty "
            "figures are given in the sources held."
        ),
        "casualties": "No figures reported in sources held.",
        "confidence": "REPORTED — listed in chronology, details thin",
        "sources": [
            {"outlet": "WIKIPEDIA",
             "title": "October 2026 attacks on Saudi Arabia airports",
             "url": "https://en.wikipedia.org/wiki/October_2026_attacks_on_Saudi_Arabia_airports",
             "note": "Tertiary — only source held for this event; treat as unconfirmed"},
        ],
    },
]



# ---------------------------------------------------------------------------
# WIRE INTAKE
#
# Pulls headlines from public RSS/Atom feeds, filters them by keyword, and
# parks matches in a review tray. NOTHING here reaches the map automatically.
# An item becomes a plotted incident only when you promote it by hand, which
# is the whole point: a human stays between the wire and the display.
#
# No social media feeds. Add outlets to FEEDS below; set "enabled": False to
# park one without deleting it.
# ---------------------------------------------------------------------------
FEEDS = [
    {"name": "BBC MIDDLE EAST", "tier": "BROADCASTER", "enabled": True,
     "url": "https://feeds.bbci.co.uk/news/world/middle_east/rss.xml"},
    {"name": "AL JAZEERA", "tier": "BROADCASTER", "enabled": True,
     "url": "https://www.aljazeera.com/xml/rss/all.xml"},
    # The National's /rss path returns 404. Routed through the news index
    # instead so its Gulf coverage still surfaces.
    {"name": "THE NATIONAL (VIA NEWS INDEX)", "tier": "REGIONAL", "enabled": True,
     "url": "https://news.google.com/rss/search?q=(yemen+OR+houthi+OR+saudi)"
            "+site:thenationalnews.com&hl=en-US&gl=US&ceid=US:en"},
    # Reuters discontinued its public RSS endpoints. This Google News query is
    # scoped to reuters.com so Reuters copy still surfaces; it is an index, so
    # always open the underlying article before promoting.
    {"name": "REUTERS (VIA NEWS INDEX)", "tier": "WIRE", "enabled": True,
     "url": "https://news.google.com/rss/search?q=(yemen+OR+houthi+OR+saudi)"
            "+site:reuters.com&hl=en-US&gl=US&ceid=US:en"},
]

# An item must match at least one of these to enter the tray.
KEYWORDS = [
    "yemen", "houthi", "ansar allah", "saudi", "aden", "sanaa", "sana'a",
    "taiz", "marib", "hodeidah", "jizan", "abha", "khamis mushait", "riyadh",
    "jeddah", "red sea", "bab al-mandab", "coalition",
]

# Gazetteer for coarse geolocation. An item is promotable only if one of these
# appears in its text — there is no geocoding API behind this, by design.
GAZETTEER = {
    "aden": (12.7855, 45.0187),
    "sanaa": (15.3694, 44.1910),
    "sana'a": (15.3694, 44.1910),
    "taiz": (13.5789, 44.0178),
    "marib": (15.4700, 45.3200),
    "hodeidah": (14.7978, 42.9545),
    "saada": (16.9402, 43.7639),
    "mukalla": (14.5425, 49.1242),
    "riyadh": (24.7136, 46.6753),
    "jeddah": (21.4858, 39.1925),
    "jizan": (16.8892, 42.5611),
    "abha": (18.2164, 42.5053),
    "khamis mushait": (18.3000, 42.7333),
    "najran": (17.4917, 44.1322),
    "dhahran": (26.2886, 50.1140),
    "medina": (24.5247, 39.5692),
    "bab al-mandab": (12.5833, 43.3333),
}

STORE = Path(__file__).resolve().parent / "incidents.json"
CLOCK_FILE = Path(__file__).resolve().parent / "_chronometers.html"
X_CACHE = Path(__file__).resolve().parent / "osint613_cache.json"


def _text(el, *names):
    for n in names:
        found = el.find(n)
        if found is not None and found.text:
            return found.text.strip()
    return ""


def _strip_html(raw: str) -> str:
    return re.sub(r"<[^>]+>", " ", raw or "").replace("&nbsp;", " ").strip()


def _parse_when(raw: str):
    """Best-effort parse of RSS/Atom date strings into aware UTC."""
    if not raw:
        return None
    try:
        d = parsedate_to_datetime(raw)
        return d.astimezone(timezone.utc) if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            d = datetime.strptime(raw.strip(), fmt)
            return d.astimezone(timezone.utc) if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def fetch_feed(feed, timeout=12):
    """Return (items, status_string). Never raises."""
    req = urllib.request.Request(
        feed["url"],
        headers={"User-Agent": "SaudiWarTracker/1.0 (OSINT situational awareness)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        return [], f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return [], f"UNREACHABLE ({getattr(e, 'reason', 'error')})"
    except Exception as e:                                  # noqa: BLE001
        return [], f"ERROR ({type(e).__name__})"

    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return [], "MALFORMED XML"

    out = []
    # RSS 2.0
    for item in root.iter("item"):
        out.append({
            "title": _text(item, "title"),
            "link": _text(item, "link"),
            "summary": _strip_html(_text(item, "description")),
            "when": _parse_when(_text(item, "pubDate")),
        })
    # Atom
    if not out:
        ns = "{http://www.w3.org/2005/Atom}"
        for entry in root.iter(f"{ns}entry"):
            link_el = entry.find(f"{ns}link")
            out.append({
                "title": _text(entry, f"{ns}title"),
                "link": link_el.get("href") if link_el is not None else "",
                "summary": _strip_html(_text(entry, f"{ns}summary", f"{ns}content")),
                "when": _parse_when(_text(entry, f"{ns}updated", f"{ns}published")),
            })

    for o in out:
        o["outlet"] = feed["name"]
        o["tier"] = feed["tier"]
    return out, f"OK ({len(out)})"


def match_location(text: str):
    low = text.lower()
    for name, coords in GAZETTEER.items():
        if name in low:
            return name.upper(), coords
    return None, None


@st.cache_data(ttl=540, show_spinner=False)
def pull_wire(window_hours: int):
    """Fetch, filter and sort wire items. Cached for 5 minutes."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    items, statuses = [], []
    for feed in FEEDS:
        if not feed.get("enabled", True):
            statuses.append((feed["name"], "DISABLED"))
            continue
        got, status = fetch_feed(feed)
        statuses.append((feed["name"], status))
        for it in got:
            # Several outlets repeat the headline as the description.
            if it["summary"].strip().lower().startswith(it["title"].strip().lower()[:40]):
                rest = it["summary"].strip()[len(it["title"]):].strip(" -—|\u2013")
                # A few characters left over is debris from a trailing byline,
                # not a summary. Drop it rather than printing a stray letter.
                it["summary"] = rest if len(rest) > 25 else ""
            blob = f"{it['title']} {it['summary']}".lower()
            if not any(k in blob for k in KEYWORDS):
                continue
            if it["when"] and it["when"] < cutoff:
                continue
            loc, coords = match_location(f"{it['title']} {it['summary']}")
            it["loc"] = loc
            it["coords"] = coords
            items.append(it)

    seen, dedup = set(), []
    for it in items:
        key = it["link"] or it["title"]
        if key in seen:
            continue
        seen.add(key)
        dedup.append(it)

    dedup.sort(key=lambda x: x["when"] or datetime.min.replace(tzinfo=timezone.utc),
               reverse=True)
    return dedup, statuses


def load_promoted():
    if not STORE.exists():
        return []
    try:
        return json.loads(STORE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def save_promoted(records):
    STORE.write_text(json.dumps(records, indent=2), encoding="utf-8")


def _x_link(status_id: str) -> str:
    return f"https://x.com/{X_HANDLE}/status/{status_id}" if status_id else f"https://x.com/{X_HANDLE}"


def _load_x_cache():
    if not X_CACHE.exists():
        return []
    try:
        return json.loads(X_CACHE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _save_x_cache(posts):
    try:
        X_CACHE.write_text(json.dumps(posts, indent=2), encoding="utf-8")
    except OSError:
        pass


@st.cache_data(ttl=60, show_spinner=False)
def pull_x_watch():
    """Latest posts from @Osint613. Live mirrors in parallel, then cache, then seed."""
    live = []

    def _one(url):
        got, status = fetch_feed(
            {"name": X_HANDLE, "tier": "SOCIAL", "url": url, "enabled": True},
            timeout=4,
        )
        return got, status

    try:
        with ThreadPoolExecutor(max_workers=len(X_RSS_URLS)) as pool:
            futs = [pool.submit(_one, url) for url in X_RSS_URLS]
            for fut in as_completed(futs, timeout=6):
                got, status = fut.result()
                if not status.startswith("OK"):
                    continue
                batch = []
                for it in got:
                    text = (it.get("title") or it.get("summary") or "").strip()
                    if not text or text.lower() in ("osint613", "twitter feed"):
                        continue
                    when = it["when"].strftime("%Y%m%dT%H%MZ") if it.get("when") else ""
                    batch.append({
                        "text": text[:280],
                        "when": when,
                        "link": it.get("link") or f"https://x.com/{X_HANDLE}",
                    })
                if batch:
                    live = batch
                    break
    except Exception:                                       # noqa: BLE001
        live = []

    if live:
        _save_x_cache(live[:20])
        return live[:20], "LIVE"

    cached = _load_x_cache()
    if cached:
        return cached[:20], "CACHE"

    seeded = [{
        "text": row["text"],
        "when": row["when"],
        "link": _x_link(row["id"]),
    } for row in X_SEED]
    return seeded, "SNAPSHOT"


def render_x_ticker():
    """Vertical auto-scroll of @Osint613 under the panes. Hover pauses."""
    posts, source = pull_x_watch()
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=X_LOOKBACK_MIN)
    fresh = []
    for p in posts:
        try:
            when = parse_dtg(p["when"]) if p.get("when") else None
        except ValueError:
            when = None
        if when and when >= cutoff:
            fresh.append(p)

    if fresh:
        shown = fresh
        window = f"LAST {X_LOOKBACK_MIN} MIN"
    else:
        shown = posts[:12]
        window = f"QUIET {X_LOOKBACK_MIN} MIN — LATEST"

    rows = []
    for p in shown:
        stamp = "----Z"
        if p.get("when"):
            try:
                stamp = parse_dtg(p["when"]).strftime("%H%MZ")
            except ValueError:
                stamp = p["when"]
        text = html.escape(p.get("text") or "")
        link = html.escape(p.get("link") or f"https://x.com/{X_HANDLE}", quote=True)
        rows.append(
            f'<a class="row" href="{link}" target="_blank" rel="noopener">'
            f'<span class="tm">{html.escape(stamp)}</span>'
            f'<span class="tx">{text}</span></a>'
        )
    if not rows:
        rows.append('<div class="empty">NO POSTS ON HAND</div>')

    body = "".join(rows)
    doc = f"""
    <html><head><meta charset="utf-8"><style>
      html, body {{ margin:0; padding:0; background:{BG}; }}
      * {{ font-family:{MONO}; box-sizing:border-box; }}
      .hd {{
        display:flex; justify-content:space-between; align-items:baseline;
        border:1px solid {BORDER}; border-bottom:none; background:{PANEL};
        padding:4px 10px; letter-spacing:1.6px;
      }}
      .hd-k {{ color:{TEXT_DIM}; font-size:10px; }}
      .hd-v {{ color:{TEXT}; font-size:11px; }}
      .hd-a {{ color:{ALERT}; font-size:10px; letter-spacing:1.4px; }}
      #vp {{
        height:{X_TICKER_H - 28}px; overflow:hidden; border:1px solid {BORDER};
        background:{PANEL}; position:relative;
      }}
      #track {{ position:absolute; left:0; right:0; top:0; }}
      .row {{
        display:flex; gap:12px; align-items:baseline;
        padding:5px 10px; border-bottom:1px dotted {BORDER};
        color:{TEXT}; text-decoration:none; font-size:12px; line-height:1.45;
      }}
      .row:hover {{ background:#061206; }}
      .tm {{ color:{TEXT_DIM}; font-size:10.5px; letter-spacing:1px;
             white-space:nowrap; font-variant-numeric:tabular-nums; }}
      .tx {{ color:{TEXT}; }}
      .empty {{ color:{TEXT_DIM}; padding:10px; font-size:11px; letter-spacing:1.4px; }}
    </style></head><body>
      <div class="hd">
        <span><span class="hd-k">X WATCH</span>
          <span class="hd-v">&nbsp;@{X_HANDLE}</span></span>
        <span class="hd-a">{window}</span>
        <span class="hd-k">{source} // UNVERIFIED // NOT PLOTTED // HOVER PAUSES</span>
      </div>
      <div id="vp"><div id="track">{body}{body}</div></div>
    <script>
      var vp = document.getElementById("vp");
      var track = document.getElementById("track");
      var SPEED = {X_SCROLL_PX_PER_SEC};
      var paused = false, acc = 0, last = null, y = 0;
      vp.addEventListener("mouseenter", function() {{ paused = true; }});
      vp.addEventListener("mouseleave", function() {{ paused = false; }});
      function step(ts) {{
        if (last === null) last = ts;
        var dt = (ts - last) / 1000; last = ts;
        var half = track.scrollHeight / 2;
        if (!paused && SPEED > 0 && half > vp.clientHeight) {{
          acc += SPEED * dt;
          if (acc >= 1) {{
            var stepPx = Math.floor(acc);
            acc -= stepPx;
            y += stepPx;
            if (y >= half) y -= half;
            track.style.transform = "translateY(" + (-y) + "px)";
          }}
        }}
        requestAnimationFrame(step);
      }}
      requestAnimationFrame(step);
    </script>
    </body></html>
    """
    try:
        components.html(doc, height=X_TICKER_H + 8, scrolling=False)
    except Exception:                                       # noqa: BLE001
        st.markdown(doc, unsafe_allow_html=True)


def render_incident_feed(live, archived, height):
    """The incident feed as one self-scrolling panel.

    Rendered as a component rather than Streamlit widgets so it can scroll
    continuously on its own. Hovering pauses it; the scroll position is kept
    across the 30s page refresh so it does not jump back to the top.
    """
    cards, last_day = [], None
    for inc in sorted(live, key=lambda x: x["dtg"], reverse=True):
        day = day_bucket(inc["dtg"])
        if day != last_day:
            cards.append(
                f'<div class="tmark"><span class="tmark-l">{day_label(inc["dtg"])}</span>'
                f'<span class="tmark-rule"></span>'
                f'<span class="tmark-r">{day}</span></div>'
            )
            last_day = day

        is_active = inc["status"] == "ACTIVE"
        red = is_red(inc)
        if is_active:
            badge = f'<span class="badge{"" if red else " badge-amber"}">ALERT</span>'
        else:
            badge = f'<span class="badge-s">{inc["status"]}</span>'
        cls = "card-red" if red else "card-std"

        srcs = ""
        for src in inc["sources"]:
            body = (f'<a href="{src["url"]}" target="_blank">{src["title"]}</a>'
                    if src["url"] else src["title"])
            srcs += (f'<div>&middot; <b>{src["outlet"]}</b> &mdash; {body}'
                     f'<br><span class="meta">&nbsp;&nbsp;{src["note"]}</span></div>')

        conflict = ""
        if inc.get("conflicting_reports"):
            rows = "".join(f"<div>&middot; {c}</div>" for c in inc["conflicting_reports"])
            conflict = f'<span class="lab">CONFLICTING REPORTING</span><div class="alert">{rows}</div>'

        cards.append(f"""
          <div class="card {cls}">
            {badge}<span class="meta">&nbsp;{inc['id']}</span>
            <div class="name">{inc['name']}</div>
            <div class="meta">{inc['locality']}</div>
            <div class="stamp">
              <div><span class="sk">ZULU</span><span class="sv">{dtg_display(inc)}</span></div>
              <div><span class="sk">LOCAL</span><span class="sv">{local_display(inc)}</span></div>
              <div><span class="sk">ELAPSED</span><span class="sv">{age_label(inc['dtg'])}</span></div>
              <div><span class="sk">GRID</span><span class="sv">{inc['lat']:.4f}N {inc['lon']:.4f}E</span></div>
              <div><span class="sk">TYPE</span><span class="sv">{inc['type']}</span></div>
              <div><span class="sk">SEVERITY</span>
                <span class="sv{' alert' if red else ''}">{inc['severity']}</span></div>
              <div><span class="sk">KIA / INJ</span><span class="sv alert">{cas_line(inc)}</span></div>
              <div><span class="sk">CONF</span><span class="sv">{inc['confidence']}</span></div>
            </div>
            <span class="lab">SUMMARY</span><div class="body">{inc['summary']}</div>
            <span class="lab">CASUALTIES</span><div class="alert">{inc['casualties']}</div>
            {conflict}
            <span class="lab">ATTRIBUTION</span><div class="body">{inc['attribution']}</div>
            <span class="lab">VERIFIED SOURCES</span><div class="body">{srcs}</div>
          </div>
        """)

    if not cards:
        cards.append(
            f'<div class="empty">NO INCIDENTS IN THE LAST '
            f'{INCIDENT_WINDOW_HOURS // 24} DAYS.<br>{len(archived)} ARCHIVED '
            f'OUTSIDE WINDOW.</div>'
        )

    body = "".join(cards)
    tal = casualty_totals(live)
    disputed_note = " (DISPUTED)" if tal["disputed"] else ""
    unrep_note = (f'<span class="t-un">{tal["unreported"]} EVENT(S) NO FIGURES</span>'
                  if tal["unreported"] else "")
    doc = f"""
    <html><head><meta charset="utf-8"><style>
      html, body {{ margin:0; padding:0; background:{BG}; }}
      * {{ font-family:{MONO}; box-sizing:border-box; }}
      #vp {{ height:{height}px; overflow-y:auto; border:1px solid {BORDER};
             background:{PANEL}; padding:8px 10px; scrollbar-width:thin;
             scrollbar-color:{BORDER} {BG}; }}
      #vp::-webkit-scrollbar {{ width:9px; }}
      #vp::-webkit-scrollbar-track {{ background:{BG}; }}
      #vp::-webkit-scrollbar-thumb {{ background:{BORDER}; }}
      .tmark {{ display:flex; align-items:center; gap:7px; margin:13px 0 8px 0; }}
      .tmark-l {{ color:{TEXT}; font-size:11.5px; letter-spacing:2.5px; white-space:nowrap; }}
      .tmark-r {{ color:{TEXT_DIM}; font-size:10px; letter-spacing:1.5px; white-space:nowrap; }}
      .tmark-rule {{ flex:1; height:1px; background:{BORDER}; }}
      .card {{ border:1px solid {BORDER}; background:{PANEL}; margin-bottom:10px;
               padding:9px 11px; font-size:12.5px; line-height:1.6; color:{TEXT}; }}
      .card-red {{ border-left:3px solid {ALERT}; }}
      .card-std {{ border-left:3px solid {BORDER_LT}; }}
      .badge {{ display:inline-block; background:{ALERT}; color:{BG}; padding:1px 7px;
                font-size:10.5px; letter-spacing:2px;
                animation:blink 1.6s steps(1,end) infinite; }}
      .badge-amber {{ background:{BORDER_LT}; color:{BG}; }}
      .badge-s {{ display:inline-block; border:1px solid {BORDER_LT}; color:{TEXT_DIM};
                  padding:1px 7px; font-size:10.5px; letter-spacing:2px; }}
      @keyframes blink {{ 0%,60%{{opacity:1}} 61%,100%{{opacity:.25}} }}
      .name {{ color:{TEXT}; font-size:13.5px; letter-spacing:1.5px; margin:6px 0 2px 0; }}
      .meta {{ color:{TEXT_DIM}; font-size:11.5px; letter-spacing:1px; }}
      .stamp {{ margin:7px 0 2px 0; border-top:1px dotted {BORDER};
                border-bottom:1px dotted {BORDER}; padding:4px 0; }}
      .stamp > div {{ display:flex; justify-content:space-between; padding:1px 0; }}
      .sk {{ color:{TEXT_DIM}; font-size:10.5px; letter-spacing:2px; }}
      .sv {{ color:{TEXT}; font-size:11px; font-variant-numeric:tabular-nums;
             text-align:right; }}
      .lab {{ color:{TEXT_DIM}; font-size:10.5px; letter-spacing:2px; display:block;
              border-bottom:1px solid {BORDER}; margin:9px 0 4px 0; padding-bottom:2px; }}
      .body {{ color:{TEXT}; margin-top:6px; }}
      .alert {{ color:{ALERT}; }}
      .empty {{ color:{TEXT_DIM}; font-size:11.5px; letter-spacing:1.5px; padding:10px 2px; }}
      a {{ color:{TEXT}; }}
      #hud {{ position:sticky; top:-8px; z-index:5; background:{PANEL};
              border-bottom:1px solid {BORDER}; padding:6px 0 5px 0;
              margin:-8px -10px 0 -10px; padding-left:10px; padding-right:10px; }}
      .t-row {{ display:flex; justify-content:space-between; align-items:baseline;
                gap:8px; flex-wrap:wrap; }}
      .t-cell {{ display:flex; gap:6px; align-items:baseline; white-space:nowrap; }}
      .t-k {{ color:{TEXT_DIM}; font-size:9.5px; letter-spacing:2px; }}
      .t-v {{ color:{TEXT}; font-size:17px; letter-spacing:1px;
              font-variant-numeric:tabular-nums; }}
      .t-v-alert {{ color:{ALERT}; font-size:17px; letter-spacing:1px;
                    font-variant-numeric:tabular-nums; }}
      .t-sub {{ color:{TEXT_DIM}; font-size:8.5px; letter-spacing:1px;
                margin-top:3px; flex-wrap:wrap; row-gap:2px; }}
      .t-sub span {{ white-space:nowrap; }}
      .t-un {{ color:{TEXT_DIM}; }}
    </style></head><body>
      <div id="vp">
        <div id="hud">
          <div class="t-row">
            <span class="t-cell"><span class="t-k">KIA</span>
              <span class="t-v-alert">{tal['kia']}</span></span>
            <span class="t-cell"><span class="t-k">INJURED</span>
              <span class="t-v-alert">{tal['wia']}</span></span>
            <span class="t-cell"><span class="t-k">EVENTS</span>
              <span class="t-v">{len(live)}</span></span>
            <span class="t-cell"><span class="t-k">WINDOW</span>
              <span class="t-v">{INCIDENT_WINDOW_HOURS // 24}D</span></span>
          </div>
          <div class="t-row t-sub">
            <span id="st">AUTO-SCROLL ACTIVE</span>
            <span>{unrep_note}</span>
            <span>REPORTED{disputed_note} &mdash; HOVER PAUSES</span>
          </div>
        </div>
        {body}
      </div>
    <script>
      var vp = document.getElementById("vp");
      var st = document.getElementById("st");
      var SPEED = {FEED_SCROLL_PX_PER_SEC};
      var paused = false, acc = 0, last = null;

      try {{
        var saved = sessionStorage.getItem("swt_feed_scroll");
        if (saved !== null) vp.scrollTop = parseFloat(saved) || 0;
      }} catch (e) {{}}

      vp.addEventListener("mouseenter", function() {{
        paused = true; st.textContent = "PAUSED";
      }});
      vp.addEventListener("mouseleave", function() {{
        paused = false; st.textContent = "AUTO-SCROLL ACTIVE";
      }});
      vp.addEventListener("scroll", function() {{
        try {{ sessionStorage.setItem("swt_feed_scroll", vp.scrollTop); }} catch (e) {{}}
      }});

      function step(ts) {{
        if (last === null) last = ts;
        var dt = (ts - last) / 1000; last = ts;
        if (!paused && SPEED > 0 && vp.scrollHeight > vp.clientHeight) {{
          acc += SPEED * dt;
          if (acc >= 1) {{
            var whole = Math.floor(acc); acc -= whole;
            if (vp.scrollTop + vp.clientHeight >= vp.scrollHeight - 1) {{
              vp.scrollTop = 0;                 // loop back to newest
            }} else {{
              vp.scrollTop += whole;
            }}
          }}
        }}
        requestAnimationFrame(step);
      }}
      requestAnimationFrame(step);
    </script>
    </body></html>
    """
    try:
        components.html(doc, height=height + 6, scrolling=False)
    except Exception:                                       # noqa: BLE001
        st.markdown(doc, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# CHROME
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="SAUDI WAR TRACKER",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    f"""
    <style>
      #MainMenu, footer, header {{ visibility: hidden; }}
      .stDeployButton {{ display: none; }}

      .stApp, body {{
          background: {BG};
          color: {TEXT};
          font-family: {MONO};
      }}
      .block-container {{
          padding: 0.4rem 0.9rem 0.5rem 0.9rem;
          max-width: 100%;
      }}
      /* tighten Streamlit's default vertical gaps, but never to zero —
         at zero the iframes ride up over their own pane headers. */
      div[data-testid="stVerticalBlock"] {{ gap: 0.35rem; }}
      div[data-testid="stHorizontalBlock"] {{ gap: 0.5rem; }}
      * {{ font-family: {MONO} !important; }}
      /* Streamlit draws expander arrows etc. with an icon font. The rule above
         would render them as the literal word "arrow_right", so put it back. */
      span[data-testid="stIconMaterial"],
      [data-testid*="Icon"] span,
      .material-icons, .material-icons-outlined,
      [class*="material-symbols"], [class*="MaterialIcon"] {{
          font-family: "Material Symbols Rounded", "Material Symbols Outlined",
                       "Material Icons" !important;
      }}

      /* ---- status bar -------------------------------------------------- */
      .swt-statusbar {{
          display: flex;
          flex-wrap: wrap;
          border: 1px solid {BORDER};
          background: {PANEL};
          font-size: 12px;
          letter-spacing: 1.5px;
          margin-bottom: 10px;
      }}
      .swt-statusbar div {{
          padding: 6px 14px;
          border-right: 1px solid {BORDER};
          white-space: nowrap;
      }}
      .swt-statusbar div:last-child {{ border-right: none; }}

      /* compact system strip */
      .swt-strip {{ margin-top: 6px; font-size: 10.5px; }}
      .swt-strip div {{ padding: 4px 11px; }}
      .swt-strip div:last-child {{ margin-left: 0; }}

      /* pane headers */
      .swt-pane-hd {{
          position: relative;
          z-index: 3;
          margin-bottom: 0;
          min-height: 24px;
          display: flex;
          justify-content: space-between;
          align-items: baseline;
          gap: 10px;
          border: 1px solid {BORDER};
          border-bottom: none;
          background: {PANEL};
          padding: 5px 8px;
          font-size: 9.5px;
          letter-spacing: 1.2px;
          color: {TEXT_DIM};
      }}
      .swt-pane-hd > span {{
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
          min-width: 0;
      }}
      .swt-pane-dtg {{ color: {TEXT}; flex-shrink: 0; }}

      /* scrolling pane bodies */
      div[data-testid="stVerticalBlockBorderWrapper"] {{
          border: 1px solid {BORDER};
          background: {PANEL};
          padding: 7px 8px 7px 8px;
      }}
      div[data-testid="stVerticalBlockBorderWrapper"]::-webkit-scrollbar {{ width: 9px; }}
      div[data-testid="stVerticalBlockBorderWrapper"]::-webkit-scrollbar-track {{
          background: {BG};
      }}
      div[data-testid="stVerticalBlockBorderWrapper"]::-webkit-scrollbar-thumb {{
          background: {BORDER};
      }}
      div[data-testid="stVerticalBlockBorderWrapper"]::-webkit-scrollbar-thumb:hover {{
          background: {BORDER_LT};
      }}

      /* time markers in the scrolling intel */
      .swt-tmark {{
          display: flex;
          align-items: center;
          gap: 7px;
          margin: 11px 0 7px 0;
      }}
      .swt-tmark-l {{
          color: {TEXT};
          font-size: 11px;
          letter-spacing: 2px;
          white-space: nowrap;
      }}
      .swt-tmark-r {{
          color: {TEXT_DIM};
          font-size: 10px;
          letter-spacing: 1.5px;
          white-space: nowrap;
      }}
      .swt-tmark-rule {{ flex: 1; height: 1px; background: {BORDER}; }}

      .swt-empty {{
          color: {TEXT_DIM};
          font-size: 11.5px;
          letter-spacing: 1.5px;
          line-height: 1.7;
          padding: 10px 2px;
      }}
      .swt-feedstat {{
          border: 1px solid {BORDER};
          padding: 5px 8px;
          margin: 7px 0 4px 0;
          font-size: 11px;
      }}

      /* expanders inside the wire pane */
      details, div[data-testid="stExpander"] {{
          border: 1px solid {BORDER} !important;
          border-radius: 0 !important;
          background: {BG} !important;
      }}
      div[data-testid="stExpander"] summary {{
          color: {TEXT_DIM} !important;
          font-size: 11px !important;
          letter-spacing: 1.5px;
      }}
      .swt-sb-k {{ color: {TEXT_DIM}; }}
      .swt-sb-v {{ color: {TEXT}; }}
      .swt-sb-alert {{ color: {ALERT}; }}
      .swt-threat {{ display: flex; align-items: baseline; gap: 7px; }}
      .swt-threat-v {{ font-size: 15px; letter-spacing: 2px; }}
      .swt-threat-sub {{ color: {TEXT_DIM}; font-size: 9px; letter-spacing: 1px; }}

      /* ---- header ------------------------------------------------------ */
      .swt-head {{
          border: 1px solid {BORDER};
          background: {PANEL};
          padding: 10px 14px;
          margin-bottom: 10px;
      }}
      .swt-title {{
          font-size: 24px;
          letter-spacing: 7px;
          color: {TEXT};
          margin: 0;
      }}
      .swt-sub {{
          font-size: 11px;
          letter-spacing: 2.5px;
          color: {TEXT_DIM};
          margin-top: 3px;
      }}

      /* ---- panels ------------------------------------------------------ */
      .swt-panel {{
          border: 1px solid {BORDER};
          background: {PANEL};
          margin-bottom: 10px;
      }}
      .swt-panel-hd {{
          border-bottom: 1px solid {BORDER};
          padding: 5px 10px;
          font-size: 11px;
          letter-spacing: 2.5px;
          color: {TEXT_DIM};
      }}
      .swt-panel-bd {{ padding: 10px; font-size: 12.5px; line-height: 1.65; }}

      .swt-row {{
          display: flex;
          justify-content: space-between;
          border-bottom: 1px dotted {BORDER};
          padding: 3px 0;
      }}
      .swt-row:last-child {{ border-bottom: none; }}
      .swt-k {{ color: {TEXT_DIM}; letter-spacing: 1px; }}
      .swt-v {{ color: {TEXT}; }}
      .swt-v-alert {{ color: {ALERT}; }}

      /* ---- incident cards ---------------------------------------------- */
      .swt-inc {{
          border: 1px solid {BORDER};
          border-left: 3px solid {ALERT};
          background: {PANEL};
          margin-bottom: 10px;
          padding: 9px 11px;
          font-size: 12.5px;
          line-height: 1.6;
      }}
      .swt-inc-closed {{ border-left: 3px solid {BORDER_LT}; }}
      .swt-badge {{
          display: inline-block;
          background: {ALERT};
          color: {BG};
          padding: 1px 7px;
          font-size: 10.5px;
          letter-spacing: 2px;
          animation: swtblink 1.6s steps(1, end) infinite;
      }}
      .swt-badge-static {{
          display: inline-block;
          border: 1px solid {BORDER_LT};
          color: {TEXT_DIM};
          padding: 1px 7px;
          font-size: 10.5px;
          letter-spacing: 2px;
      }}
      @keyframes swtblink {{ 0%,60% {{opacity:1;}} 61%,100% {{opacity:0.25;}} }}

      .swt-inc-name {{
          color: {TEXT};
          font-size: 13.5px;
          letter-spacing: 1.5px;
          margin: 6px 0 2px 0;
      }}
      .swt-inc-meta {{ color: {TEXT_DIM}; font-size: 11.5px; letter-spacing: 1px; }}
      .swt-inc-body {{ color: {TEXT}; margin-top: 7px; }}
      .swt-label {{
          color: {TEXT_DIM};
          font-size: 10.5px;
          letter-spacing: 2px;
          border-bottom: 1px solid {BORDER};
          display: block;
          margin: 9px 0 4px 0;
          padding-bottom: 2px;
      }}
      .swt-inc a {{ color: {TEXT}; text-decoration: underline; }}
      .swt-inc a:hover {{ color: {BORDER_LT}; }}
      .swt-caveat {{ color: {ALERT}; }}

      /* ---- controls ---------------------------------------------------- */
      .stButton > button {{
          background: {PANEL};
          color: {TEXT};
          border: 1px solid {BORDER};
          border-radius: 0;
          font-size: 10.5px;
          letter-spacing: 1.5px;
          padding: 2px 8px;
          min-height: 0;
          line-height: 1.5;
      }}
      .stButton > button:hover {{
          border-color: {BORDER_LT};
          color: {TEXT};
          background: {PANEL};
      }}

      .swt-foot {{
          border-top: 1px solid {BORDER};
          margin-top: 10px;
          padding-top: 8px;
          color: {TEXT_DIM};
          font-size: 10.5px;
          letter-spacing: 1.4px;
          line-height: 1.8;
      }}
      iframe {{ border: 1px solid {BORDER} !important; }}
    </style>
    """,
    unsafe_allow_html=True,
)



# ---------------------------------------------------------------------------
# CHRONOMETER BAR
# Rendered as a component so the clocks tick in the browser once per second
# without round-tripping to the server. The 30s data refresh is separate.
# ---------------------------------------------------------------------------
def render_chronometers():
    cells = "".join(
        f"""
        <div class="clk">
          <div class="clk-lbl">{label}</div>
          <div class="clk-time" data-zone="{zone}">--:--:--</div>
          <div class="clk-sub"><span data-zonedate="{zone}">--------</span> &nbsp;{suffix}</div>
        </div>
        """
        for label, zone, suffix in CLOCKS
    )

    html = f"""
    <html><head><meta charset="utf-8"><style>
      html, body {{ margin:0; padding:0; background:{BG}; }}
      * {{ font-family:{MONO}; box-sizing:border-box; }}
      .bar {{ display:flex; border:1px solid {BORDER}; background:{PANEL}; }}
      .clk {{ flex:1; padding:7px 12px; border-right:1px solid {BORDER}; }}
      .clk:last-child {{ border-right:none; }}
      .clk-lbl {{ color:{TEXT_DIM}; font-size:10px; letter-spacing:3px; }}
      .clk-time {{ color:{TEXT}; font-size:26px; letter-spacing:3px;
                   line-height:1.15; font-variant-numeric:tabular-nums; }}
      .clk-sub {{ color:{TEXT_DIM}; font-size:10px; letter-spacing:1.5px; }}
      .sync {{ flex:1.25; padding:7px 12px; border-left:1px solid {BORDER}; }}
      .sync-row {{ display:flex; justify-content:space-between;
                   font-size:10.5px; letter-spacing:1.5px; padding:1px 0; }}
      .sync-k {{ color:{TEXT_DIM}; }}
      .sync-v {{ color:{TEXT}; font-variant-numeric:tabular-nums; }}
      .sync-v.hot {{ color:{ALERT}; }}
      .dtg {{ color:{TEXT}; font-size:15px; letter-spacing:2.5px;
              font-variant-numeric:tabular-nums; }}
    </style></head><body>
      <div class="bar">
        {cells}
        <div class="sync">
          <div class="clk-lbl">DTG &mdash; ZULU</div>
          <div class="dtg" id="dtg">--------T----Z</div>
          <div class="sync-row"><span class="sync-k">LAST SYNC</span>
            <span class="sync-v">{{SYNC}}</span></div>
          <div class="sync-row"><span class="sync-k">NEXT SYNC</span>
            <span class="sync-v" id="cd">{{CD}}</span></div>
        </div>
      </div>
    <script>
      var PERIOD = {AUTO_REFRESH_SECONDS};
      var started = Date.now();

      function pad(n) {{ return String(n).padStart(2, "0"); }}

      function fmt(zone) {{
        var o = {{ hour12:false, hour:"2-digit", minute:"2-digit", second:"2-digit" }};
        if (zone !== "UTC") o.timeZone = zone; else o.timeZone = "UTC";
        return new Intl.DateTimeFormat("en-GB", o).format(new Date());
      }}

      function fmtDate(zone) {{
        var o = {{ year:"numeric", month:"2-digit", day:"2-digit",
                   timeZone: zone === "UTC" ? "UTC" : zone }};
        var p = new Intl.DateTimeFormat("en-GB", o).formatToParts(new Date());
        var g = {{}};
        p.forEach(function(x) {{ g[x.type] = x.value; }});
        return g.year + g.month + g.day;
      }}

      function tick() {{
        document.querySelectorAll("[data-zone]").forEach(function(el) {{
          el.textContent = fmt(el.getAttribute("data-zone"));
        }});
        document.querySelectorAll("[data-zonedate]").forEach(function(el) {{
          el.textContent = fmtDate(el.getAttribute("data-zonedate"));
        }});

        var d = new Date();
        document.getElementById("dtg").textContent =
          d.getUTCFullYear() + pad(d.getUTCMonth()+1) + pad(d.getUTCDate()) +
          "T" + pad(d.getUTCHours()) + pad(d.getUTCMinutes()) + "Z";

        var cd = document.getElementById("cd");
        if (PERIOD > 0 && cd) {{
          var left = Math.max(0, PERIOD - Math.floor((Date.now() - started)/1000));
          cd.textContent = (left >= 60)
            ? "T-" + Math.floor(left/60) + ":" + pad(left % 60)
            : "T-" + pad(left);
          if (left <= 10) {{ cd.classList.add("hot"); }}
          if (left <= 0) {{
            cd.textContent = "SYNCING";
            try {{ window.parent.location.reload(); }}
            catch (e) {{ try {{ window.top.location.reload(); }} catch (e2) {{}} }}
          }}
        }} else if (cd) {{
          cd.textContent = "MANUAL";
        }}
      }}

      tick();
      setInterval(tick, 1000);
    </script>
    </body></html>
    """
    html = html.replace("{SYNC}", dtg_now())
    if AUTO_REFRESH_SECONDS >= 60:
        cd0 = f"T-{AUTO_REFRESH_SECONDS // 60}:{AUTO_REFRESH_SECONDS % 60:02d}"
    elif AUTO_REFRESH_SECONDS:
        cd0 = f"T-{AUTO_REFRESH_SECONDS:02d}"
    else:
        cd0 = "MANUAL"
    html = html.replace("{CD}", cd0)

    # components.html is the proven path and still works; Streamlit has
    # announced its removal, so fall back to st.iframe if it ever goes away.
    try:
        components.html(html, height=92, scrolling=False)
    except Exception:                                       # noqa: BLE001
        CLOCK_FILE.write_text(html, encoding="utf-8")
        st.iframe(CLOCK_FILE, height=84)


# ---------------------------------------------------------------------------
# MAP
# ---------------------------------------------------------------------------
def build_map(incidents):
    m = folium.Map(
        location=MAP_CENTER,
        zoom_start=MAP_ZOOM,
        tiles=None,            # basemap added explicitly below
        control_scale=True,
        zoom_control=True,
        attributionControl=True,
    )

    bm = BASEMAPS[BASEMAP]
    folium.TileLayer(
        tiles=bm["base"],
        attr=bm["attr"],
        name=bm["label"],
        max_zoom=bm["max_zoom"],
        control=False,
    ).add_to(m)

    if bm["reference"]:
        folium.TileLayer(
            tiles=bm["reference"],
            attr=bm["attr"],
            name="REFERENCE",
            max_zoom=bm["max_zoom"],
            control=False,
            overlay=True,
        ).add_to(m)

    m.get_root().header.add_child(
        folium.Element(
            f"""
            <style>
              .leaflet-container {{ background: {BG}; font-family: {MONO}; }}
              .swt-ring {{
                  border: 1px solid {ALERT};
                  border-radius: 50%;
                  width: 30px; height: 30px;
                  animation: swtring 3s ease-out infinite;
              }}
              @keyframes swtring {{
                  0%   {{ transform: scale(0.45); opacity: 0.85; }}
                  100% {{ transform: scale(1.45); opacity: 0;    }}
              }}
              .swt-ref-lbl {{
                  color: {TEXT_DIM};
                  font-family: {MONO};
                  font-size: 10.5px;
                  letter-spacing: 1.2px;
                  white-space: nowrap;
                  text-shadow: 0 0 3px {BG}, 0 0 3px {BG};
              }}
              .swt-inc-lbl {{
                  color: {ALERT};
                  font-family: {MONO};
                  font-size: 11.5px;
                  letter-spacing: 1.5px;
                  white-space: nowrap;
                  text-shadow: 0 0 3px {BG}, 0 0 3px {BG};
              }}
              .swt-country {{
                  color: {BORDER_LT};
                  font-family: {MONO};
                  font-size: 13px;
                  letter-spacing: 6px;
                  white-space: nowrap;
              }}
              .leaflet-popup-content-wrapper, .leaflet-popup-tip {{
                  background: {PANEL};
                  color: {TEXT};
                  border: 1px solid {BORDER};
                  border-radius: 0;
                  box-shadow: none;
              }}
              .leaflet-popup-content {{ font-family: {MONO}; font-size: 12px; margin: 10px; }}
              .leaflet-popup-content a {{ color: {TEXT}; }}
              .leaflet-control-attribution {{
                  background: {PANEL} !important;
                  color: {TEXT_DIM} !important;
                  font-size: 9px !important;
              }}
              .leaflet-control-attribution a {{ color: {TEXT_DIM} !important; }}
            </style>
            """
        )
    )

    # Country labels
    for name, lat, lon in COUNTRY_LABELS:
        folium.Marker(
            [lat, lon],
            icon=folium.DivIcon(
                html=f'<div class="swt-country">{name}</div>',
                icon_size=(180, 20),
                icon_anchor=(90, 10),
            ),
        ).add_to(m)

    # Reference infrastructure — olive, low weight
    for label, short, ref, lat, lon, kind in REFERENCE_POINTS:
        radius = 4 if kind == "APT" else 3

        # Permanent label so locations are readable without clicking.
        folium.Marker(
            [lat, lon],
            icon=folium.DivIcon(
                html=f'<div class="swt-ref-lbl">{short}</div>',
                icon_size=(150, 16),
                icon_anchor=(-8, 8),
            ),
        ).add_to(m)

        folium.CircleMarker(
            location=[lat, lon],
            radius=radius,
            color=BORDER_LT,
            weight=1,
            fill=True,
            fill_color=BORDER,
            fill_opacity=0.85,
            popup=folium.Popup(
                f"<b style='letter-spacing:1px'>{label}</b><br>"
                f"<span style='color:{TEXT_DIM}'>REF {ref} &nbsp;|&nbsp; "
                f"{lat:.4f}N {lon:.4f}E</span>",
                max_width=280,
            ),
            tooltip=label,
        ).add_to(m)

    # Incidents — red, ringed
    for inc in incidents:
        active = inc["status"] == "ACTIVE"
        src_html = "".join(
            f"<div>&middot; {s['outlet']}"
            + (f" &mdash; <a href='{s['url']}' target='_blank'>OPEN</a>" if s["url"] else "")
            + "</div>"
            for s in inc["sources"]
        )
        popup_html = (
            f"<div style='font-family:{MONO};min-width:290px'>"
            f"<div style='color:{ALERT};letter-spacing:2px;font-size:11px'>"
            f"{inc['status']} &nbsp;|&nbsp; {inc['severity']}</div>"
            f"<div style='color:{TEXT};letter-spacing:1.5px;margin-top:4px'>"
            f"<b>{inc['name']}</b></div>"
            f"<div style='color:{TEXT_DIM};font-size:11px'>{inc['locality']}</div>"
            f"<hr style='border:none;border-top:1px solid {BORDER};margin:7px 0'>"
            f"<div style='color:{TEXT_DIM};font-size:11px'>DTG {inc['dtg']}<br>"
            f"TYPE {inc['type']}<br>"
            f"GRID {inc['lat']:.4f}N {inc['lon']:.4f}E</div>"
            f"<div style='margin-top:7px;color:{TEXT};line-height:1.55'>{inc['summary']}</div>"
            f"<div style='margin-top:7px;color:{ALERT};font-size:11px'>{inc['casualties']}</div>"
            f"<hr style='border:none;border-top:1px solid {BORDER};margin:7px 0'>"
            f"<div style='color:{TEXT_DIM};font-size:10.5px;letter-spacing:1.5px'>SOURCES</div>"
            f"<div style='color:{TEXT};font-size:11px'>{src_html}</div>"
            f"</div>"
        )

        if active and is_red(inc):
            folium.Marker(
                [inc["lat"], inc["lon"]],
                icon=folium.DivIcon(
                    html='<div class="swt-ring"></div>',
                    icon_size=(30, 30),
                    icon_anchor=(15, 15),
                ),
            ).add_to(m)

        mark = sev_color(inc)
        folium.CircleMarker(
            location=[inc["lat"], inc["lon"]],
            radius=16,
            color=mark,
            weight=1,
            opacity=0.55,
            fill=True,
            fill_color=mark,
            fill_opacity=0.07,
        ).add_to(m)

        folium.Marker(
            [inc["lat"], inc["lon"]],
            icon=folium.DivIcon(
                html=f'<div class="swt-inc-lbl" style="color:{sev_color(inc)}">'
                     f'{inc["locality"].split(",")[0]}</div>',
                icon_size=(170, 16),
                icon_anchor=(-18, 8),
            ),
        ).add_to(m)

        folium.CircleMarker(
            location=[inc["lat"], inc["lon"]],
            radius=5,
            color=mark,
            weight=1,
            fill=True,
            fill_color=mark,
            fill_opacity=1.0,
            popup=folium.Popup(popup_html, max_width=340),
            tooltip=f"{inc['id']} // {inc['name']}",
        ).add_to(m)

    # Frame tightly on the actual points of interest rather than a fixed
    # zoom, so the theater fills the panel and labels are legible.
    pts = [(lat, lon) for _, _, _, lat, lon, _ in REFERENCE_POINTS]
    pts += [(i["lat"], i["lon"]) for i in incidents]
    if pts:
        lats = [p[0] for p in pts]
        lons = [p[1] for p in pts]
        m.fit_bounds(
            [[min(lats), min(lons)], [max(lats), max(lons)]],
            padding=(10, 10),
        )

    return m


# ---------------------------------------------------------------------------
# RENDER
#
# Everything is sized to fit one screen. Each pane scrolls internally instead
# of the page scrolling as a whole. PANE_H is the single knob: raise it on a
# tall monitor, lower it if the footer gets pushed off.
# ---------------------------------------------------------------------------
PANE_H = 770

now = dtg_now()
ALL_INCIDENTS = INCIDENTS + load_promoted()
live = [i for i in ALL_INCIDENTS if in_window(i)]
archived = [i for i in ALL_INCIDENTS if not in_window(i)]
active = [i for i in live if i["status"] == "ACTIVE"]


def hour_bucket(dtg: str) -> str:
    """Hour-resolution marker key, e.g. 20261015T19Z."""
    return dtg[:11] + "Z"


def time_marker(label: str, right: str = "") -> str:
    return (
        f'<div class="swt-tmark"><span class="swt-tmark-l">{label}</span>'
        f'<span class="swt-tmark-rule"></span>'
        f'<span class="swt-tmark-r">{right}</span></div>'
    )


threats = [(name, threat_level(ALL_INCIDENTS, lat, lon))
           for name, lat, lon in THREAT_WATCH]
threat_cells = "".join(
    f'<div class="swt-threat"><span class="swt-sb-k">THREAT {name}</span> '
    f'<span class="swt-threat-v" style="color:{threat_color(t["level"])}">{t["level"]}</span>'
    f'<span class="swt-threat-sub">{t["count"]} EVT / {THREAT_RADIUS_KM}KM / '
    f'{THREAT_LOOKBACK_H // 24}D'
    + (f' / LAST H+{t["last_age"]}' if t["last_age"] is not None else ' / NONE')
    + f' / SCORE {t["score"]}</span></div>'
    for name, t in threats
)

st.markdown(
    f"""
    <div class="swt-statusbar">
      <div><span class="swt-sb-k">DTG</span> <span class="swt-sb-v">{now}</span></div>
      <div><span class="swt-sb-k">THEATER</span> <span class="swt-sb-v">{THEATER}</span></div>
      <div><span class="swt-sb-k">STATUS</span>
           <span class="{'swt-sb-alert' if active else 'swt-sb-v'}">
           {'ACTIVE TRACKING — ' + str(len(active)) + ' INCIDENT(S)' if active else 'NOMINAL'}</span></div>
      <div><span class="swt-sb-k">TITLE</span>
           <span class="swt-sb-v" style="letter-spacing:5px">SAUDI WAR TRACKER</span></div>
      {threat_cells}
      <div><span class="swt-sb-k">CLASS</span> <span class="swt-sb-v">{CLASSIFICATION}</span></div>
    </div>
    """,
    unsafe_allow_html=True,
)

render_chronometers()

# --- compact horizontal system strip, replacing the old tall status panel ----
sev_counts = {}
for i in live:
    sev_counts[i["severity"]] = sev_counts.get(i["severity"], 0) + 1
sev_line = " / ".join(f"{k} {v}" for k, v in sorted(sev_counts.items())) or "NONE"

wire_items, feed_statuses = pull_wire(WIRE_WINDOW_HOURS)
promoted_links = {p.get("link") for p in load_promoted() if p.get("link")}
pending = [w for w in wire_items if w["link"] not in promoted_links]
feeds_ok = sum(1 for _, s in feed_statuses if s.startswith("OK"))

strip = [
    ("AOR", "KSA / YEM"),
    ("INCIDENT WIN", f"{INCIDENT_WINDOW_HOURS // 24}D"),
    ("WIRE WIN", f"{WIRE_WINDOW_HOURS}H"),
    ("IN WINDOW", str(len(live))),
    ("ARCHIVED", str(len(archived))),
    ("ACTIVE", str(len(active))),
    ("KIA", casualty_totals(live)["kia"]),
    ("INJURED", casualty_totals(live)["wia"]),
    ("SEVERITY", sev_line),
    ("REF PTS", str(len(REFERENCE_POINTS))),
    ("AUTO SYNC", f"{AUTO_REFRESH_SECONDS}s" if AUTO_REFRESH_SECONDS else "OFF"),
    ("FEEDS", f"{feeds_ok}/{len(feed_statuses)} OK"),
    ("PENDING", str(len(pending))),
    ("BASEMAP", BASEMAPS[BASEMAP]["label"]),
]
cells = "".join(
    f'<div><span class="swt-sb-k">{k}</span> '
    f'<span class="{"swt-sb-alert" if (k == "ACTIVE" and active) or (k == "FEEDS" and feeds_ok == 0) or k in ("KIA", "INJURED") else "swt-sb-v"}">{v}</span></div>'
    for k, v in strip
)
st.markdown(f'<div class="swt-statusbar swt-strip">{cells}</div>', unsafe_allow_html=True)

# --- three-pane split -------------------------------------------------------
col_map, col_feed, col_wire = st.columns([6, 3, 3], gap="small")

with col_map:
    st.markdown(
        f'<div class="swt-pane-hd"><span>TACTICAL OVERLAY</span>'
        f'<span class="swt-pane-dtg">{now}</span></div>',
        unsafe_allow_html=True,
    )
    st_folium(
        build_map(live),
        width=None,
        height=PANE_H,
        returned_objects=[],
        key="theater_map",
    )

with col_feed:
    st.markdown(
        f'<div class="swt-pane-hd"><span>INCIDENT FEED {INCIDENT_WINDOW_HOURS // 24}D</span>'
        f'<span class="swt-pane-dtg">{len(live)} PLOTTED</span></div>',
        unsafe_allow_html=True,
    )
    render_incident_feed(live, archived, PANE_H)

with col_wire:
    st.markdown(
        f'<div class="swt-pane-hd"><span>WIRE INTAKE {WIRE_WINDOW_HOURS}H</span>'
        f'<span class="swt-pane-dtg">{len(pending)} UNVERIF</span></div>',
        unsafe_allow_html=True,
    )
    with st.container(height=PANE_H, border=False):
        bc1, bc2 = st.columns(2)
        if bc1.button("FORCE SYNC", use_container_width=True):
            st.rerun()
        if bc2.button("PULL WIRE", use_container_width=True):
            pull_wire.clear()
            st.rerun()

        fs = "".join(
            f'<div class="swt-row"><span class="swt-k">{name}</span>'
            f'<span class="{"swt-v" if status.startswith("OK") else "swt-v-alert"}">{status}</span></div>'
            for name, status in feed_statuses
        )
        st.markdown(
            f'<div class="swt-feedstat">'
            f'<div class="swt-label" style="margin-top:0">FEED STATUS</div>{fs}</div>',
            unsafe_allow_html=True,
        )

        if not pending:
            st.markdown(
                f'<div class="swt-empty">NO MATCHING WIRE ITEMS IN {WIRE_WINDOW_HOURS}H.<br>'
                'If every feed above errors, this host has no route to those outlets.</div>',
                unsafe_allow_html=True,
            )

        last_bucket = None
        for idx, item in enumerate(pending[:40]):
            when = item["when"].strftime("%Y%m%dT%H%MZ") if item["when"] else ""
            bucket = hour_bucket(when) if when else "UNKNOWN DTG"
            if bucket != last_bucket:
                st.markdown(
                    time_marker(bucket, age_label(when) if when else ""),
                    unsafe_allow_html=True,
                )
                last_bucket = bucket

            geo = (f"{item['loc']} {item['coords'][0]:.3f}N {item['coords'][1]:.3f}E"
                   if item["coords"] else "NO GEO MATCH &mdash; NOT PROMOTABLE")
            st.markdown(
                f"""
                <div class="swt-inc swt-inc-closed">
                  <span class="swt-badge-static">{item['tier']}</span>
                  <span class="swt-inc-meta">&nbsp;{item['outlet']}</span>
                  <div class="swt-inc-name" style="font-size:12px">{item['title']}</div>
                  <div class="swt-inc-meta">{when or 'UNKNOWN DTG'} &nbsp;|&nbsp; {geo}</div>
                  <div class="swt-inc-body">{item['summary'][:280]}</div>
                  <div class="swt-inc-body">
                    <a href="{item['link']}" target="_blank">OPEN SOURCE ARTICLE</a></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if item["coords"]:
                with st.expander(f"PROMOTE // {item['title'][:44]}"):
                    itype = st.selectbox(
                        "TYPE",
                        ["MISSILE STRIKE", "DRONE STRIKE", "AIRSTRIKE", "GROUND ENGAGEMENT",
                         "MARITIME INCIDENT", "IED / VBIED", "INTERCEPT", "OTHER"],
                        key=f"t{idx}",
                    )
                    isev = st.selectbox("SEVERITY", ["LOW", "MODERATE", "HIGH", "CRITICAL"],
                                        index=1, key=f"s{idx}")
                    note = st.text_area("ANALYST NOTE", key=f"n{idx}", height=68)
                    if st.button("CONFIRM PROMOTE", key=f"p{idx}", use_container_width=True):
                        stamp = item["when"] or datetime.now(timezone.utc)
                        rec = {
                            "id": f"WIRE-{stamp.strftime('%Y%m%d')}-{idx:03d}",
                            "dtg": when or dtg_now(),
                            "name": item["title"][:90].upper(),
                            "locality": item["loc"],
                            "lat": item["coords"][0],
                            "lon": item["coords"][1],
                            "type": itype,
                            "severity": isev,
                            "status": "MONITORING",
                            "attribution": "Not established at time of promotion.",
                            "summary": (item["summary"][:600] +
                                        (f"\n\nANALYST NOTE: {note}" if note else "")),
                            "casualties": "Not reported at time of promotion.",
                            "kia": None,
                            "wia": None,
                            "confidence": "SINGLE SOURCE — PENDING CORROBORATION",
                            "link": item["link"],
                            "sources": [{
                                "outlet": item["outlet"],
                                "title": item["title"],
                                "url": item["link"],
                                "note": f"{item['tier']} — promoted from wire intake",
                            }],
                        }
                        records = load_promoted()
                        records.append(rec)
                        save_promoted(records)
                        st.rerun()

render_x_ticker()

st.markdown(
    f"""
    <div class="swt-foot">
      {CLASSIFICATION} &nbsp;//&nbsp; GENERATED {now} &nbsp;//&nbsp;
      AUTO SYNC {AUTO_REFRESH_SECONDS}s &nbsp;//&nbsp; INCIDENTS {INCIDENT_WINDOW_HOURS // 24}D / WIRE {WIRE_WINDOW_HOURS}H &nbsp;//&nbsp;
      X FOOTER @{X_HANDLE} UNVERIFIED, NOT PLOTTED, PREFERS LAST {X_LOOKBACK_MIN} MIN.
      Verified wire services, major broadcasters and official statements only on the map.
      Wire intake is UNVERIFIED until promoted by an analyst. Where reporting conflicts, both
      figures are shown. FOR SITUATIONAL AWARENESS ONLY &mdash; NOT AN INTELLIGENCE PRODUCT,
      NOT FOR OPERATIONAL PLANNING OR TARGETING.
    </div>
    """,
    unsafe_allow_html=True,
)

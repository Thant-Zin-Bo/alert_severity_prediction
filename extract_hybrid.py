# extract_hybrid.py
# Hybrid extractor (regex + no-label "NER") + preprocessing for Start Time / Duration / Priority
# NO DEDUPE: keeps all non-empty rows
# Outputs: out/alerts_with_fields_hybrid.csv, out/coverage_hybrid.json, out/entity_preview.csv, out/preprocess_report.json

from pathlib import Path
import re, json
import pandas as pd
import numpy as np

# ----------------- Paths (edit only INPUT_CSV / OUT_DIR if you like) --------
SCRIPT_DIR = Path(__file__).resolve().parent
INPUT_CSV = SCRIPT_DIR / "Alert_raw.csv"       # your input file (change if needed)
TYPE_CUES_FILE = SCRIPT_DIR / "type_cues.yml"  # optional; plain text/yml list
OUT_DIR = SCRIPT_DIR / "out"                   # <-- change this if you want

OUT_CSV = OUT_DIR / "alerts_with_fields_hybrid.csv"
COVERAGE_JSON = OUT_DIR / "coverage_hybrid.json"
ENTITY_PREVIEW = OUT_DIR / "entity_preview.csv"
PREPROC_JSON = OUT_DIR / "preprocess_report.json"

# ----------------- Defaults & simple cue-file loader -------------------------
DEFAULT_TYPE_CUES = [
    r"oracle database",
    r"oracle weblogic",
    r"oracle cluster",
    r"oracle goldengate extract",
    r"oracle goldengate replicat",
    r"kubernetes cluster",
    r"kubernetes (?:node|pod)",
    r"windows server",
    r"linux server",
    r"kafka broker",
    r"redis server",
    r"postgres(?:ql)? database",
    r"microsoft sql(?: server)?",
    r"sql server",
    r"microsoft iis web",
    r"elasticsearch node",
    r"rabbitmq node",
    r"aws cloud",
    r"eG agent",
    r"external web",
    r"iis app pool",
    r"fcp port",
    r"host",
]
# Make TYPE_CUES available to NER even if main() hasn’t run yet.
TYPE_CUES = DEFAULT_TYPE_CUES.copy()

def load_type_cues(path: Path):
    if not path.exists():
        return DEFAULT_TYPE_CUES
    cues = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("- "):
            ln = ln[2:].strip()
        cues.append(ln)
    return cues or DEFAULT_TYPE_CUES

# ----------------- Decode weird +AHs- / +AF8- artifacts ----------------------
def decode_mutf7_like(s: str) -> str:
    """Map '+AHs-...+AH0-' style artifacts to ASCII so regex can match."""
    if not isinstance(s, str):
        s = "" if s is None else str(s)
    table = {
        "+AHs-": "{",   "+AH0-": "}",
        "+AFs-": "[",   "+AF0-": "]",
        "+AF8-": "_",   "+AFw-": "/",
        "+AC0-": "-",   "+ACM-": "#",
        "+ACo-": "*",   "+AD0-": "=",   "+ACI-": '"',  "+ACQ-": "'",
    }
    for k in sorted(table.keys(), key=len, reverse=True):
        s = s.replace(k, table[k])
    return s

# ----------------- Helpers ---------------------------------------------------
NAME_RE = r"[A-Za-z0-9._:+\-\/#]+(?:[A-Za-z0-9._:+\-\/#]+)?"
NAME_OR_PORT = NAME_RE + r"(?::\d{2,5})?"
STOPWORDS = {"on","in","of","at","by","for","drive","disk","node","host","pod","page","web"}

def clean_text(s):
    s = "" if s is None else str(s)
    s = decode_mutf7_like(s)                 # decode first
    return re.sub(r"\s+", " ", s).strip()

def valid_name(name: str) -> bool:
    if not name: return False
    n = name.strip().strip(":/-_.").lower()
    if not n or len(n) < 2: return False
    if n in STOPWORDS: return False
    return True

def pick_or_none(value):
    v = clean_text(value) if value else None
    return v if v else None

def looks_like_host(n: str) -> bool:
    if not n: return False
    # IPs, hostnames with dots, underscores, or hyphens
    return bool(re.search(r"(?:\d{1,3}\.){3}\d{1,3}", n) or
                re.search(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}", n) or
                re.search(r"[_-]", n))

# ----------------- Regex rules ----------------------------------------------
def build_regex_rules(TYPE_ALT: str):
    RULES = [
        dict(
            name="ogg_extract_braced",
            pat=re.compile(r"(?i)(?P<test>.+?)\s*\{\s*EXTRACT/(?P<name>[\w.\-:/#]+)\s*\}"),
            f=lambda m: ("oracle goldengate extract", m.group("name"), m.group("test")),
        ),
        dict(
            name="ogg_replicat_braced",
            pat=re.compile(r"(?i)(?P<test>.+?)\s*\{\s*REPLICAT/(?P<name>[\w.\-:/#]+)\s*\}"),
            f=lambda m: ("oracle goldengate replicat", m.group("name"), m.group("test")),
        ),

        dict(
            name="external_web_affecting",
            pat=re.compile(r"(?i)this is affecting\s+external web\s+(?P<name>[\w.\-:/#]+)"),
            f=lambda m: ("external web", m.group("name"), None),
        ),
        dict(
            name="web_page_not_available_affecting",
            pat=re.compile(r"(?i)the web page\s+(?P<pg>[\w.\-:/#]+)\s+is not available.*?affecting\s+external web\s+(?P<name>[\w.\-:/#]+)"),
            f=lambda m: ("external web", m.group("name"), f"web page {m.group('pg')} not available"),
        ),

        dict(
            name="iis_apppool_braced",
            pat=re.compile(r"(?i)(?P<test>.+?)\s*\{\s*(?P<name>DefaultAppPool[^\}\s]*)\s*\}"),
            f=lambda m: ("iis app pool", m.group("name"), m.group("test")),
        ),
        dict(
            name="fcp_port_braced",
            pat=re.compile(r"(?i)(?P<test>.+?)\s+in the FCP\s*\{\s*(?P<name>port\.[^\}\s]+).*?\}"),
            f=lambda m: ("fcp port", m.group("name"), m.group("test")),
        ),

        dict(
            name="generic_on_host_only",
            pat=re.compile(r"(?i)(?P<test>.+?)\bon\s+(?P<name>(?:[A-Za-z0-9._-]+\.)+[A-Za-z]{2,}|[A-Za-z0-9._-]{6,})"),
            f=lambda m: ("host", m.group("name"), m.group("test")),
        ),

        dict(
            name="eg_agent_test_on_name",
            pat=re.compile(r"(?i)\btest\s+(?P<test>[A-Za-z0-9._:+\-\/#]+).*?\bon\s+eG agent\s+(?P<name>"+NAME_RE+r")"),
            f=lambda m: ("eG agent", m.group("name"), m.group("test")),
        ),
        dict(
            name="in_pod_name_on_k8s_cluster",
            pat=re.compile(r"(?i)(?P<test>.+?)\bin\s+pod\s+(?P<name>"+NAME_RE+r").*?\bon\s+kubernetes cluster\s+(?P<cluster>"+NAME_RE+r")"),
            f=lambda m: ("kubernetes pod", m.group("name"), m.group("test")),
        ),
        dict(
            name="drive_of_name",
            pat=re.compile(r"(?i)(?P<test>.+?)\bdrive\s+of\s+(?P<name>"+NAME_RE+r")"),
            f=lambda m: ("host", m.group("name"), m.group("test")),
        ),
        dict(
            name="on_oracle_db_name",
            pat=re.compile(r"(?i)(?P<test>.+?)\bon\s+oracle database\s+(?P<name>"+NAME_RE+r")"),
            f=lambda m: ("oracle database", m.group("name"), m.group("test")),
        ),
        dict(
            name="from_aws_cloud_name",
            pat=re.compile(r"(?i)(?P<test>.+?)\bfrom\s+aws cloud\s+(?P<name>"+NAME_RE+r")"),
            f=lambda m: ("aws cloud", m.group("name"), m.group("test")),
        ),

        dict(
            name="test_on_type_name",
            pat=re.compile(r"(?i)(?P<test>.+?)\bon\s+(?P<type>"+r"(?:%s)" % "|".join(DEFAULT_TYPE_CUES)+r")\s+(?P<name>"+NAME_RE+r")"),
            f=lambda m: (m.group("type").lower(), m.group("name"), m.group("test")),
        ),
        dict(
            name="test_from_type_name",
            pat=re.compile(r"(?i)(?P<test>.+?)\bfrom\s+(?P<type>"+r"(?:%s)" % "|".join(DEFAULT_TYPE_CUES)+r")\s+(?P<name>"+NAME_RE+r")"),
            f=lambda m: (m.group("type").lower(), m.group("name"), m.group("test")),
        ),
        dict(
            name="type_colon_name",
            pat=re.compile(r"(?i)(?:(?P<test>.+?)\s+\|\s+)?(?P<type>"+r"(?:%s)" % "|".join(DEFAULT_TYPE_CUES)+r")\s*[:]\s*(?P<name>"+NAME_RE+r")"),
            f=lambda m: (m.group("type").lower(), m.group("name"), m.group("test")),
        ),

        dict(
            name="broad_on_from_type_name",
            pat=re.compile(r"(?i)(?P<test>.+?)\b(?:on|from)\s+(?P<type>[A-Za-z][A-Za-z \-]{2,40})\s+(?P<name>"+NAME_RE+r")"),
            f=lambda m: (m.group("type").strip().lower(), m.group("name"), m.group("test")),
        ),

        dict(
            name="generic_braced_resource",
            pat=re.compile(r"(?i)(?P<test>.+?)\s*\{\s*(?P<name>[^}]+?)\s*\}"),
            f=lambda m: ("resource", m.group("name"), m.group("test")),
        ),
    ]
    return RULES

# ----------------- No-label "NER" (SMARTER) ----------------------------------
def ner_candidates(text: str):
    """
    Heuristic NER to cover:
    - Microsoft SQL Server NAME:PORT (… 's error log, connections to …)
    - Oracle WebLogic NAME:PORT (JMX connection, heap memory …)
    - Generic 'of/ on/ from <name>' and '{ … }' fallbacks
    """
    t = clean_text(text)

    # 1) Type from cues: choose the longest match
    types = []
    for cue in TYPE_CUES:
        try:
            pat = re.compile(cue, re.IGNORECASE)
        except re.error:
            continue
        for m in pat.finditer(t):
            types.append((m.start(), m.end(), m.group(0).lower()))
    type_txt = max(types, key=lambda x: x[1]-x[0])[2] if types else None

    # 2) NAME after specific cues/patterns (handles unmatched examples)
    name = None

    # 2a) Microsoft SQL Server … <NAME[:PORT]>
    if not name:
        m = re.search(r"(?i)microsoft\s+sql(?:\s+server)?\s+(?P<name>"+NAME_OR_PORT+r")", t)
        if m and valid_name(m.group("name")):
            name = m.group("name")
            if type_txt is None:
                type_txt = "sql server"

    # 2b) Possessive "'s error log" — capture preceding NAME[:PORT]
    if not name:
        m = re.search(r"(?i)(?P<name>"+NAME_OR_PORT+r")\s*'s\s+error\s+log", t)
        if m and valid_name(m.group("name")):
            name = m.group("name")
            if type_txt is None and re.search(r"(?i)microsoft\s+sql|sql\s+server", t):
                type_txt = "sql server"

    # 2c) "connections to Microsoft SQL <NAME[:PORT]>" or "clients connecting to …"
    if not name:
        m = re.search(r"(?i)(?:connections?\s+to|connecting\s+to)\s+microsoft\s+sql(?:\s+server)?\s+(?P<name>"+NAME_OR_PORT+r")", t)
        if m and valid_name(m.group("name")):
            name = m.group("name")
            if type_txt is None:
                type_txt = "sql server"

    # 2d) Oracle WebLogic <NAME[:PORT]> (JMX / heap etc.)
    if not name:
        m = re.search(r"(?i)oracle\s+weblogic\s+(?P<name>"+NAME_OR_PORT+r")", t)
        if m and valid_name(m.group("name")):
            name = m.group("name")
            if type_txt is None:
                type_txt = "oracle weblogic"

    # 3) Generic fallbacks
    if not name:
        m = re.search(r"(?i)\bin\s+pod\s+(?P<name>"+NAME_RE+r")", t)
        if m and valid_name(m.group("name")):
            name = m.group("name")
    if not name:
        m = re.search(r"(?i)\bdrive\s+of\s+(?P<name>"+NAME_RE+r")", t)
        if m and valid_name(m.group("name")):
            name = m.group("name")
    if not name:
        m = re.search(r"(?i)\b(?:on|from|of)\s+(?P<name>"+NAME_RE+r")", t)
        if m and valid_name(m.group("name")):
            name = m.group("name")
    if not name:
        m = re.search(r"(?i)\{\s*(?P<name>[^}]+)\s*\}", t)
        if m and valid_name(m.group("name")):
            name = m.group("name")

    # 4) If we found a host-like name but no type, default to 'host'
    if type_txt is None and name and looks_like_host(name):
        type_txt = "host"

    return type_txt, name

def choose(a, b):
    return a if a else b

def extract_row(text: str, RULES):
    if not isinstance(text, str) or not text.strip():
        return dict(Component_Type=None, Component_Name=None, Test=None,
                    Raw_Type=None, Raw_Name=None, Raw_Test=None,
                    Src_Type="none", Src_Name="none",
                    Ner_Type=None, Ner_Name=None,
                    Regex_Type=None, Regex_Name=None)
    t = clean_text(text)

    # Regex pass
    r_type = r_name = r_test = None
    for rule in RULES:
        m = rule["pat"].search(t)
        if not m: continue
        g_type, g_name, g_test = rule["f"](m)
        g_type = pick_or_none(g_type)
        g_name = pick_or_none(g_name)
        g_test = pick_or_none(g_test)
        if g_name and not valid_name(g_name):
            g_name = None
        r_type, r_name, r_test = g_type, g_name, g_test
        break

    # No-label NER pass (improved)
    n_type, n_name = ner_candidates(t)

    # Merge + provenance
    m_type, m_name, m_test = choose(r_type, n_type), choose(r_name, n_name), r_test
    s_type = "regex" if (m_type == r_type and m_type) else ("ner" if (m_type == n_type and m_type) else ("both" if (r_type and n_type) else "none"))
    s_name = "regex" if (m_name == r_name and m_name) else ("ner" if (m_name == n_name and m_name) else ("both" if (r_name and n_name) else "none"))

    return dict(
        Component_Type=m_type, Component_Name=m_name, Test=m_test,
        Raw_Type=m_type, Raw_Name=m_name, Raw_Test=m_test,
        Src_Type=s_type, Src_Name=s_name,
        Ner_Type=n_type, Ner_Name=n_name,
        Regex_Type=r_type, Regex_Name=r_name
    )

# ===================== PREPROCESSING (Start Time / Duration / Priority) =====================

PRIORITY_MAP = {
    "critical": "Critical", "crit": "Critical", "p1": "Critical", "sev1": "Critical", "urgent": "Critical",
    "major": "Major", "high": "Major", "p2": "Major", "sev2": "Major",
    "minor": "Minor", "low": "Minor", "p3": "Minor", "sev3": "Minor",
}
PRIORITY_LEVELS = {"Minor": 1, "Major": 2, "Critical": 3}

def normalize_priority(x):
    if pd.isna(x): return "Unknown"
    s = str(x).strip()
    k = s.lower()
    if k in PRIORITY_MAP:
        return PRIORITY_MAP[k]
    if s in {"Minor","Major","Critical"}: return s
    if "crit" in k or "p1" in k or "sev1" in k: return "Critical"
    if "major" in k or "high" in k or "p2" in k or "sev2" in k: return "Major"
    if "minor" in k or "low" in k or "p3" in k or "sev3" in k: return "Minor"
    return "Unknown"

def map_priority_level(label):
    return PRIORITY_LEVELS.get(label, 0)

_DUR_HMS_RE = re.compile(r"^\s*(\d{1,2}):(\d{1,2})(?::(\d{1,2}))?\s*$")
_DUR_UNITS_RE = re.compile(r"(?i)(\d+(?:\.\d+)?)\s*(h|hr|hrs|hour|hours|m|min|mins|minute|minutes|s|sec|secs|second|seconds)")

def parse_duration_to_seconds(s):
    if s is None or (isinstance(s, float) and pd.isna(s)): return None
    txt = str(s).strip()
    if not txt: return None
    m = _DUR_HMS_RE.match(txt)
    if m:
        a = int(m.group(1)); b = int(m.group(2)); c = int(m.group(3) or 0)
        if m.group(3) is not None:  # HH:MM:SS
            return a*3600 + b*60 + c
        return a*60 + b  # assume MM:SS
    total = 0.0
    for num, unit in _DUR_UNITS_RE.findall(txt):
        v = float(num); u = unit.lower()
        if u in {"h","hr","hrs","hour","hours"}:   total += v*3600.0
        elif u in {"m","min","mins","minute","minutes"}: total += v*60.0
        elif u in {"s","sec","secs","second","seconds"}:  total += v
    if total > 0: return int(round(total))
    if txt.isdigit():
        iv = int(txt)
        return iv*60 if iv < 1000 else iv
    return None

START_CANDIDATES = [
    "start time", "start_time", "start", "event start", "event start time",
    "event_start_time", "starttime"
]
DUR_CANDIDATES = ["duration", "elapsed", "time taken", "time_taken"]

def find_col(cols_lower_map, key_options):
    for k in key_options:
        if k in cols_lower_map:
            return cols_lower_map[k]
    return None

def parse_start_time_series(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, errors="coerce", infer_datetime_format=True)

def datetime_to_epoch(series: pd.Series) -> pd.Series:
    def to_epoch(ts):
        try:
            if pd.isna(ts): return None
            return int(pd.Timestamp(ts).timestamp())
        except Exception:
            return None
    return series.map(to_epoch)

def day_of_week(series: pd.Series) -> pd.Series:
    return series.dt.dayofweek.where(series.notna(), None)

def hour_of_day(series: pd.Series) -> pd.Series:
    return series.dt.hour.where(series.notna(), None)

def is_weekend(series: pd.Series) -> pd.Series:
    return series.dt.dayofweek.isin([5,6]).where(series.notna(), None)

# ===================== Run ===================================================
if __name__ == "__main__":
    print(f"Using input:      {INPUT_CSV}")
    print(f"Using type cues:  {TYPE_CUES_FILE if TYPE_CUES_FILE.exists() else '(default list)'}")
    print(f"Writing to:       {OUT_DIR}")

    if not INPUT_CSV.exists():
        raise SystemExit(f"Input CSV not found: {INPUT_CSV}\n"
                         f"Put Alert_raw.csv next to this script, or change INPUT_CSV at the top.")

    # Load cues + build rules
    TYPE_CUES = load_type_cues(TYPE_CUES_FILE)
    TYPE_ALT = r"(?:%s)" % "|".join(TYPE_CUES)
    RULES = build_regex_rules(TYPE_ALT)

    # Read CSV and resolve columns
    df = pd.read_csv(INPUT_CSV)
    cols_lower = {c.lower(): c for c in df.columns}

    # Description & Priority columns
    desc_key = next((k for k in ["alert_description","description","message","alert","text"] if k in cols_lower), None)
    if not desc_key:
        raise SystemExit("Missing description column: one of Alert_Description/Description/Message/Alert/Text")
    pri_key = "priority" if "priority" in cols_lower else None
    if not pri_key:
        raise SystemExit("Missing required column: Priority")

    desc_col = cols_lower[desc_key]
    pri_col = cols_lower[pri_key]

    # Debug: artifact rows
    pre_artifacts = df[desc_col].astype(str).str.contains(r"\+AH[s0]-|\+AF[0-9sw]-|\+AC[0MQoI]-", regex=True, case=False).sum()
    print(f"Rows with '+AHs-/+AF8-…' artifacts (pre-clean): {pre_artifacts}")

    # --------- Clean only (NO DEDUPE)  --------------------------------------
    raw_rows = len(df)
    df[desc_col] = df[desc_col].astype(str).map(clean_text)
    df = df[df[desc_col].str.len() > 0].copy()   # keep all non-empty
    kept_rows = len(df)
    print({"raw_rows": int(raw_rows), "kept_non_empty": int(kept_rows), "dropped_empty": int(raw_rows - kept_rows)})

    # --------- Start Time & Duration & Priority preprocessing
    start_col = find_col(cols_lower, START_CANDIDATES)
    dur_col = find_col(cols_lower, DUR_CANDIDATES)

    # Parse Start Time
    if start_col:
        df["Start_DT"] = parse_start_time_series(df[start_col])
        df["Start_ISO"] = df["Start_DT"].dt.strftime("%Y-%m-%dT%H:%M:%S")
        df["Start_Epoch"] = datetime_to_epoch(df["Start_DT"])
        df["Start_Hour"] = hour_of_day(df["Start_DT"])
        df["Start_DOW"] = day_of_week(df["Start_DT"])
        df["Is_Weekend"] = is_weekend(df["Start_DT"])
    else:
        df["Start_DT"] = pd.NaT
        df["Start_ISO"] = None
        df["Start_Epoch"] = None
        df["Start_Hour"] = None
        df["Start_DOW"] = None
        df["Is_Weekend"] = None

    # Parse Duration
    if dur_col:
        dur_sec = df[dur_col].map(parse_duration_to_seconds)
        df["Duration_Sec"] = dur_sec
        df["Duration_Min"] = (dur_sec.astype(float) / 60.0).round(3)
    else:
        df["Duration_Sec"] = None
        df["Duration_Min"] = None

    # Normalize Priority
    df["Priority_Norm"] = df[pri_col].map(normalize_priority)
    df["Priority_Level"] = df["Priority_Norm"].map(map_priority_level)

    # --------- Extract TYPE/NAME/TEST
    ex = df[desc_col].map(lambda s: extract_row(s, RULES)).apply(pd.Series)

    # --------- Merge outputs
    out_df = pd.concat([
        df[[pri_col, desc_col,
            "Start_ISO","Start_Epoch","Start_Hour","Start_DOW","Is_Weekend",
            "Duration_Sec","Duration_Min",
            "Priority_Norm","Priority_Level"]],
        ex
    ], axis=1).rename(columns={pri_col: "Priority", desc_col: "Alert_Description"})

    # --------- Normalize missing TYPE/NAME/TEST to UNK (right before saving)
    UNK_TOKEN = "UNK"
    fill_cols = [
        "Component_Type", "Component_Name", "Test",
        "Raw_Type", "Raw_Name", "Raw_Test",
        "Regex_Type", "Regex_Name", "Ner_Type", "Ner_Name"
    ]
    for c in fill_cols:
        if c in out_df.columns:
            out_df[c] = out_df[c].astype("string").str.strip()
            out_df[c] = out_df[c].replace(r"^$", pd.NA, regex=True)
            out_df[c] = out_df[c].fillna(UNK_TOKEN)

    # --------- Coverage (Type/Name/Test)  (note: uses .notna() so UNK doesn't count as 'found')
    n = len(out_df)
    cov_type = float(out_df["Component_Type"].ne(UNK_TOKEN).mean()) if n else 0.0
    cov_name = float(out_df["Component_Name"].ne(UNK_TOKEN).mean()) if n else 0.0
    cov_test = float(out_df["Test"].ne(UNK_TOKEN).mean()) if n else 0.0

    # --------- Save CSV + preview
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(OUT_CSV, index=False)

    prev_cols = [
        "Priority","Priority_Norm","Priority_Level",
        "Start_ISO","Duration_Sec","Duration_Min",
        "Alert_Description","Component_Type","Component_Name","Test",
        "Src_Type","Src_Name","Regex_Type","Regex_Name","Ner_Type","Ner_Name"
    ]
    out_df[prev_cols].head(300).to_csv(ENTITY_PREVIEW, index=False)

    # --------- Coverage JSON (with a few preprocess stats)
    cov = {
        "rows": int(n),
        "coverage": {"type": cov_type, "name": cov_name, "test": cov_test},
        "unmatched_examples": out_df[(out_df["Component_Type"] == UNK_TOKEN) | (out_df["Component_Name"] == UNK_TOKEN)]["Alert_Description"].head(50).tolist(),
        "notes": "No dedupe. NER upgraded for MSSQL/WebLogic patterns. Start/Duration/Priority preprocessing included. UNK normalization applied."
    }
    COVERAGE_JSON.write_text(json.dumps(cov, indent=2), encoding="utf-8")

    # --------- Preprocess report JSON
    start_ok = int(out_df["Start_ISO"].notna().sum()) if "Start_ISO" in out_df.columns else 0
    dur_ok = int(out_df["Duration_Sec"].notna().sum()) if "Duration_Sec" in out_df.columns else 0

    dur_vals = out_df["Duration_Sec"].dropna().astype(int).tolist()
    dur_stats = {}
    if dur_vals:
        dur_stats = {
            "min_sec": int(min(dur_vals)),
            "p50_sec": int(np.percentile(dur_vals, 50)),
            "p90_sec": int(np.percentile(dur_vals, 90)),
            "max_sec": int(max(dur_vals))
        }

    pri_dist = out_df["Priority_Norm"].value_counts(dropna=False).to_dict()

    PREPROC_JSON.write_text(json.dumps({
        "columns_detected": {
            "start_time": start_col or None,
            "duration": dur_col or None,
            "priority": pri_col
        },
        "parse_rates": {"start_time_parsed": {"ok": start_ok, "total": int(n)},
                        "duration_parsed": {"ok": dur_ok, "total": int(n)}},
        "duration_stats": dur_stats,
        "priority_distribution": pri_dist
    }, indent=2), encoding="utf-8")

    print(f"Saved CSV          → {OUT_CSV}")
    print(f"Coverage (T,N,Te) → ({cov_type:.3f}, {cov_name:.3f}, {cov_test:.3f})")
    print(f"Coverage JSON     → {COVERAGE_JSON}")
    print(f"Preprocess report → {PREPROC_JSON}")
    print(f"Entity preview    → {ENTITY_PREVIEW}")

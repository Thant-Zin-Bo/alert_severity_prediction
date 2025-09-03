# pseudonymize.py — dictionary-based pseudonymization (3 dictionaries)
# Input : out/alerts_with_fields_hybrid.csv
# Output: out/alerts_pseudo.csv (+ dicts + report)

from pathlib import Path
import re, json
import pandas as pd

# ----------------- Paths -----------------
SCRIPT_DIR = Path(__file__).resolve().parent
IN_CSV     = SCRIPT_DIR / "out" / "alerts_with_fields_hybrid.csv"
OUT_DIR    = SCRIPT_DIR / "out"
OUT_CSV    = OUT_DIR / "alerts_pseudo.csv"
DICT_JSON  = OUT_DIR / "pseudo_dictionaries.json"
DICT_CT_CSV = OUT_DIR / "dict_component_type.csv"
DICT_CN_CSV = OUT_DIR / "dict_component_name.csv"
DICT_T_CSV  = OUT_DIR / "dict_test.csv"
REPORT     = OUT_DIR / "pseudo_report.json"

# ----------------- Config -----------------
MERGE_WITH_EXISTING = True
REPLACE_IN_TEXT     = True
ADD_TOKEN_PREFIX    = False  # keep OFF to avoid duplicating signal in text
UNK_TOKEN           = "UNK"

# Columns to drop from the final CSV (ignore missing safely)
DROP_COLS = [
    "Alert_Description","Start_Epoch","Start_Hour","Duration_Sec","Start_DOW",
    "Priority_Norm","Component_Name","Test",
    "Raw_Type","Raw_Name","Raw_Test","Src_Type","Src_Name","Ner_Type","Ner_Name",
    "Regex_Type","Regex_Name",
    "Component_Type_Token","Component_Type,_Token",
    "Component_Name_Token","Test_Token"
]

# ---------- Decode artifacts / cleanup ----------
def decode_mutf7_like(s: str) -> str:
    if not isinstance(s, str): s = "" if s is None else str(s)
    table = {"+AHs-":"{", "+AH0-":"}", "+AFs-":"[", "+AF0-":"]", "+AF8-":"_", "+AFw-":"/",
             "+AC0-":"-", "+ACM-":"#", "+ACo-":"*", "+AD0-":"=", "+ACI-":'"', "+ACQ-":"'"}
    for k in sorted(table, key=len, reverse=True): s = s.replace(k, table[k])
    return s

def clean_text(s: str) -> str:
    s = "" if s is None else str(s)
    s = decode_mutf7_like(s)
    return re.sub(r"\s+", " ", s).strip()

# ---------- ID scrubs (generic, not dictionary-aware) ----------
IP_PORT_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")
UUID_RE      = re.compile(r"\b[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\b")
HEXID_RE     = re.compile(r"\b0x[0-9A-Fa-f]+\b")
PORTNAME_RE  = re.compile(r"\bPort\s+\d+\b", re.IGNORECASE)

def scrub_ids(text: str) -> str:
    t = text
    t = IP_PORT_RE.sub("<IPPORT>", t)
    t = UUID_RE.sub("<UUID>", t)
    t = HEXID_RE.sub("<HEXID>", t)
    t = PORTNAME_RE.sub("<PORTNAME>", t)
    # NOTE: no brace replacement here; we do dictionary-aware braces later
    return t

# ---------- New hardening patterns ----------
NAME_COLON_CHAIN_RE = re.compile(r'(?<!<)\b[A-Za-z][A-Za-z0-9._+-]{4,}(?::[A-Za-z0-9._+-]{1,}){1,6}\b(?![^>]*>)')
LONG_ID_RE = re.compile(r'(?<!<)\b[A-Za-z0-9][A-Za-z0-9._+-]{7,}\b(?![^>]*>)')
DOMAIN_RE = re.compile(r'(?<!<)\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d{2,5})?\b(?![^>]*>)')
CHAIN_RE = re.compile(r'(?<!<)\b(?:[A-Za-z0-9]+[-_]){2,}[A-Za-z0-9]+(?::\d{2,5})?\b(?![^>]*>)')
CAMEL_RE = re.compile(r'(?<!<)\b(?:[A-Z][a-z0-9]+){2,}[A-Za-z0-9]*\b(?![^>]*>)')

def harden_generic_name_patterns(text: str, name_token: str) -> str:
    t = text
    t = NAME_COLON_CHAIN_RE.sub(name_token, t)
    t = DOMAIN_RE.sub(name_token, t)
    t = CHAIN_RE.sub(name_token, t)
    t = LONG_ID_RE.sub(name_token, t)
    t = CAMEL_RE.sub(name_token, t)
    return t

# ---------- Dictionaries (exactly 3) ----------
def build_or_load_dicts(path: Path) -> dict:
    if MERGE_WITH_EXISTING and path.exists():
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            return {
                "component_type": d.get("component_type", {}),
                "component_name": d.get("component_name", {}),
                "test": d.get("test", {})
            }
        except Exception:
            pass
    return {"component_type": {}, "component_name": {}, "test": {}}

def _next_index(values, prefix: str) -> int:
    mx = 0
    for lbl in values:
        if isinstance(lbl, str) and lbl.startswith(prefix):
            try: mx = max(mx, int(lbl[len(prefix):].strip()))
            except: pass
    return mx + 1

def is_missing_or_unk(val: str) -> bool:
    if val is None: return True
    s = str(val).strip()
    return (s == "" or s.upper() == UNK_TOKEN)

def assign_id(mapping: dict, raw: str, prefix: str) -> str:
    # Do NOT assign an ID for UNK/missing
    if is_missing_or_unk(raw):
        return ""
    raw_norm = str(raw).strip()
    if raw_norm in mapping: return mapping[raw_norm]
    lbl = f"{prefix}{_next_index(mapping.values(), prefix)}"
    mapping[raw_norm] = lbl
    return lbl

# ---------- Case-insensitive literal replacement ----------
def _ci_pat(s: str):
    s = (s or "").strip()
    if not s or is_missing_or_unk(s): return None
    esc = re.escape(s).replace(r"\ ", r"\s+")
    try: return re.compile(esc, re.IGNORECASE)
    except re.error: return None

def replace_ci(text: str, literal: str, token: str) -> str:
    pat = _ci_pat(literal)
    if not pat: return text
    return pat.sub(token, text)

# ---------- Name variants replacement ----------
def replace_name_variants(text: str, raw_name: str, token: str) -> str:
    """Replace exact name and common variants (colon-chains, token-chains, case)."""
    if is_missing_or_unk(raw_name): return text
    base = re.escape(raw_name)
    text = re.sub(rf"(?<!<){base}(?![^>]*>)", token, text, flags=re.IGNORECASE)
    text = re.sub(rf"(?<!<){base}(?::[A-Za-z0-9._+-]+){{1,6}}(?![^>]*>)", token, text, flags=re.IGNORECASE)
    text = re.sub(rf"(?<!<)(?:[A-Za-z0-9._+-]+:)*{base}(?::[A-Za-z0-9._+-]+)*(?![^>]*>)",
                  token, text, flags=re.IGNORECASE)
    return text

# ---------- Dictionary-aware brace replacement ----------
BRACES_RE = re.compile(r"\{\s*[^}]*\}")

def replace_braced_with_name_token(txt: str, name_token: str) -> str:
    """
    Replace any {...} block with a dictionary-aware NAME token:
      - Use name_token (e.g., <component_name_7>) if available,
      - else use {<component_name_UNK>}.
    """
    use_tok = name_token if name_token else "<component_name_UNK>"
    return BRACES_RE.sub("{" + use_tok + "}", txt)

# ---------- Per-row transform ----------
def pseudonymize_row(row, dicts):
    """
    Returns: pseudo_text, ct_label ('component N' or ''), cn_label ('component_name_N' or ''), t_label ('testN' or '')
    """
    raw_text  = clean_text(row["Alert_Description"])
    comp_type = str(row.get("Component_Type") or "").strip()
    comp_name = str(row.get("Component_Name") or "").strip()
    test      = str(row.get("Test") or "").strip()

    ct_map, cn_map, t_map = dicts["component_type"], dicts["component_name"], dicts["test"]

    # IDs are 'component N' / 'component_name_N' / 'testN' — skip UNK
    ct_label = assign_id(ct_map, comp_type, prefix="component ")
    cn_label = assign_id(cn_map, comp_name, prefix="component_name_")
    t_label  = assign_id(t_map,  test,      prefix="test")

    # tokens used inside the text (and for header)
    if ct_label:
        ct_tok = f"<{ct_label.replace(' ', '_')}>"
    else:
        ct_tok = "<component_type_UNK>" if is_missing_or_unk(comp_type) else "<component_type>"

    if cn_label:
        cn_tok = f"<{cn_label}>"
    else:
        cn_tok = "<component_name_UNK>" if is_missing_or_unk(comp_name) else "<component_name>"

    if t_label:
        t_tok = f"<{t_label.replace('test', 'test_')}>"
    else:
        t_tok = "<test_UNK>" if is_missing_or_unk(test) else "<test>"

    # build pseudo text
    pseudo = scrub_ids(raw_text)

    if REPLACE_IN_TEXT:
        # Replace the name by all known surface forms (skip UNK)
        candidate_names = {
            comp_name,
            str(row.get("Raw_Name") or ""),
            str(row.get("Ner_Name") or ""),
            str(row.get("Regex_Name") or "")
        }
        for nm in sorted({n for n in candidate_names if n and not is_missing_or_unk(n) and len(n) > 2}, key=len, reverse=True):
            pseudo = replace_name_variants(pseudo, nm, cn_tok)

        # Replace type and test tokens (skip UNK)
        if not is_missing_or_unk(comp_type):
            pseudo = replace_ci(pseudo, comp_type, ct_tok)

        if not is_missing_or_unk(test):
            p = _ci_pat(test)
            if p:
                pseudo = re.sub(r"^\s*" + p.pattern, t_tok, pseudo)  # start-of-string
                pseudo = p.sub(t_tok, pseudo)                        # anywhere

        # Dictionary-aware brace normalization (treat braces as names)
        pseudo = replace_braced_with_name_token(pseudo, cn_tok if cn_label else "")

        # Generic hardening to catch leftovers like IDs, FQDNs, colon chains
        pseudo = harden_generic_name_patterns(pseudo, cn_tok if cn_label else "<component_name_UNK>")

    pseudo = re.sub(r"\s+", " ", pseudo).strip()

    # Canonical header (optional; useful for debugging)
    # Example: [TYPE]=<component_1> [NAME]=<component_name_3> [TEST]=<test_2> | ...
    header = f"[TYPE]={ct_tok} [NAME]={cn_tok} [TEST]={t_tok} | "
    pseudo = f"{header}{pseudo}"

    return pseudo, ct_label, cn_label, t_label

# ----------------- Run -----------------
if __name__ == "__main__":
    if not IN_CSV.exists():
        raise SystemExit(f"Missing input: {IN_CSV} — run the extractor first.")

    df = pd.read_csv(IN_CSV)

    required = {"Priority","Alert_Description","Component_Type","Component_Name","Test"}
    missing = required - set(df.columns)
    if missing:
        raise SystemExit(f"Input missing columns: {missing}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    DICTS = build_or_load_dicts(DICT_JSON)

    pseudos, ct_ids, cn_ids, t_ids = [], [], [], []
    for _, r in df.iterrows():
        pseudo, ct_label, cn_label, t_label = pseudonymize_row(r, DICTS)
        pseudos.append(pseudo); ct_ids.append(ct_label); cn_ids.append(cn_label); t_ids.append(t_label)

    out = df.copy()
    out["Component_Type_Token"] = ct_ids
    out["Component_Name_Token"] = cn_ids
    out["Test_Token"]           = t_ids
    out["Pseudo_Description"]   = pseudos

    # Drop the columns you listed (ignore missing)
    out = out.drop(columns=[c.strip() for c in DROP_COLS], errors="ignore")

    out.to_csv(OUT_CSV, index=False)
    DICT_JSON.write_text(json.dumps(DICTS, indent=2, ensure_ascii=False), encoding="utf-8")

    # Optional: export the 3 dictionaries for review (exclude UNK rows naturally)
    if DICTS["component_type"]:
        pd.DataFrame(sorted(DICTS["component_type"].items()),
                     columns=["raw_component_type","id"]).to_csv(DICT_CT_CSV, index=False)
    if DICTS["component_name"]:
        pd.DataFrame(sorted(DICTS["component_name"].items()),
                     columns=["raw_component_name","id"]).to_csv(DICT_CN_CSV, index=False)
    if DICTS["test"]:
        pd.DataFrame(sorted(DICTS["test"].items()),
                     columns=["raw_test","id"]).to_csv(DICT_T_CSV, index=False)

    # Leak check (best-effort)
    leaks = dict(name=0, ip=0, uuid=0, hexid=0)
    name_cols_for_check = ["Component_Name","Raw_Name","Ner_Name","Regex_Name"]
    for i, r in enumerate(df.itertuples(index=False), start=0):
        pdx = str(pseudos[i])
        for col in name_cols_for_check:
            nm = str(getattr(r, col, "") or "")
            if nm and not is_missing_or_unk(nm) and len(nm) > 2 and re.search(re.escape(nm), pdx, flags=re.IGNORECASE):
                leaks["name"] += 1; break
        if IP_PORT_RE.search(pdx):  leaks["ip"]   += 1
        if UUID_RE.search(pdx):     leaks["uuid"] += 1
        if HEXID_RE.search(pdx):    leaks["hexid"]+= 1

    REPORT.write_text(json.dumps({
        "rows": int(len(out)),
        "leaks": leaks,
        "dict_sizes": {k: len(v) for k, v in DICTS.items()},
        "notes": "Consistent UNK tokens: <component_type_UNK>/<component_name_UNK>/<test_UNK>. Braces → {<component_name_*|UNK>}."
    }, indent=2), encoding="utf-8")

    print(f"Wrote → {OUT_CSV}")
    print(f"Wrote dictionaries → {DICT_JSON}")
    print(f"Wrote dict CSVs → {DICT_CT_CSV.name}, {DICT_CN_CSV.name}, {DICT_T_CSV.name}")
    print(f"Leak summary → {REPORT}")

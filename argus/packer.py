"""Packer / protector identification from PE static features.

Turns a generic "packed: yes (entropy 7.96)" into "packed with UPX / VMProtect /
Themida / ...". Commercial protectors (Themida, VMProtect, Enigma) are a strong
malware/evasion signal in their own right — legitimate software rarely ships
wrapped in them. Detection is section-name signatures first (exact, like PEiD),
then a heuristic fallback (high entropy + minimal imports + non-standard
sections) that flags a protector even when it randomizes its section names.

Pure functions over the `static` dict from tools/malware.analyze_file().
"""
from __future__ import annotations

# Section-name substrings that pin a specific packer/protector.
_PACKER_SECTIONS = {
    "UPX":                (("upx0", "upx1", "upx2", "upx!"),),
    "VMProtect":          ((".vmp0", ".vmp1", ".vmp2"),),
    "Themida/WinLicense": ((".themida", ".winlice"),),
    "ASPack":             ((".aspack", ".adata"),),
    "ASProtect":          ((".aspr",),),
    "PECompact":          (("pec1", "pec2"),),
    "MPRESS":             ((".mpress1", ".mpress2"),),
    "Petite":             ((".petite",),),
    "NSPack":             ((".nsp0", ".nsp1", ".nsp2"),),
    "Enigma":             ((".enigma1", ".enigma2"),),
    "MEW":                (("mew",),),
    "kkrunchy":           (("kkrunchy",),),
    "MoleBox":            ((".mbox",),),
    "Obsidium":           ((".obsidium",),),
    "PELock":             ((".pelock",),),
    "Yoda":               (("yc", ".yp"),),
}

_STANDARD_SECTIONS = {".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata",
                      ".edata", ".pdata", ".bss", ".tls", ".debug", ".didat",
                      ".xdata", ".00cfg", "code", "data", ".gfids"}


def _section_names(static: dict) -> list[str]:
    pe = static.get("pe") or {}
    return [(s.get("name") or "").strip().lower() for s in (pe.get("sections") or [])]


def match_sections(names: list[str]) -> str | None:
    """Exact packer match from section names, or None."""
    for packer, groups in _PACKER_SECTIONS.items():
        for group in groups:
            if any(any(sig in n for n in names) for sig in group):
                return packer
    return None


def identify(static: dict) -> dict:
    """Return {packer, confidence, indicators}. packer is None if not packed."""
    pe = static.get("pe") or {}
    names = _section_names(static)
    imports = pe.get("imports") or []
    entropy = static.get("entropy") or (pe.get("entropy") or 0)
    high_ent = pe.get("high_entropy_sections") or []

    hit = match_sections(names)
    if hit:
        return {"packer": hit, "confidence": "high",
                "indicators": [f"section signature for {hit}"]}

    # Heuristic: a protector that randomises its section names still leaves a
    # fingerprint — high entropy + a tiny import table + non-standard sections.
    packed = isinstance(entropy, (int, float)) and entropy >= 7.2
    if not packed:
        return {"packer": None, "confidence": None, "indicators": []}

    inds = [f"overall entropy {entropy}"]
    tiny_imports = 0 < len(imports) <= 3
    nonstd = [n for n in names if n and n not in _STANDARD_SECTIONS]
    if high_ent:
        inds.append(f"high-entropy section(s): {', '.join(high_ent)}")
    if tiny_imports:
        inds.append(f"minimal imports ({len(imports)} DLL)")
    if nonstd:
        inds.append(f"non-standard sections: {', '.join(nonstd[:5])}")

    strong = (tiny_imports or bool(high_ent) or bool(nonstd))
    return {"packer": "unknown/custom", "confidence": "medium" if strong else "low",
            "indicators": inds}

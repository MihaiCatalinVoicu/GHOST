#!/usr/bin/env python3
# Generate sdkmanager-style package.xml for the pinned SDK components, from the SAME
# repository2 manifests the pins.txt sha1 values come from (sdkmanager generates its
# local package.xml from these). Validated against WSL's sdkmanager-installed samples.
import xml.etree.ElementTree as ET
import re, sys, os

# ET refuses ns\d+ prefixes (reserved); serialize with placeholders, rename after.
PLACEHOLDER = {
    "http://schemas.android.com/repository/android/common/02": "p2",
    "http://schemas.android.com/repository/android/common/01": "p3",
    "http://schemas.android.com/repository/android/generic/01": "p4",
    "http://schemas.android.com/repository/android/generic/02": "p5",
    "http://schemas.android.com/sdk/android/repo/addon2/01": "p6",
    "http://schemas.android.com/sdk/android/repo/addon2/02": "p7",
    "http://schemas.android.com/sdk/android/repo/addon2/03": "p8",
    "http://schemas.android.com/sdk/android/repo/repository2/01": "p9",
    "http://schemas.android.com/sdk/android/repo/repository2/02": "p10",
    "http://schemas.android.com/sdk/android/repo/repository2/03": "p11",
    "http://schemas.android.com/sdk/android/repo/sys-img2/04": "p12",
    "http://schemas.android.com/sdk/android/repo/sys-img2/03": "p13",
    "http://schemas.android.com/sdk/android/repo/sys-img2/02": "p14",
    "http://schemas.android.com/sdk/android/repo/sys-img2/01": "p15",
}
NSMAP = {u: f"ns{n}" for u, n in [(u, p[1:]) for u, p in PLACEHOLDER.items()]}
for uri, p in PLACEHOLDER.items():
    ET.register_namespace(p, uri)

def fix_names(s):
    for uri, ph in PLACEHOLDER.items():
        s = s.replace(f"xmlns:{ph}=", f'xmlns:{NSMAP[uri]}=')
    s = re.sub(r"\bp(\d+):", r"ns\1:", s)
    return s

def collect_prefixes(xmlfile):
    """prefix -> uri as declared anywhere in the source manifest (iterparse start-ns)."""
    m = {}
    for _, (p, u) in ET.iterparse(xmlfile, events=("start-ns",)):
        m.setdefault(p, u)
    return m

def fix_xsi_type(s, pmap):
    """xsi:type values are QName STRINGS (ET can't see them); map the source prefix to ours."""
    def rep(mo):
        pfx, local = mo.group(1), mo.group(2)
        uri = pmap.get(pfx)
        if uri and uri in NSMAP:
            return f'xsi:type="{NSMAP[uri]}:{local}"'
        return mo.group(0)
    return re.sub(r'xsi:type="([^:"]+):([^"]+)"', rep, s)

REPO2 = {
    "cmdline-tools;12.0": ("/tmp/repository2-1.xml", "/opt/android-sdk/cmdline-tools/latest"),
    "platform-tools": ("/tmp/repository2-1.xml", "/opt/android-sdk/platform-tools"),
    "build-tools;37.0.0": ("/tmp/repository2-1.xml", "/opt/android-sdk/build-tools/37.0.0"),
    "build-tools;36.0.0": ("/tmp/repository2-1.xml", "/opt/android-sdk/build-tools/36.0.0"),
    "ndk;30.0.16248370": ("/tmp/repository2-1.xml", "/opt/android-sdk/ndk/30.0.16248370"),
    "platforms;android-37.0": ("/tmp/repository2-3.xml", "/opt/android-sdk/platforms/android-37.0"),
    "platforms;android-37.2": ("/tmp/repository2-3.xml", "/opt/android-sdk/platforms/android-37.2"),
}
OUTDIR = "/tmp/pkgxml"
os.makedirs(OUTDIR, exist_ok=True)

def lname(tag):
    return tag.rsplit("}", 1)[-1]

def find_child(el, name):
    for c in el:
        if lname(c.tag) == name:
            return c
    return None

for path, (xmlfile, dest) in REPO2.items():
    tree = ET.parse(xmlfile)
    root = tree.getroot()
    # license texts live at the top of the manifest
    licenses = {}
    for lic in root.iter():
        if lname(lic.tag) == "license" and lic.get("id"):
            licenses[lic.get("id")] = lic.text or ""
    pkg = None
    for rp in root.iter():
        if lname(rp.tag) == "remotePackage" and rp.get("path") == path:
            pkg = rp
            break
    if pkg is None:
        print(f"MISSING {path}")
        sys.exit(1)
    pmap = collect_prefixes(xmlfile)
    type_details = find_child(pkg, "type-details")
    revision = find_child(pkg, "revision")
    display = find_child(pkg, "display-name")
    uses = find_child(pkg, "uses-license")
    lic_id = uses.get("ref") if uses is not None else None
    lic_text = licenses.get(lic_id, "")

    parts = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>']
    decls = "".join(f' xmlns:{p}="{u}"' for u, p in NSMAP.items())
    parts.append(f"<ns2:repository{decls}>")
    if lic_id:
        parts.append(f'<license id="{lic_id}" type="text">{lic_text}</license>')
    parts.append(f'<localPackage path="{path}" obsolete="false">')
    parts.append(ET.tostring(type_details, encoding="unicode"))
    parts.append(ET.tostring(revision, encoding="unicode"))
    parts.append(ET.tostring(display, encoding="unicode"))
    if uses is not None:
        parts.append(f'<uses-license ref="{uses.get("ref")}"/>')
    parts.append("</localPackage></ns2:repository>")
    out = fix_xsi_type(fix_names("".join(parts)), pmap)
    fname = path.replace(";", "_").replace("/", "_") + ".xml"
    with open(os.path.join(OUTDIR, fname), "w", encoding="utf-8") as f:
        f.write(out)
    rev = ET.tostring(revision, encoding="unicode")
    print(f"OK {path} -> {fname} ({len(out)} bytes) rev={rev[:80]}")

#!/usr/bin/env python3
"""Check that every integration ships an icon in its own directory.

  python3 scripts/check_integration_icons.py            # report, exit 1 on a gap
  python3 scripts/check_integration_icons.py --list-ok  # also list the good ones

Each integration is expected to carry `<slug>/<slug>.svg`, or `<slug>/<slug>.png`
where the vendor publishes no vector. The icon lives beside the script so a
reader looking at one integration directory has everything that belongs to it.

This check is deliberately self-contained: it reads only this repository. The
tooling that POPULATES these files lives in the platform repo, because resolving
an integration slug to a vendor mark needs the private icon library and its
slug-to-vendor mapping. Adding a new integration therefore means running that
sync, not editing anything here.

Validation is calibrated against the icons already shipped rather than an ideal.
A missing viewBox or a file with nothing drawable in it will not render, so those
fail. A width attribute, a monochrome fill, or a few hundred bytes over the size
target are house preferences that plenty of good icons violate, so those warn --
a check that flags a fifth of a healthy set is one people learn to skip.
"""

import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIZE_TARGET = 3072


def validate_svg(path):
    """Return (errors, warnings) for an SVG icon."""
    try:
        body = open(path, encoding="utf-8").read()
    except (IOError, UnicodeDecodeError) as err:
        return (["unreadable: %s" % err], [])
    errors, warnings = [], []
    if "viewBox" not in body:
        errors.append("no viewBox, so it will not scale")
    if not re.search(r"<(path|circle|polygon|rect|ellipse|g)\b", body):
        errors.append("nothing drawable in it")
    # Only the ROOT <svg> element's width matters: it pins the rendered size and
    # fights the container the icon is drawn into. A width on an inner <rect> or
    # <use> is geometry -- stripping that would deform the icon -- so the match
    # is scoped to the opening tag rather than the whole file.
    root = re.search(r"<svg\b[^>]*>", body)
    if root and re.search(r"\bwidth\s*=", root.group(0)):
        warnings.append("root <svg> has a width attribute")
    if not re.search(r"#[0-9a-fA-F]{3,8}\b", body):
        warnings.append("no hex fill, renders monochrome")
    if len(body.encode("utf-8")) > SIZE_TARGET:
        warnings.append("%d bytes, over the %d target"
                        % (len(body.encode("utf-8")), SIZE_TARGET))
    return (errors, warnings)


def main(argv):
    catalog = os.path.join(REPO_ROOT, "docs", "integrations.json")
    entries = json.load(open(catalog, encoding="utf-8"))["integrationDetails"]

    ok, broken, warned, missing = [], [], [], []
    for entry in entries:
        slug = entry["integration"].rstrip("/").split("/")[-2]
        svg = os.path.join(REPO_ROOT, slug, slug + ".svg")
        png = os.path.join(REPO_ROOT, slug, slug + ".png")

        if os.path.exists(svg):
            errors, warnings = validate_svg(svg)
            (broken if errors else ok).append(
                (slug, "svg", "; ".join(errors) if errors else ""))
            if warnings:
                warned.append((slug, "; ".join(warnings)))
        elif os.path.exists(png):
            # A raster has no structure worth checking here; its presence is the
            # whole assertion. These exist only where no vendor vector does.
            ok.append((slug, "png", ""))
        else:
            missing.append(slug)

    print("%d integrations: %d with an icon, %d missing, %d invalid, %d with warnings"
          % (len(entries), len(ok) + len(broken), len(missing), len(broken), len(warned)))

    if "--list-ok" in argv:
        print("\npresent:")
        for slug, kind, _ in sorted(ok):
            print("  %s.%s" % (slug, kind))
    if broken:
        print("\nINVALID (these will not render):")
        for slug, kind, why in sorted(broken):
            print("  %-34s %s" % (slug + "." + kind, why))
    if warned and "--quiet" not in argv:
        print("\nwarnings (house preference, not failures):")
        for slug, why in sorted(warned):
            print("  %-34s %s" % (slug, why))
    if missing:
        print("\nNO ICON:")
        for slug in sorted(missing):
            print("  %s" % slug)
        print("\nPopulate these from the platform checkout that holds the icon")
        print("library, which is where the slug-to-vendor mapping lives:")
        print("  python3 scripts/sync_integration_icons.py <path-to-this-repo>")

    return 1 if (missing or broken) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Stamp assets/site.css with a content hash in every page.

Browsers cache the stylesheet for four hours (max-age=14400). Without a
hash in the URL, a visitor who has the old CSS and fetches new HTML gets
a broken header: markup that the cached stylesheet has no rules for.
That is not hypothetical, it happened. Run this after ANY change to
site.css, before deploying.
"""
import glob
import hashlib
import re
import sys

h = hashlib.sha256(open("assets/site.css", "rb").read()).hexdigest()[:10]
n = 0
for f in glob.glob("*.html"):
    s = open(f).read()
    new = re.sub(r'(href="(?:\./)?assets/site\.css)(\?v=[a-f0-9]+)?"',
                 rf'\1?v={h}"', s)
    if new != s:
        open(f, "w").write(new)
        n += 1
print(f"site.css?v={h} stamped on {n} page(s)")
sys.exit(0)

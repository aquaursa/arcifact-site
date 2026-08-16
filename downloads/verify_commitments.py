#!/usr/bin/env python3
"""Verify the Arcifact append-only commitment log.

    python3 verify_commitments.py commitments.json \
        --issuer-keys arcifact-issuer-keys.json

Checks, in order:
  1. every entry's hash recomputes from its own body;
  2. every entry carries the hash of the one before it, back to genesis,
     so no entry can be altered or removed without breaking the chain;
  3. entry numbers are consecutive and timestamps never go backwards;
  4. the head signature verifies against a key you supply OUT OF BAND.
     A key read from the log itself would prove nothing.

VERDICTS

  AUTHENTIC_CHAIN        the chain is intact AND the head signature
                         verified against the key you supplied.
  SELF_CONSISTENT_CHAIN  the chain is intact, but no signature check was
                         requested. Nothing is claimed about who wrote
                         it. Exit 0.
  INCOMPLETE             a signature check WAS requested and could not be
                         performed, for example because pynacl is not
                         installed. Exit non-zero, because you asked a
                         question this run could not answer.
  INVALID                a check failed. Exit non-zero.

The distinction matters more than it looks. An earlier version of this
tool printed CHAIN INTACT and exited 0 when pynacl was missing, even
with a corrupted signature, while asserting that the entries were the
ones that had been signed. That is exactly the fail-open behaviour this
project exists to catch, and it is why the verdict now separates
integrity from authenticity.

WHAT A VALID CHAIN DOES AND DOES NOT SHOW

Does: that the entries you are reading are the entries that were
signed, in that order, and that none has been edited or dropped.

Does NOT: that any timestamp is honest. The issuer controls the clock.
A signed chain can be produced all at once and dated freely.

The timestamps become hard to fake only through the ANCHOR. This file
is committed to a public git repository, so each head hash appears in a
commit hosted by a third party with a server-side date. To check that a
commitment really predates something, find the commit that introduced
that head and read ITS timestamp, not the one in this file:

    git log --oneline -S<head-hash> -- commitments.json

That check does not involve Arcifact at all, which is the point.

Requires Python 3.9+. pynacl only for the signature check.
"""
import argparse
import hashlib
import json
import sys

GENESIS = "0" * 64


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("log")
    ap.add_argument("--issuer-keys",
                    help="published key file, obtained out of band")
    a = ap.parse_args()
    log = json.load(open(a.log))
    fails, notes, unchecked = [], [], []

    if log.get("schema") != "arcifact-commitments/1":
        fails.append(f"unexpected schema {log.get('schema')!r}")

    entries = log.get("entries") or []
    if not entries:
        fails.append("no entries")
    prev = GENESIS
    last_utc = ""
    for i, e in enumerate(entries, 1):
        body = {k: v for k, v in e.items() if k != "entry_hash"}
        if hashlib.sha256(canon(body)).hexdigest() != e.get("entry_hash"):
            fails.append(f"entry {i}: hash does not recompute")
        if e.get("prev") != prev:
            fails.append(f"entry {i}: broken chain, expected prev "
                         f"{prev[:12]} got {str(e.get('prev'))[:12]}")
        if e.get("n") != i:
            fails.append(f"entry {i}: numbered {e.get('n')}")
        if e.get("utc", "") < last_utc:
            fails.append(f"entry {i}: timestamp goes backwards")
        last_utc = e.get("utc", "")
        prev = e.get("entry_hash")

    sig = log.get("signature")
    if not sig:
        notes.append("head is UNSIGNED: entries may have been appended "
                     "since the last signature")
    elif sig.get("head") != prev or sig.get("count") != len(entries):
        fails.append("signature covers a different head or count than "
                     "the entries present")
    elif not a.issuer_keys:
        notes.append("signature not checked: pass --issuer-keys with a "
                     "key obtained out of band. Integrity only is "
                     "reported; authenticity is NOT claimed")
    else:
        try:
            from nacl.signing import VerifyKey
            keys = json.load(open(a.issuer_keys))
            table = {k["key_id"]: k["public_key"]
                     for k in keys.get("keys", [])}
            pub = table.get(sig.get("key_id"))
            if not pub:
                fails.append(f"no published key for {sig.get('key_id')!r}")
            else:
                VerifyKey(bytes.fromhex(pub)).verify(
                    canon({"head": sig["head"], "count": sig["count"]}),
                    bytes.fromhex(sig["sig"]))
                notes.append(f"head signature verified against "
                             f"{sig['key_id']}")
        except ImportError:
            unchecked.append("pynacl not installed, so the signature you "
                             "asked to verify could not be checked. "
                             "Install it (pip install pynacl) and rerun; "
                             "until then authenticity is unknown")
        except Exception as exc:
            fails.append(f"signature verification failed: {str(exc)[:80]}")

    signature_verified = any("signature verified" in n for n in notes)
    print(f"entries            {len(entries)}")
    print(f"head               {prev[:32]}")
    anchor = log.get("anchor") or {}
    if anchor:
        print(f"anchor             {anchor.get('kind')} "
              f"{anchor.get('repository','')}")
    for n in notes:
        print(f"  note             {n}")
    for u in unchecked:
        print(f"  NOT CHECKED      {u}")
    for f in fails:
        print(f"  FAILED           {f}")

    if fails:
        verdict, code = "INVALID", 1
    elif unchecked:
        # a question was asked that this run could not answer
        verdict, code = "INCOMPLETE", 2
    elif signature_verified:
        verdict, code = "AUTHENTIC_CHAIN", 0
    else:
        verdict, code = "SELF_CONSISTENT_CHAIN", 0
    print(f"VERDICT            {verdict}")
    if verdict == "AUTHENTIC_CHAIN":
        print("                   The entries you read are the entries the "
              "issuer signed, in")
        print("                   order and unaltered. Timestamps remain the "
              "issuer's word:")
        print("                   date the head against public git history.")
    elif verdict == "SELF_CONSISTENT_CHAIN":
        print("                   The chain is internally consistent. NOTHING "
              "is claimed about")
        print("                   who produced it: no signature was checked. "
              "Pass --issuer-keys")
        print("                   with a key obtained out of band to "
              "establish authenticity.")
    elif verdict == "INCOMPLETE":
        print("                   Integrity holds, authenticity is UNKNOWN. "
              "Do not treat this")
        print("                   as a verified log.")
    return code


if __name__ == "__main__":
    sys.exit(main())

# Vendor names on Product badges

NVD and CVE records often name a Product without its vendor ("Storage Scale"). The page puts the vendor in
front ("IBM Storage Scale") when the vendor is in `web/vendors.json`, the one list of vendor spellings. The page
(`web/board.mjs`) and the collector (`collector/incidents.py`) both read it; there is no other table.

## Add a vendor

1. Look at `unknown_vendors.json` in the store (`web/data/` locally): each cycle lists the vendors of the last 90
   days that are missing from the file and whose Product names do not already say the vendor, with one example name.
2. Add a line to `web/vendors.json`: the key exactly as listed (the part of the Product id before `:`, lowercase,
   for example `getgrav` or `red_hat`), the value as the vendor writes its own name (`"dlink": "D-Link"`).
   Check the spelling on the vendor's own site; do not guess casing.
3. Run `node --test` and `python -m unittest discover tests`. No other change is needed; the next cycle drops the
   vendor from `unknown_vendors.json`.

A name that already contains the spelling is shown as it is (`"IBM QRadar"` stays, never "IBM IBM QRadar").
Vendors not in the file are never guessed: their names stay bare until someone adds them.

=======
# Falcon — V3 

**Falcon** is a lightweight, self-contained OSINT reconnaissance toolkit designed to work. It's ideal for small recon jobs, red-team recon, teaching, and as a modular base you can extend later with optional plugins.

> ⚠️ **Ethics & Legal**: Use Falcon only on targets you own or have explicit written permission to test. The author and contributors are **not** responsible for misuse.
>>>>>>> d61199f (Falcon V3 update)

---

## Highlights

* Single-file executable: `falcon` (or `falcon.py`) — easy to copy and run.
* No paid API keys required. Avoids reliance on Shodan/HIBP/paid services.
* Built-in features:

  * WHOIS lookup
  * DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME)
  * Basic IP analysis (free ipinfo fallback + threaded port scanner)
  * Phone number analysis (uses `phonenumbers` + carrier + region + Folium map)
  * Username enumeration across common social platforms (simple profile checks)
  * Small subdomain brute-force using a built-in wordlist
* Outputs JSON reports into `./reports/` and saves simple Folium map HTML files for phone scans.

---

## Requirements

This project targets Python 3.8+.

Install runtime dependencies:

```bash
python -m pip install requests python-whois dnspython phonenumbers folium pycountry
```

Or use the provided `requirements.txt` (recommended in a project repo):

```
requests
python-whois
dnspython
phonenumbers
folium
pycountry
```

---

## Quickstart (example)

Save the single-file script as `falcon` (or `falcon.py`) and make it executable:

```bash
chmod +x falcon
./falcon -d example.com -i 8.8.8.8 -u someuser -p +237600000000 --subdomains
```

### Example CLI options

* `-d`, `--domain` — run WHOIS + DNS (and optionally subdomain bruteforce)
* `-i`, `--ip` — run IP geo lookup + port scan
* `-u`, `--username` — username enumeration across platforms
* `-p`, `--phone` — local phone analysis using `phonenumbers` (optionally saves a Folium map)
* `--subdomains` — enable builtin brute force when `--domain` is provided

All reports are saved to `./reports/` (JSON files, and HTML maps for phone scans).

---

## Notes & Limitations

* **No precise mobile geolocation.** Phone maps are centered on country centroids only — this is by design and avoids any false claims about precise location. Precise carrier-level geolocation requires telco data (not available without contracts and legal process).
* **Free IP lookups.** The script uses a lightweight fallback (ipinfo.io free endpoint) when available — accuracy varies. For local-only operation you can replace this with a local GeoIP DB (MaxMind GeoLite2 — note their license).
* **WHOIS may vary by TLD.** The `python-whois` library depends on whois servers and parsing; results may be partial for some new gTLDs.
* **Username enumeration is basic.** It only checks HTTP status and redirects. For deeper analysis (profile scraping, post history), add platform-specific scrapers or API integrations.

---

## Extending Falcon

The single-file approach is convenient for quick use, but I recommend splitting into modules for larger projects. Good extension ideas:

* Add a plugin loader (drop-in `plugins/` where each plugin exposes `register(args, session, result)`)
* Replace threaded port scans with async scanning using `asyncio` + `aiohttp` for better concurrency
* Add optional paid integrations gated behind environment variables (Shodan/HIBP) — keep them as optional plugins
* Add caching (SQLite) to avoid repeated queries and to store historical results

---

## Troubleshooting

* If a WHOIS lookup fails, try running the script from a different network or double-check the domain spelling.
* If Folium maps don’t open, make sure the file exists under `./reports/` and open it with a browser (`file://` path).
* Slow subdomain checks? Use a smaller wordlist or reduce thread count.

---

## Contribute & Contact

PRs, issues, and suggestions are welcome. If you want help customizing Falcon for your workflow (e.g., adding a plugin or a Dockerfile), open an issue on the GitHub repo.

GitHub: [https://github.com/6lackRaven](https://github.com/6lackRaven)

Telegram: https://t.me/RavenObsidian

Facebook: Raven Obsidian

Youtube: Raven Obsidian
---

## License

This project is provided under the MIT license. See `LICENSE` for details.

---

## Donation

```
btc:  bc1qvc8y7z2jguzr7e3fvwyf09l3me94mqk06nz3hj
usdt:  0x58bC732d4279321F1E4A8cA57eD2Ad16ed5A2e15
Sol:  E7x7ak3H6ob2eHbgsbfgVXpEJyVqMPUFPBtkuEUKj2cq
```


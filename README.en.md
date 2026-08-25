# BIN lookup API — card issuer, brand and country by BIN/IIN

[Русский](README.md) · **English**

Ready-to-run examples for the **BIN lookup API** in six languages: **Python, TypeScript (Node.js), Go, Java, C#, PHP.**
Identify the **card issuer by BIN** — pass the first 6–8 digits (**BIN / IIN check**) and get the payment scheme, card type and category, issuing bank, **card country detection** and currency. Plus **payment fraud prevention**: match the card country against the payer's IP country.

Every example **runs out of the box — no signup, no key, no card.** A public demo key is baked in.

```bash
git clone https://github.com/atlorium-api/bin-lookup-api-client
cd bin-lookup-api-client/python && pip install -r requirements.txt && python main.py 45717360 8.8.8.8
```

> The demo key returns **realistic mock data**, not real BIN records — which is why the issuer name looks generated. That is the point: you can write and test the integration before paying. Swap in a live key and the same code returns real issuer data.

---

## ⚠️ Send the BIN, never the full card number

**Send the first 6–8 digits only. The full card number (PAN) must not leave your perimeter.**

This is basic **PCI DSS** hygiene: a BIN is not cardholder data, a full PAN is — and a PAN must not be logged, forwarded to third-party services, or stored without certification.

That is why all six examples ship a `normalizeBin()` function that **truncates the input to 8 digits before the request goes out**. Even if a full PAN from your checkout form is passed in by accident, only the BIN leaves the process:

```bash
python main.py 4571736012345678   # the wire request is GET /api/bin/45717360
```

## What it is for

Checkout anti-fraud, payment routing (pick an acquirer by country and scheme), payment-form UX (show the scheme icon, force 3-D Secure), card-mix analytics, blocking prepaid cards in subscription products.

The examples do not just print JSON — they **apply** it. Each ships an `assessCheckoutRisk()` function that turns a BIN card plus the payer's IP into a verdict: does the card country match the IP country (a classic fraud signal), is the card prepaid (elevated chargeback risk), is the IP blocklisted, is the issuer unknown, is the card commercial or consumer.

## Quick start

Try the API without cloning anything:

```bash
curl -H "Authorization: Bearer ak_sandbox_demo_mockdata_v1" \
     "https://atlorium.com/api/bin/45717360?customerIp=8.8.8.8"
```

| Language | Run | Requires |
|----------|-----|----------|
| [Python](python/) | `pip install -r requirements.txt && python main.py` | Python 3.10+ |
| [TypeScript / Node.js](node/) | `npm install && npm start` | Node.js 20+ |
| [Go](go/) | `go run .` | Go 1.22+ |
| [Java](java/) | `java Main.java` | JDK 17+ (no dependencies) |
| [C#](csharp/) | `dotnet run` | .NET 8+ |
| [PHP](php/) | `php main.php` | PHP 8.1+ |

Pass your own BIN and payer IP as arguments: `python main.py 48334884 8.8.8.8`

## Authentication

The key goes in the `Authorization` header:

```
Authorization: Bearer YOUR_KEY
```

| Key | Behaviour |
|-----|-----------|
| `ak_sandbox_demo_mockdata_v1` | **Demo key.** Public, shared by everyone. Returns mocks, charges nothing, needs no account. Responses are deterministic, so you can assert on them in tests. |
| Live key | Real BIN directory data. Get one at [atlorium.com](https://atlorium.com) |

Switching to a live key requires **no code changes** — every example reads an environment variable:

```bash
export ATLORIUM_API_KEY="ak_your_live_key"
```

Every sandbox response carries the header `X-Atlorium-Sandbox: true`, so mock data can never be mistaken for real data.

## Endpoints

Base URL: `https://atlorium.com`

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/bin/{bin}` | Card details by BIN/IIN + anti-fraud check against the payer's IP |
| `GET` | `/api/bin/validate/{bin}` | BIN format validation (digits only, length 6/8/10) |

### `GET /api/bin/{bin}`

| Parameter | In | Type | Description |
|-----------|----|------|-------------|
| `bin` | path | string | BIN/IIN — the first **6, 8 or 10** digits of the card number. Longer is more accurate; 8 is the sweet spot between accuracy and PCI hygiene. |
| `customerIp` | query | string | **(Optional)** The payer's IP address. When present, the response gains anti-fraud fields: country/city by IP, whether the IP country matches the card country, and blocklist checks. |

### `GET /api/bin/validate/{bin}`

| Parameter | In | Type | Description |
|-----------|----|------|-------------|
| `bin` | path | string | The BIN to check (6, 8 or 10 digits; spaces and separators are ignored) |

It validates the **format, not the existence** of the BIN: `isValidFormat: true` does not guarantee an issuer will be found.

## Response fields

### `GET /api/bin/{bin}` → `BinLookupResult`

| Field | Type | Meaning |
|-------|------|---------|
| `valid` | bool | **The key field.** Whether the BIN exists in the directory |
| `binNumber` | string | The BIN the lookup ran on |
| `binLength` | int | 6, 8 or 10 |
| `cardBrand` | string | Payment scheme: VISA, MASTERCARD, MIR… |
| `cardType` | string | DEBIT, CREDIT, CHARGE CARD… |
| `cardCategory` | string | STANDARD, GOLD, PLATINUM, BUSINESS… |
| `country` / `countryCode` / `countryCode3` | string | **Card country**: name, ISO-2, ISO-3 |
| `currencyCode` | string | Card currency, ISO-4217 |
| `issuer` | string | Issuing bank |
| `issuerWebsite` / `issuerPhone` | string | Issuer's website and phone |
| `isCommercial` | bool | Commercial / corporate card rather than consumer |
| `isPrepaid` | bool | **Risk flag.** Prepaid (including virtual) card |
| `isReloadable` | bool | Whether the card can be topped up. `false` for single-use cards |
| `hasCustomerIp` | bool | Whether `customerIp` was supplied — i.e. whether the fields below are filled |
| `ipMatchesBin` | bool | **The main anti-fraud flag.** Payer's IP country matches the card country |
| `ipCountry` / `ipCountryCode` / `ipCountryCode3` | string | Country by the payer's IP |
| `ipRegion` / `ipCity` | string | Region and city by IP |
| `ipBlocklisted` | bool | The IP appears on blocklists |
| `ipBlocklists` | array | Which blocklists exactly |
| `elapsedMs` | int | Server-side processing time, ms |

### `GET /api/bin/validate/{bin}` → `BinFormatValidationResult`

| Field | Type | Meaning |
|-------|------|---------|
| `normalizedBin` | string | The BIN after stripping spaces and separators |
| `isValidFormat` | bool | Format is valid (digits only, length 6/8/10) |
| `binLength` | int | Length of the normalized BIN |
| `message` | string | Human-readable explanation |

## Error handling

| Code | Cause | What to do |
|------|-------|------------|
| `400` | Malformed BIN | Must be 6, 8 or 10 digits, digits only |
| `401` | Key missing, expired or invalid | Check the `Authorization` header |
| `402` | Insufficient credit balance | Top up at [atlorium.com](https://atlorium.com) |
| `429` | Rate limit exceeded | Retry with backoff |
| `503` | Service temporarily unavailable | Retry later. **You are not charged for our failures** |

Note: a syntactically valid BIN that is simply absent from the directory returns `200 OK` with `valid: false` — that is not an error. All six examples map the codes above to human-readable causes — see the `AtloriumError` class.

## Pricing

**Pay-as-you-go, no subscription** — you pay per successful request. Current prices: **[atlorium.com/pricing](https://atlorium.com/pricing)**

## FAQ

**How many digits should I send — 6, 8 or 10?** BINs were historically 6 digits, but the schemes moved to 8-digit BINs, so 6 digits identify the issuer only coarsely. Use **8**. The API accepts 10, but that is over half the card number — a needless PCI risk for a marginal accuracy gain.

**Does it tell me whether the card is valid and funded?** No, and that is a real boundary. BIN lookup answers "what kind of card is this and whose bank issued it", not "is the card live, stolen, or funded". Card validity is the acquirer's job (plus the Luhn checksum); balance is an authorization request.

**What does `ipMatchesBin: false` mean?** The card was issued in one country and the payment comes from an IP in another. It is a risk signal, not a verdict — tourists, expats and VPN users look exactly like this. Feed it into a score, do not decline on it alone.

**How is this better than free BIN databases?** Open datasets are updated irregularly, miss newer 8-digit BINs, and carry no IP anti-fraud data at all. Here both signals arrive in a single request, with an SLA and no restrictions on commercial use.

## Other Atlorium APIs

The same account and the same key also give you:

- [AML crypto screening](https://github.com/atlorium-api/aml-crypto-screening-api-client) — risk score, sanctions, PEP
- [SWIFT/BIC](https://github.com/atlorium-api/swift-bic-api-client) — ISO-9362 code parsing and pre-transfer checks
- [IP profile](https://github.com/atlorium-api/ip-geolocation-api-client) — geo, ASN, VPN/proxy/Tor detection
- [CBR BIC directory](https://github.com/atlorium-api/cbr-bik-api-client) — bank details and payment account checksum
- [CIDR calculator](https://github.com/atlorium-api/cidr-subnet-calculator-api-client) — split networks into subnets, IP range membership
- [EGRUL/EGRIP](https://github.com/atlorium-api/egrul-api-client) — Russian company check by INN/OGRN: status, address, capital

Full catalogue: [atlorium.com](https://atlorium.com)

## Links

- **API reference (Swagger):** [atlorium.com/binAPI](https://atlorium.com/binAPI)
- **OpenAPI spec:** [bin_en-US.json](https://atlorium.com/openapi/bin_en-US.json)
- **Support:** support@atlorium.com

## License

[MIT](LICENSE)

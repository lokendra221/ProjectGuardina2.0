
#!/usr/bin/env python3
import re, json, csv, sys, os, ast, hashlib

# ---------------------- Regexes ----------------------
PHONE_RE = re.compile(r'(?<!\d)(\d{10})(?!\d)')
AADHAR_RE = re.compile(r'(?<!\d)(\d{4})[\s-]?(\d{4})[\s-]?(\d{4})(?!\d)')
PASSPORT_RE = re.compile(r'(?i)\b([A-PR-WY])[0-9]{7}\b')  # e.g., P1234567
EMAIL_RE = re.compile(r'\b([a-zA-Z0-9_.%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b')
UPI_RE = re.compile(r'\b([a-zA-Z0-9._-]{2,})@([a-zA-Z]{2,}|[a-zA-Z0-9]{2,})\b')
IPV4_RE = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')
PIN_RE = re.compile(r'(?<!\d)\d{6}(?!\d)')

def mask_phone(s):
    m = PHONE_RE.search(s or '')
    if not m: 
        return s
    val = m.group(1)
    return s.replace(val, val[:2] + 'XXXXXX' + val[-2:])

def mask_aadhar(s):
    m = AADHAR_RE.search(s or '')
    if not m: 
        return s
    val = ''.join(m.groups())
    masked = 'XXXX XXXX ' + val[-4:]
    return AADHAR_RE.sub(masked, s)

def mask_passport(s):
    return PASSPORT_RE.sub(lambda x: x.group(1).upper() + 'XXXXXXX', s or '')

def mask_email(s):
    def repl(m):
        local, dom = m.group(1), m.group(2)
        keep = local[:2]
        return f'{keep}XXX@{dom}'
    return EMAIL_RE.sub(repl, s or '')

def mask_upi(s):
    def repl(m):
        user, prov = m.group(1), m.group(2)
        keep = user[:2]
        return f'{keep}XXX@{prov}'
    return UPI_RE.sub(repl, s or '')

def mask_ip(ip):
    return IPV4_RE.sub(lambda m: '.'.join(m.group(1).split('.')[:3]) + '.XXX', ip or '')

def mask_name(name):
    parts = re.split(r'\s+', name.strip()) if isinstance(name, str) else []
    masked = []
    for p in parts:
        if not p: continue
        masked.append(p[0].upper() + 'XXX')
    return ' '.join(masked) if masked else name

def mask_address(addr):
    if not isinstance(addr, str): 
        return addr
    # Keep city/state words but redact numbers and street/body
    # Simpler: full redact to ensure safety
    return '[REDACTED_ADDRESS]'

def mask_device_id(did):
    if not isinstance(did, str): 
        did = str(did) if did is not None else ''
    if len(did) <= 3:
        return 'XXX'
    return did[:3] + '...' + did[-2:]

def parse_json_cell(cell):
    if cell is None:
        return {}
    txt = str(cell).strip()
    if not txt:
        return {}
    # Try strict JSON first
    try:
        return json.loads(txt)
    except Exception:
        pass
    # Try python literal (handles single quotes)
    try:
        return ast.literal_eval(txt)
    except Exception:
        pass
    # Try forgiving replace of single quotes
    try:
        return json.loads(txt.replace("'", '"'))
    except Exception:
        return {}

def is_full_name(val):
    if not isinstance(val, str): 
        return False
    parts = [p for p in re.split(r'\s+', val.strip()) if p]
    return len(parts) >= 2

def has_valid_email(val):
    if not isinstance(val, str): 
        return False
    return EMAIL_RE.search(val) is not None

def looks_like_address(d):
    # We consider an address present if 'address' non-empty OR (city and pin_code) pair
    addr = d.get('address')
    if isinstance(addr, str) and len(addr.strip()) >= 8:
        return True
    city = d.get('city')
    pin_code = str(d.get('pin_code') or '')
    if (city and PIN_RE.search(pin_code)):
        return True
    return False

def value_as_str(v):
    if v is None:
        return ''
    if isinstance(v, (dict, list)):
        try:
            return json.dumps(v, ensure_ascii=False)
        except Exception:
            return str(v)
    return str(v)

def detect_and_redact(record_map):
    d = dict(record_map)  # copy to read
    red = dict(record_map)  # we'll mutate for redaction
    ispii = False

    # ---------- Standalone PII ----------
    # phone (10 digit) : keys that can hold phone-like info
    for k in ['phone', 'contact']:
        val = value_as_str(d.get(k))
        if PHONE_RE.search(val):
            ispii = True
            red[k] = mask_phone(val)

    # aadhar
    if 'aadhar' in d:
        val = value_as_str(d.get('aadhar'))
        if AADHAR_RE.search(val):
            ispii = True
            red['aadhar'] = mask_aadhar(val)

    # passport
    if 'passport' in d:
        val = value_as_str(d.get('passport'))
        if PASSPORT_RE.search(val):
            ispii = True
            red['passport'] = mask_passport(val)

    # upi_id
    if 'upi_id' in d:
        val = value_as_str(d.get('upi_id'))
        if UPI_RE.search(val):
            ispii = True
            red['upi_id'] = mask_upi(val)

    # ---------- Combinatorial PII ----------
    signals = set()

    # name (full)
    if is_full_name(d.get('name')):
        signals.add('name')

    # email
    if has_valid_email(d.get('email')):
        signals.add('email')

    # address
    if looks_like_address(d):
        signals.add('address')

    # device or ip (will only count if paired later)
    device_present = bool(d.get('device_id'))
    ip_present = bool( has_valid_email(d.get('ip_address')) == False and IPV4_RE.search(value_as_str(d.get('ip_address') or '')) )

    if device_present or ip_present:
        signals.add('device_or_ip')

    # If we have at least two from the set {name, email, address, device/ip}, it's PII
    # Special constraint: device/ip alone should not count; with another user context it counts (already enforced).
    if len(signals.intersection({'name','email','address','device_or_ip'})) >= 2:
        ispii = True
        # redact the components present
        if 'name' in signals and d.get('name'):
            red['name'] = mask_name(value_as_str(d.get('name')))
        if 'email' in signals and d.get('email'):
            red['email'] = mask_email(value_as_str(d.get('email')))
        if 'address' in signals and d.get('address'):
            red['address'] = mask_address(value_as_str(d.get('address')))
        if 'device_or_ip' in signals:
            if d.get('ip_address'):
                red['ip_address'] = mask_ip(value_as_str(d.get('ip_address')))
            if d.get('device_id'):
                red['device_id'] = mask_device_id(value_as_str(d.get('device_id')))

    # ---------- Non-PII guardrails ----------
    # Ensure we don't mark PII for standalone items from combinatorial list appearing alone.
    if not ispii:
        # if only email present alone -> not PII and do not redact
        # if only first_name or last_name present -> not PII
        pass

    return ispii, red

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector_full_candidate_name.py <input_csv_path>")
        sys.exit(1)

    in_path = sys.argv[1]
    out_path = 'redacted_output_candidate_full_name.csv'

    # input has columns: record_id, Data_json
    with open(in_path, 'r', encoding='utf-8') as f, open(out_path, 'w', encoding='utf-8', newline='') as out:
        reader = csv.DictReader(f)
        fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            rec_id = row.get('record_id') or row.get('Record_ID') or row.get('id') or ''
            data_json = row.get('Data_json') or row.get('data_json') or row.get('payload') or '{}'
            d = parse_json_cell(data_json)
            ispii, red = detect_and_redact(d)
            # Only redact JSON fields that were changed if ispii True; else leave original
            out_obj = red if ispii else d
            writer.writerow({
                'record_id': rec_id,
                'redacted_data_json': json.dumps(out_obj, ensure_ascii=False),
                'is_pii': str(bool(ispii))
            })

    print(f'Wrote: {out_path}')

if __name__ == '__main__':
    main()

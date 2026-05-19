import json


def extract_json_payload(raw: str) -> dict | None:
    text = raw.strip()
    try:
        payload = json.loads(text)
        return payload if isinstance(payload, dict) else None
    except Exception:
        pass

    if text.startswith('```'):
        lines = text.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == '```':
            body = '\n'.join(lines[1:-1]).strip()
            try:
                payload = json.loads(body)
                return payload if isinstance(payload, dict) else None
            except Exception:
                pass

    s, e = text.find('{'), text.rfind('}')
    if s != -1 and e > s:
        try:
            payload = json.loads(text[s:e + 1])
            return payload if isinstance(payload, dict) else None
        except Exception:
            return None
    return None

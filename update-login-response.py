from pathlib import Path

p = Path("server.js")
s = p.read_text(encoding="utf-8")

old = '''                message:
                    "Login successful.",

                token,

                user: {'''

new = '''                message:
                    "Login successful.",

                token,

                requiresActivation,

                user: {'''

if old not in s:
    raise SystemExit("TARGET_RESPONSE_NOT_FOUND")

s = s.replace(old, new, 1)

p.write_text(s, encoding="utf-8")

print("LOGIN_RESPONSE_UPDATED")

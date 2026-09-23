from pathlib import Path

p = Path(".\server.js")
s = p.read_text(encoding="utf-8")

marker = "/* =========================================================\n   USER REGISTER\n========================================================= */"

first = s.find(marker)
second = s.find(marker, first + len(marker))

if first == -1 or second == -1:
    raise SystemExit("Could not locate two USER REGISTER blocks.")

login = s.find("/* =========================================================\n   USER LOGIN", second)

if login == -1:
    raise SystemExit("Could not locate USER LOGIN after the old register block.")

s = s[:second] + s[login:]

p.write_text(s, encoding="utf-8")

print("Old USER REGISTER block removed successfully.")

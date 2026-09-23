from pathlib import Path

p = Path(".\server.js")
s = p.read_text(encoding="utf-8")

old = '''        "id,username,email,full_name,is_active,activation_expires_at,max_devices,created_at,updated_at"
'''

new = '''        "id,username,email,phone,full_name,is_active,is_activated,activation_expires_at,max_devices,created_at,updated_at"
'''

if old not in s:
    raise SystemExit("ME select line not found.")

s = s.replace(old, new, 1)

marker = '''    if (!user.is_active) {
'''

insert = '''    if (user.is_activated === false) {
        return res.status(403).json({
            success: false,
            message: "Account activation is required.",
            requiresActivation: true,
            userId: user.id,
            username: user.username,
            email: user.email || null,
            phone: user.phone || null
        });
    }


'''

if marker not in s:
    raise SystemExit("ME active-check marker not found.")

s = s.replace(marker, insert + marker, 1)

p.write_text(s, encoding="utf-8")

print("AUTH ME updated successfully.")

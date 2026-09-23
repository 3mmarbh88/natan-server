from pathlib import Path

p = Path(".\server.js")
s = p.read_text(encoding="utf-8")

old = '''            if (!user.is_active) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Your NATAN account is disabled."
                });
            }


            if (
                user.activation_expires_at &&
                new Date(
                    user.activation_expires_at
                ) <= new Date()
            ) {'''

new = '''            if (!user.is_active) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Your NATAN account is disabled."
                });
            }


            if (user.is_activated === false) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Account activation is required.",
                    requiresActivation: true,
                    userId: user.id,
                    username: user.username,
                    email: user.email || null,
                    phone: user.phone || null
                });
            }


            if (
                user.activation_expires_at &&
                new Date(
                    user.activation_expires_at
                ) <= new Date()
            ) {'''

if old not in s:
    raise SystemExit("LOGIN activation insertion point not found.")

s = s.replace(old, new, 1)

p.write_text(s, encoding="utf-8")

print("USER LOGIN activation check added successfully.")

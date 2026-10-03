from pathlib import Path

p = Path("server.js")
s = p.read_text(encoding="utf-8")

old = '''            if (
                user.is_activated === false
            ) {

                return res.status(403).json({

                    success:
                        false,

                    message:
                        "Account activation is required.",

                    requiresActivation:
                        true,

                    userId:
                        user.id,

                    username:
                        user.username,

                    email:
                        user.email || null,

                    phone:
                        user.phone || null
                });
            }


'''

if old not in s:
    raise SystemExit("ME_ACTIVATION_BLOCK_NOT_FOUND")

s = s.replace(old, "", 1)

p.write_text(s, encoding="utf-8")

print("ME_ALLOW_UNACTIVATED_FIXED")

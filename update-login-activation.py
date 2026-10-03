from pathlib import Path

p = Path("server.js")
s = p.read_text(encoding="utf-8")

old = '''            /* Activation required */

            if (
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

new = '''            /* Activation status */

            const requiresActivation =
                user.is_activated === false;

'''

if old not in s:
    raise SystemExit("TARGET_BLOCK_NOT_FOUND")

s = s.replace(old, new, 1)

p.write_text(s, encoding="utf-8")

print("LOGIN_ACTIVATION_CHECK_UPDATED")

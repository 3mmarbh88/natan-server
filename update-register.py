from pathlib import Path
import re

p = Path("server.js")
s = p.read_text(encoding="utf-8")

pattern = r'/\* =========================================================\s+USER REGISTER\s+========================================================= \*/.*?(?=/\* =========================================================\s+USER LOGIN\s+========================================================= \*/)'

new_block = r'''/* =========================================================
   USER REGISTER
========================================================= */

app.post(
    "/api/auth/register",
    async (req, res) => {

        try {

            const {
                fullName,
                email,
                phone,
                password,
                deviceId,
                deviceName,
                platform,
                appVersion
            } = req.body;


            const cleanFullName =
                fullName === undefined ||
                fullName === null
                    ? ""
                    : String(fullName).trim();

            const cleanEmail =
                normalizeEmail(email);

            const cleanPhone =
                phone === undefined ||
                phone === null
                    ? ""
                    : String(phone).trim();


            /* Required fields */

            if (!cleanFullName) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Full name is required."
                });
            }


            if (!cleanEmail) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Email is required."
                });
            }


            if (!cleanPhone) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Phone number is required."
                });
            }


            if (
                !password ||
                String(password).length < 6
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Password must contain at least 6 characters."
                });
            }


            /* Check email */

            const {
                data: existingEmail,
                error: emailError
            } =
                await supabase
                    .from("natan_users")
                    .select("id")
                    .eq(
                        "email",
                        cleanEmail
                    )
                    .maybeSingle();


            if (emailError) {

                return res.status(500).json({
                    success: false,
                    message:
                        emailError.message
                });
            }


            if (existingEmail) {

                return res.status(409).json({
                    success: false,
                    message:
                        "Email already exists."
                });
            }


            /* Check phone */

            const {
                data: existingPhone,
                error: phoneError
            } =
                await supabase
                    .from("natan_users")
                    .select("id")
                    .eq(
                        "phone",
                        cleanPhone
                    )
                    .maybeSingle();


            if (phoneError) {

                return res.status(500).json({
                    success: false,
                    message:
                        phoneError.message
                });
            }


            if (existingPhone) {

                return res.status(409).json({
                    success: false,
                    message:
                        "Phone number already exists."
                });
            }


            /*
             * New users no longer enter a username.
             *
             * The server generates an internal username
             * from the phone number. Existing accounts keep
             * their current usernames.
             */

            let generatedUsername =
                cleanPhone
                    .replace(/[^\dA-Za-z]/g, "")
                    .toLowerCase();

            if (!generatedUsername) {

                generatedUsername =
                    cleanEmail
                        .split("@")[0]
                        .replace(/[^a-zA-Z0-9._-]/g, "")
                        .toLowerCase();
            }


            if (generatedUsername.length < 3) {

                generatedUsername =
                    `natan_${crypto.randomBytes(4).toString("hex")}`;
            }


            /* Make sure generated username is unique */

            const {
                data: existingUsername
            } =
                await supabase
                    .from("natan_users")
                    .select("id")
                    .eq(
                        "username",
                        generatedUsername
                    )
                    .maybeSingle();


            if (existingUsername) {

                generatedUsername =
                    `${generatedUsername}_${crypto.randomBytes(3).toString("hex")}`;
            }


            const passwordHash =
                await bcrypt.hash(
                    String(password),
                    12
                );


            /*
             * Account is created but NOT ACTIVATED.
             *
             * is_active = true:
             *   The administrator has not disabled the account.
             *
             * is_activated = false:
             *   The user still needs an activation code.
             */

            const {
                data: user,
                error: userError
            } =
                await supabase
                    .from("natan_users")
                    .insert({

                        username:
                            generatedUsername,

                        email:
                            cleanEmail,

                        phone:
                            cleanPhone,

                        password_hash:
                            passwordHash,

                        full_name:
                            cleanFullName,

                        is_active:
                            true,

                        is_activated:
                            false,

                        activation_expires_at:
                            null,

                        max_devices:
                            1
                    })
                    .select(
                        "id,username,email,phone,full_name,is_active,is_activated,activation_expires_at,max_devices,created_at,updated_at"
                    )
                    .single();


            if (userError) {

                return res.status(500).json({
                    success: false,
                    message:
                        userError.message
                });
            }


            /* Register device */

            if (deviceId) {

                await supabase
                    .from("natan_devices")
                    .insert({

                        user_id:
                            user.id,

                        device_id:
                            String(deviceId),

                        device_name:
                            deviceName || null,

                        platform:
                            platform || null,

                        app_version:
                            appVersion || null,

                        is_active:
                            true
                    });
            }


            /* Activity log */

            await supabase
                .from("natan_activity_logs")
                .insert({

                    user_id:
                        user.id,

                    action:
                        "register",

                    description:
                        "NATAN account registered and awaiting activation.",

                    device_id:
                        deviceId || null
                });


            return res.status(201).json({

                success:
                    true,

                message:
                    "Account created successfully. Activation is required before login.",

                requiresActivation:
                    true,

                user: {

                    id:
                        user.id,

                    username:
                        user.username,

                    email:
                        user.email,

                    phone:
                        user.phone,

                    fullName:
                        user.full_name,

                    active:
                        user.is_active,

                    isActivated:
                        user.is_activated,

                    expiresAt:
                        null,

                    maxDevices:
                        user.max_devices
                }
            });


        } catch (error) {

            console.error(
                "Register error:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Server error."
            });
        }
    }
);


'''

match = re.search(pattern, s, flags=re.S)

if not match:
    raise SystemExit("USER REGISTER block was not found. No changes were made.")

s = s[:match.start()] + new_block + s[match.start():]

p.write_text(s, encoding="utf-8")

print("USER REGISTER block updated successfully.")

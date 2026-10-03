from pathlib import Path

p = Path("server.js")
s = p.read_text(encoding="utf-8")

start_marker = 'app.post(\n    "/api/auth/register",'
end_marker = '\n\n/* =========================================================\n   USER LOGIN'

start = s.index(start_marker)
end = s.index(end_marker, start)

new_route = r'''app.post(
    "/api/auth/register",
    loginLimiter,
    async (req, res) => {

        try {

            const {
                username,
                fullName,
                email,
                phone,
                password,
                deviceId,
                deviceName,
                platform,
                appVersion
            } = req.body;

            /* =====================================================
               REGISTRATION
               Activation code is NOT required during registration.
            ===================================================== */

            const cleanUsername =
                normalizeUsername(username);

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

            const cleanDeviceId =
                deviceId === undefined ||
                deviceId === null
                    ? ""
                    : String(deviceId).trim();

            /* Username */

            if (!cleanUsername) {
                return res.status(400).json({
                    success: false,
                    message: "Username is required."
                });
            }

            if (cleanUsername.length < 3) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Username must contain at least 3 characters."
                });
            }

            /* Password */

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

            /* Device */

            if (!cleanDeviceId) {
                return res.status(400).json({
                    success: false,
                    message: "Device ID is required."
                });
            }

            /* Full name */

            if (!cleanFullName) {
                return res.status(400).json({
                    success: false,
                    message: "Full name is required."
                });
            }

            /* Email */

            if (!cleanEmail) {
                return res.status(400).json({
                    success: false,
                    message: "Email is required."
                });
            }

            /* Phone */

            if (!cleanPhone) {
                return res.status(400).json({
                    success: false,
                    message: "Phone number is required."
                });
            }

            /* =====================================================
               CHECK USERNAME
            ===================================================== */

            const {
                data: existingUsername,
                error: usernameError
            } =
                await supabase
                    .from("natan_users")
                    .select("id")
                    .eq("username", cleanUsername)
                    .maybeSingle();

            if (usernameError) {
                return res.status(500).json({
                    success: false,
                    message: usernameError.message
                });
            }

            if (existingUsername) {
                return res.status(409).json({
                    success: false,
                    message: "Username already exists."
                });
            }

            /* =====================================================
               CHECK EMAIL
            ===================================================== */

            const {
                data: existingEmail,
                error: emailError
            } =
                await supabase
                    .from("natan_users")
                    .select("id")
                    .eq("email", cleanEmail)
                    .maybeSingle();

            if (emailError) {
                return res.status(500).json({
                    success: false,
                    message: emailError.message
                });
            }

            if (existingEmail) {
                return res.status(409).json({
                    success: false,
                    message: "Email already exists."
                });
            }

            /* =====================================================
               CHECK PHONE
            ===================================================== */

            const {
                data: existingPhone,
                error: phoneError
            } =
                await supabase
                    .from("natan_users")
                    .select("id")
                    .eq("phone", cleanPhone)
                    .maybeSingle();

            if (phoneError) {
                return res.status(500).json({
                    success: false,
                    message: phoneError.message
                });
            }

            if (existingPhone) {
                return res.status(409).json({
                    success: false,
                    message: "Phone number already exists."
                });
            }

            /* =====================================================
               CHECK DEVICE
            ===================================================== */

            const {
                data: existingDevice,
                error: deviceCheckError
            } =
                await supabase
                    .from("natan_devices")
                    .select("id,user_id,is_active")
                    .eq("device_id", cleanDeviceId)
                    .maybeSingle();

            if (deviceCheckError) {
                return res.status(500).json({
                    success: false,
                    message: deviceCheckError.message
                });
            }

            if (existingDevice) {
                return res.status(409).json({
                    success: false,
                    message:
                        "This device is already registered."
                });
            }

            /* =====================================================
               HASH PASSWORD
            ===================================================== */

            const passwordHash =
                await bcrypt.hash(
                    String(password),
                    12
                );

            /* =====================================================
               CREATE UNACTIVATED USER
            ===================================================== */

            const {
                data: user,
                error: userError
            } =
                await supabase
                    .from("natan_users")
                    .insert({
                        username: cleanUsername,
                        email: cleanEmail,
                        phone: cleanPhone,
                        password_hash: passwordHash,
                        full_name: cleanFullName,

                        is_active: true,

                        /* User can enter the app,
                           but protected features require activation. */
                        is_activated: false,

                        activation_expires_at: null,

                        max_devices: 1
                    })
                    .select(
                        "id,username,email,phone,full_name,is_active,is_activated,activation_expires_at,max_devices,created_at,updated_at"
                    )
                    .single();

            if (userError) {
                return res.status(500).json({
                    success: false,
                    message: userError.message
                });
            }

            /* =====================================================
               REGISTER DEVICE
            ===================================================== */

            const {
                data: registeredDevice,
                error: deviceError
            } =
                await supabase
                    .from("natan_devices")
                    .insert({
                        user_id: user.id,
                        device_id: cleanDeviceId,
                        device_name: deviceName || null,
                        platform: platform || null,
                        app_version: appVersion || null,
                        is_active: true
                    })
                    .select(
                        "id,device_id,user_id,is_active"
                    )
                    .single();

            if (deviceError) {

                await supabase
                    .from("natan_users")
                    .delete()
                    .eq("id", user.id);

                return res.status(500).json({
                    success: false,
                    message: deviceError.message
                });
            }

            /* =====================================================
               ACTIVITY LOG
            ===================================================== */

            await supabase
                .from("natan_activity_logs")
                .insert({
                    user_id: user.id,
                    action: "register",
                    description:
                        "NATAN account registered successfully. Activation is required for protected features.",
                    device_id: cleanDeviceId
                });

            /* =====================================================
               CREATE LOGIN TOKEN
            ===================================================== */

            const token =
                createToken({
                    id: user.id,
                    username: user.username,
                    role: "user"
                });

            /* =====================================================
               SUCCESS
            ===================================================== */

            return res.status(201).json({

                success: true,

                message:
                    "NATAN account created successfully. Activation is required for protected features.",

                requiresActivation: true,

                token,

                user: {

                    id: user.id,

                    username: user.username,

                    email: user.email,

                    phone: user.phone,

                    fullName: user.full_name,

                    active: user.is_active,

                    isActivated: user.is_activated,

                    expiresAt:
                        user.activation_expires_at,

                    maxDevices:
                        user.max_devices,

                    createdAt:
                        user.created_at,

                    updatedAt:
                        user.updated_at
                },

                device: {

                    id:
                        registeredDevice.id,

                    deviceId:
                        registeredDevice.device_id,

                    userId:
                        registeredDevice.user_id,

                    active:
                        registeredDevice.is_active
                }
            });

        } catch (error) {

            console.error(
                "NATAN register error:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    error?.message ||
                    "Internal server error."
            });
        }
    }
);'''

p.write_text(
    s[:start] + new_route + s[end:],
    encoding="utf-8"
)

print("REGISTER_ROUTE_UPDATED")

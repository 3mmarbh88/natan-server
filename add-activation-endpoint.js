const activationEndpoint = `

/* =========================================================
   USER - ACTIVATE ACCOUNT
========================================================= */

app.post(
    "/api/auth/activate",
    async (req, res) => {

        try {

            const {
                identifier,
                activationCode,
                deviceId
            } = req.body || {};


            const cleanIdentifier =
                String(
                    identifier || ""
                ).trim();

            const cleanCode =
                String(
                    activationCode || ""
                ).trim().toUpperCase();

            const cleanDeviceId =
                String(
                    deviceId || ""
                ).trim();


            if (!cleanIdentifier) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Username, email, or phone is required."
                });
            }


            if (!cleanCode) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Activation code is required."
                });
            }


            if (!cleanDeviceId) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Device ID is required."
                });
            }


            /* =====================================================
               FIND USER
            ===================================================== */

            let user = null;
            let userError = null;


            const byUsername =
                await supabase
                    .from("natan_users")
                    .select(
                        "id,username,email,phone,full_name,is_active,is_activated,activation_expires_at,max_devices,created_at,updated_at"
                    )
                    .eq(
                        "username",
                        cleanIdentifier
                    )
                    .maybeSingle();


            if (byUsername.data) {

                user =
                    byUsername.data;

            } else {

                const byEmail =
                    await supabase
                        .from("natan_users")
                        .select(
                            "id,username,email,phone,full_name,is_active,is_activated,activation_expires_at,max_devices,created_at,updated_at"
                        )
                        .eq(
                            "email",
                            cleanIdentifier.toLowerCase()
                        )
                        .maybeSingle();


                if (byEmail.data) {

                    user =
                        byEmail.data;

                } else {

                    const byPhone =
                        await supabase
                            .from("natan_users")
                            .select(
                                "id,username,email,phone,full_name,is_active,is_activated,activation_expires_at,max_devices,created_at,updated_at"
                            )
                            .eq(
                                "phone",
                                cleanIdentifier
                            )
                            .maybeSingle();


                    if (byPhone.data) {

                        user =
                            byPhone.data;

                    } else {

                        userError =
                            byPhone.error ||
                            byEmail.error ||
                            byUsername.error;
                    }
                }
            }


            if (!user) {

                return res.status(404).json({
                    success: false,
                    message:
                        "NATAN account not found."
                });
            }


            if (!user.is_active) {

                return res.status(403).json({
                    success: false,
                    message:
                        "NATAN account is disabled."
                });
            }


            /* =====================================================
               VERIFY DEVICE
            ===================================================== */

            const {
                data: device,
                error: deviceError
            } =
                await supabase
                    .from("natan_devices")
                    .select(
                        "id,device_id,user_id,is_active"
                    )
                    .eq(
                        "device_id",
                        cleanDeviceId
                    )
                    .eq(
                        "user_id",
                        user.id
                    )
                    .maybeSingle();


            if (deviceError) {

                console.error(
                    "Activation device lookup error:",
                    deviceError
                );

                return res.status(500).json({
                    success: false,
                    message:
                        "Unable to verify device."
                });
            }


            if (!device) {

                return res.status(403).json({
                    success: false,
                    message:
                        "This device is not registered for this account."
                });
            }


            if (!device.is_active) {

                return res.status(403).json({
                    success: false,
                    message:
                        "This device is disabled."
                });
            }


            /* =====================================================
               FIND ACTIVATION CODE
            ===================================================== */

            const {
                data: codeRow,
                error: codeError
            } =
                await supabase
                    .from("natan_activation_codes")
                    .select(
                        "id,code,duration_days,is_used,used_by,used_at,expires_at"
                    )
                    .eq(
                        "code",
                        cleanCode
                    )
                    .maybeSingle();


            if (codeError) {

                console.error(
                    "Activation code lookup error:",
                    codeError
                );

                return res.status(500).json({
                    success: false,
                    message:
                        "Unable to verify activation code."
                });
            }


            if (!codeRow) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid activation code."
                });
            }


            if (codeRow.is_used) {

                return res.status(400).json({
                    success: false,
                    message:
                        "This activation code has already been used."
                });
            }


            if (
                codeRow.expires_at &&
                new Date(
                    codeRow.expires_at
                ) <= new Date()
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "This activation code has expired."
                });
            }


            const durationDays =
                Number(
                    codeRow.duration_days
                );


            if (
                !Number.isInteger(durationDays) ||
                durationDays < 1
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid activation code duration."
                });
            }


            /* =====================================================
               CALCULATE LICENSE EXPIRY
            ===================================================== */

            const now =
                new Date();


            const currentExpiry =
                user.activation_expires_at &&
                new Date(
                    user.activation_expires_at
                ) > now
                    ? new Date(
                        user.activation_expires_at
                    )
                    : now;


            currentExpiry.setDate(
                currentExpiry.getDate() +
                durationDays
            );


            /* =====================================================
               ACTIVATE USER
            ===================================================== */

            const {
                data: updatedUser,
                error: updateUserError
            } =
                await supabase
                    .from("natan_users")
                    .update({
                        is_activated: true,
                        activation_expires_at:
                            currentExpiry.toISOString()
                    })
                    .eq(
                        "id",
                        user.id
                    )
                    .select(
                        "id,username,email,phone,full_name,is_active,is_activated,activation_expires_at,max_devices,created_at,updated_at"
                    )
                    .single();


            if (updateUserError) {

                console.error(
                    "Activation user update error:",
                    updateUserError
                );

                return res.status(500).json({
                    success: false,
                    message:
                        "Unable to activate account."
                });
            }


            /* =====================================================
               CONSUME ACTIVATION CODE
            ===================================================== */

            const {
                error: consumeError
            } =
                await supabase
                    .from("natan_activation_codes")
                    .update({
                        is_used: true,
                        used_by: user.id,
                        used_at: now.toISOString()
                    })
                    .eq(
                        "id",
                        codeRow.id
                    )
                    .eq(
                        "is_used",
                        false
                    );


            if (consumeError) {

                console.error(
                    "Activation code consume error:",
                    consumeError
                );

                return res.status(500).json({
                    success: false,
                    message:
                        "Account activated, but activation code could not be finalized."
                });
            }


            /* =====================================================
               ACTIVITY LOG
            ===================================================== */

            await supabase
                .from("natan_activity_logs")
                .insert({
                    user_id: user.id,
                    action: "activate",
                    description:
                        "NATAN account activated successfully.",
                    device_id: cleanDeviceId
                });


            /* =====================================================
               CREATE LOGIN TOKEN
            ===================================================== */

            const token =
                createToken({
                    id: updatedUser.id,
                    username:
                        updatedUser.username,
                    role:
                        "user"
                });


            /* =====================================================
               SUCCESS
            ===================================================== */

            return res.json({

                success: true,

                message:
                    "NATAN account activated successfully.",

                requiresActivation:
                    false,

                token,

                user: {

                    id:
                        updatedUser.id,

                    username:
                        updatedUser.username,

                    email:
                        updatedUser.email,

                    phone:
                        updatedUser.phone,

                    fullName:
                        updatedUser.full_name,

                    active:
                        updatedUser.is_active,

                    isActivated:
                        updatedUser.is_activated,

                    expiresAt:
                        updatedUser.activation_expires_at,

                    maxDevices:
                        updatedUser.max_devices
                },

                device: {

                    id:
                        device.id,

                    deviceId:
                        device.device_id,

                    userId:
                        device.user_id,

                    active:
                        device.is_active
                }
            });


        } catch (error) {

            console.error(
                "Activation error:",
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

`;

const fs = require("fs");

const file = "./server.js";
let source = fs.readFileSync(file, "utf8");

const marker = `/* =========================================================
   CURRENT USER
========================================================= */`;

if (!source.includes(marker)) {
    throw new Error("CURRENT USER marker not found.");
}

if (source.includes('"/api/auth/activate"')) {
    throw new Error("Activation endpoint already exists.");
}

source = source.replace(
    marker,
    activationEndpoint + "\n\n" + marker
);

fs.writeFileSync(file, source, "utf8");

console.log("ACTIVATION_ENDPOINT_ADDED");

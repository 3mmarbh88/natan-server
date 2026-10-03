const fs = require("fs");

const file = "./server.js";
let source = fs.readFileSync(file, "utf8");

if (source.includes('"/api/auth/activate"')) {
    throw new Error("Activation endpoint already exists.");
}

const marker = '"/api/auth/me"';
const position = source.indexOf(marker);

if (position < 0) {
    throw new Error("AUTH_ME route not found.");
}

const insertAt = source.lastIndexOf("app.get(", position);

if (insertAt < 0) {
    throw new Error("AUTH_ME app.get() not found.");
}

const endpoint = `/* =========================================================
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
                String(identifier || "").trim();

            const cleanCode =
                String(activationCode || "")
                    .trim()
                    .toUpperCase();

            const cleanDeviceId =
                String(deviceId || "").trim();


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


            /* FIND USER */

            let user = null;

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

                user = byUsername.data;

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

                    user = byEmail.data;

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
                        user = byPhone.data;
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


            /* VERIFY DEVICE */

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


            /* FIND ACTIVATION CODE */

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
                new Date(codeRow.expires_at) <= new Date()
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "This activation code has expired."
                });
            }


            const durationDays =
                Number(codeRow.duration_days);


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


            /* CALCULATE LICENSE EXPIRY */

            const now = new Date();

            const currentExpiry =
                user.activation_expires_at &&
                new Date(user.activation_expires_at) > now
                    ? new Date(user.activation_expires_at)
                    : now;

            currentExpiry.setDate(
                currentExpiry.getDate() + durationDays
            );


            /* ACTIVATE USER */

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


            /* CONSUME ACTIVATION CODE */

            const {
                data: consumedCode,
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
                    )
                    .select(
                        "id,code,is_used,used_by,used_at"
                    )
                    .maybeSingle();


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


            if (!consumedCode) {

                return res.status(409).json({
                    success: false,
                    message:
                        "Activation code was already used."
                });
            }


            /* ACTIVITY LOG */

            await supabase
                .from("natan_activity_logs")
                .insert({
                    user_id: user.id,
                    action: "activate",
                    description:
                        "NATAN account activated successfully.",
                    device_id: cleanDeviceId
                });


            /* CREATE TOKEN */

            const token =
                createToken({
                    id: updatedUser.id,
                    username:
                        updatedUser.username,
                    role:
                        "user"
                });


            /* SUCCESS */

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

source =
    source.slice(0, insertAt) +
    endpoint +
    "\n\n" +
    source.slice(insertAt);

fs.writeFileSync(file, source, "utf8");

console.log("ACTIVATION_ENDPOINT_ADDED");
console.log("INSERT_POSITION=" + insertAt);

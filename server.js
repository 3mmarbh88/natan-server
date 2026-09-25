require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = Number(process.env.PORT || 3000);

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "CHANGE_ME";

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY || !JWT_SECRET) {
    console.error("ERROR: Missing required environment variables.");
    process.exit(1);
}

const supabase = createClient(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY,
    {
        auth: {
            autoRefreshToken: false,
            persistSession: false
        }
    }
);


/* =========================================================
   SECURITY / MIDDLEWARE
========================================================= */

app.use(
    helmet({
        contentSecurityPolicy: false
    })
);

app.use(cors());

app.use(
    express.json({
        limit: "100kb"
    })
);

app.use(
    express.urlencoded({
        extended: false
    })
);


/* =========================================================
   RATE LIMIT
========================================================= */

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false
});

app.use("/api/", generalLimiter);

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many login attempts. Try again later."
    }
});


/* =========================================================
   HELPERS
========================================================= */

function createToken(payload) {
    return jwt.sign(
        payload,
        JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );
}


function generateActivationCode() {

    const chars =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    function part() {

        let result = "";

        for (let i = 0; i < 4; i++) {

            result += chars[
                crypto.randomInt(
                    0,
                    chars.length
                )
            ];
        }

        return result;
    }

    return `NATAN-${part()}-${part()}`;
}


function hashToken(token) {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}


function normalizeUsername(username) {

    return String(username || "")
        .trim()
        .toLowerCase();
}


function normalizeEmail(email) {

    if (
        email === undefined ||
        email === null
    ) {
        return null;
    }

    const value =
        String(email)
            .trim()
            .toLowerCase();

    return value || null;
}


function safeUser(user) {

    if (!user) {
        return null;
    }

    return {

        id:
            user.id,

        username:
            user.username,

        email:
            user.email ?? null,

        phone:
            user.phone ?? null,

        full_name:
            user.full_name ?? null,

        is_active:
            user.is_active,

        is_activated:
            user.is_activated ?? false,

        activation_expires_at:
            user.activation_expires_at ?? null,

        max_devices:
            user.max_devices ?? 1,

        created_at:
            user.created_at ?? null,

        updated_at:
            user.updated_at ?? null
    };
}


/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function authMiddleware(req, res, next) {

    const header =
        req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {

        return res.status(401).json({
            success: false,
            message:
                "Authorization token required."
        });
    }

    const token =
        header.substring(7);

    try {

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );

        req.user = decoded;

        next();

    } catch (error) {

        return res.status(401).json({
            success: false,
            message:
                "Invalid or expired token."
        });
    }
}


function adminMiddleware(req, res, next) {

    if (
        !req.user ||
        req.user.role !== "admin"
    ) {

        return res.status(403).json({
            success: false,
            message:
                "Admin access required."
        });
    }

    next();
}


/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/api/health",
    async (req, res) => {

        try {

            const { error } =
                await supabase
                    .from("natan_users")
                    .select(
                        "id",
                        {
                            count: "exact",
                            head: true
                        }
                    );

            if (error) {

                return res.status(500).json({
                    success: false,
                    server: "online",
                    database: "error",
                    error: error.message
                });
            }

            return res.json({
                success: true,
                server: "online",
                database: "online",
                app: "NATAN",
                time:
                    new Date().toISOString()
            });

        } catch (error) {

            return res.status(500).json({
                success: false,
                server: "online",
                database: "error"
            });
        }
    }
);


/* =========================================================
   USER REGISTER
========================================================= */

app.post(
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
);

/* =========================================================
   USER LOGIN
========================================================= */

app.post(
    "/api/auth/login",
    loginLimiter,
    async (req, res) => {

        try {

            const {
                username,
                password,
                deviceId,
                deviceName,
                platform,
                appVersion
            } = req.body;


            const cleanUsername =
                normalizeUsername(username);


            if (
                !cleanUsername ||
                !password
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Username, email or phone and password are required."
                });
            }


            /*
             * IMPORTANT:
             * Login supports:
             * 1. username
             * 2. email
             * 3. phone
             */

            let user = null;
            let error = null;


            /* Search username */

            const usernameResult =
                await supabase
                    .from("natan_users")
                    .select("*")
                    .eq(
                        "username",
                        cleanUsername
                    )
                    .maybeSingle();

            user =
                usernameResult.data;

            error =
                usernameResult.error;


            /* Search email */

            if (
                !user &&
                !error
            ) {

                const cleanEmail =
                    String(username || "")
                        .trim()
                        .toLowerCase();

                if (
                    cleanEmail.includes("@")
                ) {

                    const emailResult =
                        await supabase
                            .from("natan_users")
                            .select("*")
                            .eq(
                                "email",
                                cleanEmail
                            )
                            .maybeSingle();

                    user =
                        emailResult.data;

                    error =
                        emailResult.error;
                }
            }


            /* Search phone */

            if (
                !user &&
                !error
            ) {

                const cleanPhone =
                    String(username || "")
                        .trim();

                if (cleanPhone) {

                    const phoneResult =
                        await supabase
                            .from("natan_users")
                            .select("*")
                            .eq(
                                "phone",
                                cleanPhone
                            )
                            .maybeSingle();

                    user =
                        phoneResult.data;

                    error =
                        phoneResult.error;
                }
            }


            if (error) {

                return res.status(500).json({
                    success: false,
                    message:
                        error.message
                });
            }


            if (!user) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid username, email, phone or password."
                });
            }


            /* Password */

            const passwordOk =
                await bcrypt.compare(
                    String(password),
                    user.password_hash
                );


            if (!passwordOk) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid username, email, phone or password."
                });
            }


            /* Admin disabled */

            if (!user.is_active) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Your NATAN account is disabled."
                });
            }


            /* Activation status */

            const requiresActivation =
                user.is_activated === false;

            /* Expired */

            if (
                user.activation_expires_at &&
                new Date(
                    user.activation_expires_at
                ) <= new Date()
            ) {

                return res.status(403).json({

                    success:
                        false,

                    message:
                        "Your NATAN activation has expired.",

                    expired:
                        true
                });
            }


            /* Device management */

            if (deviceId) {

                const {
                    data: existingDevice
                } =
                    await supabase
                        .from("natan_devices")
                        .select("*")
                        .eq(
                            "user_id",
                            user.id
                        )
                        .eq(
                            "device_id",
                            String(deviceId)
                        )
                        .maybeSingle();


                if (existingDevice) {

                    if (
                        !existingDevice.is_active
                    ) {

                        return res.status(403).json({
                            success: false,
                            message:
                                "This device is disabled."
                        });
                    }


                    await supabase
                        .from("natan_devices")
                        .update({

                            last_seen_at:
                                new Date().toISOString(),

                            device_name:
                                deviceName ||
                                existingDevice.device_name,

                            platform:
                                platform ||
                                existingDevice.platform,

                            app_version:
                                appVersion ||
                                existingDevice.app_version

                        })
                        .eq(
                            "id",
                            existingDevice.id
                        );

                } else {

                    const {
                        count
                    } =
                        await supabase
                            .from("natan_devices")
                            .select(
                                "id",
                                {
                                    count:
                                        "exact",
                                    head:
                                        true
                                }
                            )
                            .eq(
                                "user_id",
                                user.id
                            )
                            .eq(
                                "is_active",
                                true
                            );


                    if (
                        Number(count || 0) >=
                        Number(
                            user.max_devices || 1
                        )
                    ) {

                        return res.status(403).json({
                            success: false,
                            message:
                                "Maximum number of devices reached."
                        });
                    }


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
            }


            /* Log login */

            await supabase
                .from("natan_activity_logs")
                .insert({

                    user_id:
                        user.id,

                    action:
                        "login",

                    description:
                        "User login.",

                    device_id:
                        deviceId || null
                });


            /* JWT */

            const token =
                createToken({

                    id:
                        user.id,

                    username:
                        user.username,

                    role:
                        "user"
                });


            return res.json({

                success:
                    true,

                message:
                    "Login successful.",

                token,

                requiresActivation,

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
                        user.activation_expires_at,

                    maxDevices:
                        user.max_devices
                }
            });

        } catch (error) {

            console.error(
                "Login error:",
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


/* =========================================================
   CURRENT USER
========================================================= */

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



app.get(
    "/api/auth/me",
    authMiddleware,
    async (req, res) => {

        try {

            if (
                req.user.role !== "user"
            ) {

                return res.status(403).json({
                    success: false,
                    message:
                        "User account required."
                });
            }


            const {
                data: user,
                error
            } =
                await supabase
                    .from("natan_users")
                    .select(
                        "id,username,email,phone,full_name,is_active,is_activated,activation_expires_at,max_devices,created_at,updated_at"
                    )
                    .eq(
                        "id",
                        req.user.id
                    )
                    .maybeSingle();


            if (
                error ||
                !user
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }


            if (!user.is_active) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Account disabled."
                });
            }


            if (
                user.activation_expires_at &&
                new Date(
                    user.activation_expires_at
                ) <= new Date()
            ) {

                return res.status(403).json({

                    success:
                        false,

                    message:
                        "Activation expired.",

                    expired:
                        true
                });
            }


            return res.json({

                success:
                    true,

                user:
                    user
            });

        } catch (error) {

            console.error(
                "Auth me error:",
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


/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
    "/api/admin/login",
    loginLimiter,
    async (req, res) => {

        try {

            const {
                username,
                password
            } = req.body;


            if (
                String(username || "") !==
                    ADMIN_USERNAME ||
                String(password || "") !==
                    ADMIN_PASSWORD
            ) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid admin credentials."
                });
            }


            const token =
                createToken({

                    username:
                        ADMIN_USERNAME,

                    role:
                        "admin"
                });


            return res.json({

                success:
                    true,

                token:
                    token
            });

        } catch (error) {

            console.error(
                "Admin login error:",
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


/* =========================================================
   ADMIN - USERS
========================================================= */

app.get(
    "/api/admin/users",
    authMiddleware,
    adminMiddleware,
    async (req, res) => {

        try {

            const {
                data,
                error
            } =
                await supabase
                    .from("natan_users")
                    .select(
                        "id,username,email,phone,full_name,is_active,is_activated,activation_expires_at,max_devices,created_at,updated_at"
                    )
                    .order(
                        "created_at",
                        {
                            ascending:
                                false
                        }
                    );


            if (error) {

                return res.status(500).json({
                    success: false,
                    message:
                        error.message
                });
            }


            return res.json({

                success:
                    true,

                users:
                    data || []
            });

        } catch (error) {

            console.error(
                "Get users error:",
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


/* =========================================================
   ADMIN - UPDATE USER
========================================================= */

app.patch(
    "/api/admin/users/:id",
    authMiddleware,
    adminMiddleware,
    async (req, res) => {

        try {

            const userId =
                String(
                    req.params.id || ""
                ).trim();


            if (!userId) {

                return res.status(400).json({
                    success: false,
                    message:
                        "User ID is required."
                });
            }


            const {
                username,
                email,
                fullName,
                isActive,
                isActivated,
                maxDevices,
                extendDays,
                password
            } = req.body;


            const {
                data: user,
                error: findError
            } =
                await supabase
                    .from("natan_users")
                    .select(
                        "id,username,email,phone,full_name,is_active,is_activated,activation_expires_at,max_devices,created_at,updated_at"
                    )
                    .eq(
                        "id",
                        userId
                    )
                    .maybeSingle();


            if (findError) {

                return res.status(500).json({
                    success: false,
                    message:
                        findError.message
                });
            }


            if (!user) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }


            const update = {};


            /* Username */

            if (
                username !== undefined
            ) {

                const cleanUsername =
                    normalizeUsername(
                        username
                    );


                if (
                    cleanUsername.length < 3
                ) {

                    return res.status(400).json({
                        success: false,
                        message:
                            "Username must contain at least 3 characters."
                    });
                }


                if (
                    cleanUsername !==
                    user.username
                ) {

                    const {
                        data: duplicate,
                        error: duplicateError
                    } =
                        await supabase
                            .from("natan_users")
                            .select("id")
                            .eq(
                                "username",
                                cleanUsername
                            )
                            .neq(
                                "id",
                                userId
                            )
                            .maybeSingle();


                    if (duplicateError) {

                        return res.status(500).json({
                            success: false,
                            message:
                                duplicateError.message
                        });
                    }


                    if (duplicate) {

                        return res.status(409).json({
                            success: false,
                            message:
                                "Username already exists."
                        });
                    }
                }


                update.username =
                    cleanUsername;
            }


            /* Email */

            if (
                email !== undefined
            ) {

                const cleanEmail =
                    normalizeEmail(
                        email
                    );


                if (cleanEmail) {

                    const {
                        data: duplicateEmail,
                        error: duplicateEmailError
                    } =
                        await supabase
                            .from("natan_users")
                            .select("id")
                            .eq(
                                "email",
                                cleanEmail
                            )
                            .neq(
                                "id",
                                userId
                            )
                            .maybeSingle();


                    if (duplicateEmailError) {

                        return res.status(500).json({
                            success: false,
                            message:
                                duplicateEmailError.message
                        });
                    }


                    if (duplicateEmail) {

                        return res.status(409).json({
                            success: false,
                            message:
                                "Email already exists."
                        });
                    }
                }


                update.email =
                    cleanEmail;
            }


            /* Full name */

            if (
                fullName !== undefined
            ) {

                const cleanFullName =
                    fullName === null
                        ? null
                        : String(
                            fullName
                        ).trim();


                update.full_name =
                    cleanFullName || null;
            }


            /* Active */

            if (
                typeof isActive ===
                "boolean"
            ) {

                update.is_active =
                    isActive;
            }


            /* Activated */

            if (
                typeof isActivated ===
                "boolean"
            ) {

                update.is_activated =
                    isActivated;

                if (!isActivated) {

                    update.activation_expires_at =
                        null;
                }
            }


            /* Max devices */

            if (
                maxDevices !== undefined
            ) {

                const value =
                    Number(
                        maxDevices
                    );


                if (
                    !Number.isInteger(value) ||
                    value < 1 ||
                    value > 20
                ) {

                    return res.status(400).json({
                        success: false,
                        message:
                            "maxDevices must be between 1 and 20."
                    });
                }


                update.max_devices =
                    value;
            }


            /* Extend subscription */

            if (
                extendDays !== undefined
            ) {

                const days =
                    Number(
                        extendDays
                    );


                if (
                    !Number.isInteger(days) ||
                    days < 1 ||
                    days > 3650
                ) {

                    return res.status(400).json({
                        success: false,
                        message:
                            "extendDays must be between 1 and 3650."
                    });
                }


                const currentExpiry =
                    user.activation_expires_at &&
                    new Date(
                        user.activation_expires_at
                    ) > new Date()
                        ? new Date(
                            user.activation_expires_at
                        )
                        : new Date();


                currentExpiry.setDate(
                    currentExpiry.getDate() +
                    days
                );


                update.activation_expires_at =
                    currentExpiry.toISOString();

                update.is_activated =
                    true;
            }


            /* Password */

            if (
                password !== undefined &&
                String(password).length > 0
            ) {

                const newPassword =
                    String(password);


                if (
                    newPassword.length < 6
                ) {

                    return res.status(400).json({
                        success: false,
                        message:
                            "Password must contain at least 6 characters."
                    });
                }


                update.password_hash =
                    await bcrypt.hash(
                        newPassword,
                        12
                    );
            }


            if (
                Object.keys(update).length === 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "No changes supplied."
                });
            }


            update.updated_at =
                new Date().toISOString();


            const {
                data: updatedUser,
                error
            } =
                await supabase
                    .from("natan_users")
                    .update(update)
                    .eq(
                        "id",
                        userId
                    )
                    .select(
                        "id,username,email,phone,full_name,is_active,is_activated,activation_expires_at,max_devices,created_at,updated_at"
                    )
                    .single();


            if (error) {

                console.error(
                    "Update database error:",
                    error
                );

                return res.status(500).json({
                    success: false,
                    message:
                        error.message
                });
            }


            const changedFields =
                Object.keys(update)
                    .filter(
                        field =>
                            field !==
                            "password_hash"
                    )
                    .join(", ");


            await supabase
                .from("natan_activity_logs")
                .insert({

                    user_id:
                        userId,

                    action:
                        "admin_update_user",

                    description:
                        `Admin updated user ${user.username}. Fields: ${changedFields || "password"}`
                });


            return res.json({

                success:
                    true,

                message:
                    "User updated successfully.",

                user:
                    safeUser(updatedUser)
            });

        } catch (error) {

            console.error(
                "Update user error:",
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


/* =========================================================
   ADMIN - DELETE USER
========================================================= */

app.delete(
    "/api/admin/users/:id",
    authMiddleware,
    adminMiddleware,
    async (req, res) => {

        try {

            const userId =
                String(
                    req.params.id || ""
                ).trim();


            if (!userId) {

                return res.status(400).json({
                    success: false,
                    message:
                        "User ID is required."
                });
            }


            const {
                data: user,
                error: findError
            } =
                await supabase
                    .from("natan_users")
                    .select(
                        "id,username"
                    )
                    .eq(
                        "id",
                        userId
                    )
                    .maybeSingle();


            if (findError) {

                return res.status(500).json({
                    success: false,
                    message:
                        findError.message
                });
            }


            if (!user) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
                });
            }


            /* Delete devices */

            const {
                error: devicesError
            } =
                await supabase
                    .from("natan_devices")
                    .delete()
                    .eq(
                        "user_id",
                        userId
                    );


            if (devicesError) {

                return res.status(500).json({
                    success: false,
                    message:
                        devicesError.message
                });
            }


            /* Delete reset records */

            const {
                error: resetError
            } =
                await supabase
                    .from("natan_password_resets")
                    .delete()
                    .eq(
                        "user_id",
                        userId
                    );


            if (resetError) {

                return res.status(500).json({
                    success: false,
                    message:
                        resetError.message
                });
            }


            /* Release activation codes */

            const {
                error: activationError
            } =
                await supabase
                    .from("natan_activation_codes")
                    .update({

                        is_used:
                            false,

                        used_by:
                            null,

                        used_at:
                            null
                    })
                    .eq(
                        "used_by",
                        userId
                    );


            if (activationError) {

                console.error(
                    "Activation code update error:",
                    activationError
                );
            }


            /* Delete logs */

            const {
                error: logsError
            } =
                await supabase
                    .from("natan_activity_logs")
                    .delete()
                    .eq(
                        "user_id",
                        userId
                    );


            if (logsError) {

                return res.status(500).json({
                    success: false,
                    message:
                        logsError.message
                });
            }


            /* Delete user */

            const {
                error: deleteError
            } =
                await supabase
                    .from("natan_users")
                    .delete()
                    .eq(
                        "id",
                        userId
                    );


            if (deleteError) {

                return res.status(500).json({
                    success: false,
                    message:
                        deleteError.message
                });
            }


            return res.json({

                success:
                    true,

                message:
                    "User deleted successfully.",

                userId:
                    userId,

                username:
                    user.username
            });

        } catch (error) {

            console.error(
                "Delete user error:",
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


/* =========================================================
   ADMIN - CREATE ACTIVATION CODES
========================================================= */

app.post(
    "/api/admin/activation-codes",
    authMiddleware,
    adminMiddleware,
    async (req, res) => {

        try {

            const {
                durationDays = 30,
                count = 1
            } = req.body;


            const days =
                Number(
                    durationDays
                );

            const amount =
                Number(
                    count
                );


            if (
                !Number.isInteger(days) ||
                days < 1 ||
                days > 3650
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "durationDays must be between 1 and 3650."
                });
            }


            if (
                !Number.isInteger(amount) ||
                amount < 1 ||
                amount > 100
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "count must be between 1 and 100."
                });
            }


            const expiresAt =
                new Date();

            expiresAt.setDate(
                expiresAt.getDate() +
                days
            );


            const rows = [];


            for (
                let i = 0;
                i < amount;
                i++
            ) {

                rows.push({

                    code:
                        generateActivationCode(),

                    duration_days:
                        days,

                    is_used:
                        false,

                    expires_at:
                        expiresAt.toISOString()
                });
            }


            const {
                data,
                error
            } =
                await supabase
                    .from(
                        "natan_activation_codes"
                    )
                    .insert(rows)
                    .select(
                        "id,code,duration_days,is_used,expires_at,created_at"
                    );


            if (error) {

                return res.status(500).json({
                    success: false,
                    message:
                        error.message
                });
            }


            return res.status(201).json({

                success:
                    true,

                codes:
                    data
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                success: false,
                message:
                    "Server error."
            });
        }
    }
);


/* =========================================================
   ADMIN - ACTIVATION CODES
========================================================= */

app.get(
    "/api/admin/activation-codes",
    authMiddleware,
    adminMiddleware,
    async (req, res) => {

        try {

            const {
                data,
                error
            } =
                await supabase
                    .from(
                        "natan_activation_codes"
                    )
                    .select(
                        "id,code,duration_days,is_used,used_by,used_at,created_at,expires_at"
                    )
                    .order(
                        "created_at",
                        {
                            ascending:
                                false
                        }
                    );


            if (error) {

                return res.status(500).json({
                    success: false,
                    message:
                        error.message
                });
            }


            return res.json({

                success:
                    true,

                codes:
                    data || []
            });

        } catch (error) {

            return res.status(500).json({
                success: false,
                message:
                    "Server error."
            });
        }
    }
);


/* =========================================================
   ADMIN - DEVICES
========================================================= */

app.get(
    "/api/admin/devices",
    authMiddleware,
    adminMiddleware,
    async (req, res) => {

        try {

            const {
                data,
                error
            } =
                await supabase
                    .from(
                        "natan_devices"
                    )
                    .select(
                        "id,user_id,device_id,device_name,platform,app_version,is_active,last_seen_at,created_at"
                    )
                    .order(
                        "last_seen_at",
                        {
                            ascending:
                                false
                        }
                    );


            if (error) {

                return res.status(500).json({
                    success: false,
                    message:
                        error.message
                });
            }


            return res.json({

                success:
                    true,

                devices:
                    data || []
            });

        } catch (error) {

            return res.status(500).json({
                success: false,
                message:
                    "Server error."
            });
        }
    }
);


/* =========================================================
   ADMIN - DISABLE DEVICE
========================================================= */

app.patch(
    "/api/admin/devices/:id",
    authMiddleware,
    adminMiddleware,
    async (req, res) => {

        try {

            const {
                isActive
            } = req.body;


            if (
                typeof isActive !==
                "boolean"
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "isActive must be true or false."
                });
            }


            const {
                data,
                error
            } =
                await supabase
                    .from(
                        "natan_devices"
                    )
                    .update({

                        is_active:
                            isActive

                    })
                    .eq(
                        "id",
                        req.params.id
                    )
                    .select(
                        "id,user_id,device_id,device_name,platform,app_version,is_active,last_seen_at,created_at"
                    )
                    .single();


            if (error) {

                return res.status(500).json({
                    success: false,
                    message:
                        error.message
                });
            }


            return res.json({

                success:
                    true,

                device:
                    data
            });

        } catch (error) {

            return res.status(500).json({
                success: false,
                message:
                    "Server error."
            });
        }
    }
);


/* =========================================================
   FORGOT PASSWORD
========================================================= */

app.post(
    "/api/auth/forgot-password",
    loginLimiter,
    async (req, res) => {

        try {

            const {
                username,
                email,
                phone
            } = req.body;


            let user = null;


            if (email) {

                const {
                    data
                } =
                    await supabase
                        .from("natan_users")
                        .select(
                            "id,username,email,phone"
                        )
                        .eq(
                            "email",
                            String(email)
                                .trim()
                                .toLowerCase()
                        )
                        .maybeSingle();

                user =
                    data;

            } else if (phone) {

                const {
                    data
                } =
                    await supabase
                        .from("natan_users")
                        .select(
                            "id,username,email,phone"
                        )
                        .eq(
                            "phone",
                            String(phone)
                                .trim()
                        )
                        .maybeSingle();

                user =
                    data;

            } else {

                const {
                    data
                } =
                    await supabase
                        .from("natan_users")
                        .select(
                            "id,username,email,phone"
                        )
                        .eq(
                            "username",
                            normalizeUsername(
                                username
                            )
                        )
                        .maybeSingle();

                user =
                    data;
            }


            /*
             * Always same response.
             */

            if (!user) {

                return res.json({

                    success:
                        true,

                    message:
                        "If the account exists, a reset process has been started."
                });
            }


            const rawToken =
                crypto.randomBytes(
                    32
                ).toString("hex");


            const tokenHash =
                hashToken(
                    rawToken
                );


            const expiresAt =
                new Date(
                    Date.now() +
                    30 * 60 * 1000
                );


            await supabase
                .from(
                    "natan_password_resets"
                )
                .delete()
                .eq(
                    "user_id",
                    user.id
                )
                .is(
                    "used_at",
                    null
                );


            const {
                error
            } =
                await supabase
                    .from(
                        "natan_password_resets"
                    )
                    .insert({

                        user_id:
                            user.id,

                        token_hash:
                            tokenHash,

                        expires_at:
                            expiresAt.toISOString()
                    });


            if (error) {

                return res.status(500).json({
                    success: false,
                    message:
                        "Unable to create reset request."
                });
            }


            console.log("");

            console.log(
                "======================================"
            );

            console.log(
                "NATAN PASSWORD RESET"
            );

            console.log(
                "Username:",
                user.username
            );

            console.log(
                "Reset token:",
                rawToken
            );

            console.log(
                "======================================"
            );

            console.log("");


            return res.json({

                success:
                    true,

                message:
                    "If the account exists, a reset process has been started."
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                success: false,
                message:
                    "Server error."
            });
        }
    }
);


/* =========================================================
   RESET PASSWORD
========================================================= */

app.post(
    "/api/auth/reset-password",
    async (req, res) => {

        try {

            const {
                token,
                newPassword
            } = req.body;


            if (
                !token ||
                !newPassword
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Token and new password are required."
                });
            }


            if (
                String(newPassword).length <
                6
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Password must contain at least 6 characters."
                });
            }


            const tokenHash =
                hashToken(
                    String(token)
                );


            const {
                data: reset
            } =
                await supabase
                    .from(
                        "natan_password_resets"
                    )
                    .select("*")
                    .eq(
                        "token_hash",
                        tokenHash
                    )
                    .is(
                        "used_at",
                        null
                    )
                    .maybeSingle();


            if (!reset) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid reset token."
                });
            }


            if (
                new Date(
                    reset.expires_at
                ) <= new Date()
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Reset token has expired."
                });
            }


            const passwordHash =
                await bcrypt.hash(
                    String(newPassword),
                    12
                );


            const {
                error: passwordError
            } =
                await supabase
                    .from(
                        "natan_users"
                    )
                    .update({

                        password_hash:
                            passwordHash,

                        updated_at:
                            new Date().toISOString()
                    })
                    .eq(
                        "id",
                        reset.user_id
                    );


            if (passwordError) {

                return res.status(500).json({
                    success: false,
                    message:
                        "Unable to reset password."
                });
            }


            await supabase
                .from(
                    "natan_password_resets"
                )
                .update({

                    used_at:
                        new Date().toISOString()

                })
                .eq(
                    "id",
                    reset.id
                );


            await supabase
                .from(
                    "natan_activity_logs"
                )
                .insert({

                    user_id:
                        reset.user_id,

                    action:
                        "password_reset",

                    description:
                        "Password reset successfully."
                });


            return res.json({

                success:
                    true,

                message:
                    "Password reset successfully."
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                success: false,
                message:
                    "Server error."
            });
        }
    }
);


/* =========================================================
   404 API
========================================================= */

app.use(
    "/api",
    (req, res) => {

        res.status(404).json({

            success:
                false,

            message:
                "API endpoint not found."
        });
    }
);


/* =========================================================
   START SERVER
========================================================= */

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log("");

        console.log(
            "======================================"
        );

        console.log(
            "        NATAN SERVER ONLINE"
        );

        console.log(
            "======================================"
        );

        console.log(
            `Local URL:   http://localhost:${PORT}`
        );

        console.log(
            `Network URL: http://192.168.43.80:${PORT}`
        );

        console.log(
            `Health:      http://192.168.43.80:${PORT}/api/health`
        );

        console.log("");

        console.log(
            "Admin API:"
        );

        console.log(
            `POST http://192.168.43.80:${PORT}/api/admin/login`
        );

        console.log(
            `GET  http://192.168.43.80:${PORT}/api/admin/users`
        );

        console.log(
            `PATCH http://192.168.43.80:${PORT}/api/admin/users/:id`
        );

        console.log(
            `DELETE http://192.168.43.80:${PORT}/api/admin/users/:id`
        );

        console.log("");

        console.log(
            "NATAN SERVER READY."
        );

        console.log("");
    }
);
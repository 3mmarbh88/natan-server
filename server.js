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


            /* Generate username */

            let generatedUsername =
                cleanPhone
                    .replace(/[^\dA-Za-z]/g, "")
                    .toLowerCase();

            if (!generatedUsername) {

                generatedUsername =
                    cleanEmail
                        .split("@")[0]
                        .replace(
                            /[^a-zA-Z0-9._-]/g,
                            ""
                        )
                        .toLowerCase();
            }

            if (
                generatedUsername.length < 3
            ) {

                generatedUsername =
                    `natan_${crypto.randomBytes(4).toString("hex")}`;
            }


            /* Check username */

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


            /* Create inactive-from-activation account */

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


            /* Activity */

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


/* =========================================================
   USER ACTIVATE
========================================================= */

app.post(
    "/api/auth/activate",
    loginLimiter,
    async (req, res) => {

        try {

            const {
                username,
                email,
                phone,
                identifier,
                activationCode,
                deviceId
            } = req.body;


            const loginIdentifier =
                String(
                    identifier ||
                    username ||
                    email ||
                    phone ||
                    ""
                ).trim();

            const cleanActivationCode =
                String(
                    activationCode || ""
                )
                    .trim()
                    .toUpperCase();


            if (!loginIdentifier) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Username, email or phone number is required."
                });
            }

            if (!cleanActivationCode) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Activation code is required."
                });
            }


            /* Find user */

            const cleanIdentifier =
                loginIdentifier.toLowerCase();

            let user = null;
            let userError = null;


            const byUsername =
                await supabase
                    .from("natan_users")
                    .select("*")
                    .eq(
                        "username",
                        cleanIdentifier
                    )
                    .maybeSingle();

            if (byUsername.error) {

                userError =
                    byUsername.error;

            } else {

                user =
                    byUsername.data;
            }


            if (!user) {

                const byEmail =
                    await supabase
                        .from("natan_users")
                        .select("*")
                        .eq(
                            "email",
                            cleanIdentifier
                        )
                        .maybeSingle();

                if (byEmail.error) {

                    userError =
                        byEmail.error;

                } else {

                    user =
                        byEmail.data;
                }
            }


            if (!user) {

                const byPhone =
                    await supabase
                        .from("natan_users")
                        .select("*")
                        .eq(
                            "phone",
                            loginIdentifier
                        )
                        .maybeSingle();

                if (byPhone.error) {

                    userError =
                        byPhone.error;

                } else {

                    user =
                        byPhone.data;
                }
            }


            if (userError) {

                return res.status(500).json({
                    success: false,
                    message:
                        userError.message
                });
            }


            if (!user) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User account not found."
                });
            }


            /* Admin disabled account */

            if (!user.is_active) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Your NATAN account is disabled."
                });
            }


            /* Already activated */

            if (user.is_activated === true) {

                return res.status(409).json({
                    success: false,
                    message:
                        "This account is already activated.",
                    alreadyActivated: true
                });
            }


            /* Find activation code */

            const {
                data: activation,
                error: activationError
            } =
                await supabase
                    .from("natan_activation_codes")
                    .select("*")
                    .eq(
                        "code",
                        cleanActivationCode
                    )
                    .eq(
                        "is_used",
                        false
                    )
                    .maybeSingle();

            if (activationError) {

                return res.status(500).json({
                    success: false,
                    message:
                        activationError.message
                });
            }


            if (!activation) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid or already used activation code."
                });
            }


            /* Code expiry */

            if (
                activation.expires_at &&
                new Date(
                    activation.expires_at
                ) <= new Date()
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Activation code has expired."
                });
            }


            const durationDays =
                Number(
                    activation.duration_days ||
                    30
                );

            if (
                !Number.isInteger(durationDays) ||
                durationDays < 1
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid activation duration."
                });
            }


            const expiresAt =
                new Date();

            expiresAt.setDate(
                expiresAt.getDate() +
                durationDays
            );


            /* Activate account */

            const {
                data: updatedUser,
                error: updateUserError
            } =
                await supabase
                    .from("natan_users")
                    .update({

                        is_activated:
                            true,

                        activation_expires_at:
                            expiresAt.toISOString(),

                        updated_at:
                            new Date().toISOString()
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

                return res.status(500).json({
                    success: false,
                    message:
                        updateUserError.message
                });
            }


            /* Consume code */

            const {
                data: consumedCode,
                error: updateCodeError
            } =
                await supabase
                    .from("natan_activation_codes")
                    .update({

                        is_used:
                            true,

                        used_by:
                            user.id,

                        used_at:
                            new Date().toISOString()
                    })
                    .eq(
                        "id",
                        activation.id
                    )
                    .eq(
                        "is_used",
                        false
                    )
                    .select(
                        "id"
                    )
                    .maybeSingle();


            if (updateCodeError) {

                console.error(
                    "Activation code update error:",
                    updateCodeError
                );

                /*
                 * Roll back account activation
                 * if the code could not be consumed.
                 */

                await supabase
                    .from("natan_users")
                    .update({

                        is_activated:
                            false,

                        activation_expires_at:
                            null,

                        updated_at:
                            new Date().toISOString()
                    })
                    .eq(
                        "id",
                        user.id
                    );

                return res.status(500).json({
                    success: false,
                    message:
                        "Unable to complete activation."
                });
            }


            if (!consumedCode) {

                await supabase
                    .from("natan_users")
                    .update({

                        is_activated:
                            false,

                        activation_expires_at:
                            null,

                        updated_at:
                            new Date().toISOString()
                    })
                    .eq(
                        "id",
                        user.id
                    );

                return res.status(409).json({
                    success: false,
                    message:
                        "Activation code was already used."
                });
            }


            /* Activity */

            await supabase
                .from("natan_activity_logs")
                .insert({

                    user_id:
                        user.id,

                    action:
                        "activate",

                    description:
                        `NATAN account activated for ${durationDays} days.`,

                    device_id:
                        deviceId || null
                });


            /* JWT */

            const token =
                createToken({

                    id:
                        updatedUser.id,

                    username:
                        updatedUser.username,

                    role:
                        "user"
                });


            return res.json({

                success:
                    true,

                message:
                    "Account activated successfully.",

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


            /* Activation required */

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
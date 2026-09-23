from pathlib import Path

p = Path(".\server.js")
s = p.read_text(encoding="utf-8")

marker = '''/* =========================================================
   USER LOGIN
========================================================= */
'''

if marker not in s:
    raise SystemExit("USER LOGIN marker not found.")

if '"/api/auth/activate"' in s:
    raise SystemExit("Activation API already exists.")

block = r'''/* =========================================================
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


            /*
             * The client may send:
             * username
             * email
             * phone
             * or identifier
             */

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
                    activationCode ||
                    ""
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


            /*
             * Find user by username, email or phone.
             */

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
                userError = byUsername.error;
            } else {
                user = byUsername.data;
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
                    userError = byEmail.error;
                } else {
                    user = byEmail.data;
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
                    userError = byPhone.error;
                } else {
                    user = byPhone.data;
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


            if (!user.is_active) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Your NATAN account is disabled."
                });
            }


            /*
             * If already activated, do not consume another code.
             */

            if (user.is_activated === true) {

                return res.status(409).json({
                    success: false,
                    message:
                        "This account is already activated.",
                    alreadyActivated: true
                });
            }


            /*
             * Find unused activation code.
             */

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


            /*
             * Check activation-code expiry.
             */

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


            /*
             * Calculate the user's subscription expiry
             * from the duration assigned to the code.
             */

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


            /*
             * Activate the account.
             */

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


            /*
             * Consume activation code.
             */

            const {
                error: updateCodeError
            } =
                await supabase
                    .from(
                        "natan_activation_codes"
                    )
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
                    );


            if (updateCodeError) {

                console.error(
                    "Activation code update error:",
                    updateCodeError
                );

                /*
                 * Do not hide the successful account update,
                 * but report that the code could not be consumed.
                 */
            }


            /*
             * Activity log.
             */

            await supabase
                .from(
                    "natan_activity_logs"
                )
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


            /*
             * Issue JWT after successful activation.
             */

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


'''

s = s.replace(marker, block + marker, 1)

p.write_text(s, encoding="utf-8")

print("USER ACTIVATE API added successfully.")

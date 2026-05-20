const express = require("express");
const rateLimit = require("express-rate-limit");
const validator = require("validator");

const User = require("../models/User");
const { signToken } = require("../utils/jwt");
const { requireAuth } = require("../middleware/auth");
const { sendOtpEmail } = require("../utils/email");

const router = express.Router();

// OTPs are valid for 10 minutes, user gets 5 attempts per code
const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_TTL_MIN = Math.round(OTP_TTL_MS / 60000);
const OTP_MAX_ATTEMPTS = 5;

// When set to "true", and the email actually failed to send (or no SMTP is
// configured), the response includes the OTP so the frontend can show it on
// screen. Use this ONLY for local development — never in production.
const DEV_RETURN_OTP = process.env.DEV_RETURN_OTP === "true";

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many requests. Please try again in a few minutes." },
});

/**
 * POST /api/auth/signup
 * Body: { name, email, password }
 * Creates an UNVERIFIED user and emails a 6-digit OTP. No JWT is returned.
 */
router.post("/signup", authLimiter, async (req, res, next) => {
  try {
    const { name, email, password } = req.body || {};

    if (!name || typeof name !== "string" || name.trim().length < 2) {
      return res.status(400).json({ message: "Name must be at least 2 characters" });
    }
    if (!email || typeof email !== "string" || !validator.isEmail(email)) {
      return res.status(400).json({ message: "Please provide a valid email address" });
    }
    if (!password || typeof password !== "string" || password.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters" });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const existing = await User.findOne({ email: normalizedEmail });

    if (existing) {
      if (existing.isVerified) {
        return res.status(409).json({ message: "An account with this email already exists" });
      }
      // Unverified account — refresh credentials + issue a new OTP
      existing.name = name.trim();
      existing.password = password;
      const otp = await existing.setOtp(OTP_TTL_MS);
      await existing.save();

      const emailRes = await sendOtpEmail({
        to: existing.email,
        name: existing.name,
        otp,
        ttlMinutes: OTP_TTL_MIN,
      });

      return res.status(200).json({
        message:
          emailRes.fallback && DEV_RETURN_OTP
            ? `Account exists. Email delivery isn't configured — your code is ${otp}.`
            : "Account exists but wasn't verified. We've sent a new code to your email.",
        email: existing.email,
        ...(emailRes.fallback && DEV_RETURN_OTP ? { devOtp: otp } : {}),
      });
    }

    const user = new User({
      name: name.trim(),
      email: normalizedEmail,
      password,
    });
    const otp = await user.setOtp(OTP_TTL_MS);
    await user.save();

    const emailRes = await sendOtpEmail({
      to: user.email,
      name: user.name,
      otp,
      ttlMinutes: OTP_TTL_MIN,
    });

    return res.status(201).json({
      message:
        emailRes.fallback && DEV_RETURN_OTP
          ? `Account created. Email delivery isn't configured — your code is ${otp}.`
          : `We've sent a 6-digit verification code to ${user.email}.`,
      email: user.email,
      ...(emailRes.fallback && DEV_RETURN_OTP ? { devOtp: otp } : {}),
    });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(409).json({ message: "An account with this email already exists" });
    }
    next(err);
  }
});

/**
 * POST /api/auth/verify-otp
 * Body: { email, otp }
 * Marks the user's email as verified and issues a JWT so they're immediately logged in.
 */
router.post("/verify-otp", authLimiter, async (req, res, next) => {
  try {
    const { email, otp } = req.body || {};

    if (!email || typeof email !== "string" || !validator.isEmail(email)) {
      return res.status(400).json({ message: "A valid email is required" });
    }
    if (!otp || typeof otp !== "string" || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({ message: "Enter the 6-digit code from your email" });
    }

    const user = await User.findOne({ email: email.trim().toLowerCase() }).select(
      "+otpHash +otpExpires +otpAttempts"
    );

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired verification code" });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: "This account is already verified. Please log in." });
    }

    if (!user.otpHash || !user.otpExpires) {
      return res.status(400).json({
        message: "No verification code is pending. Please request a new one.",
      });
    }

    if (user.otpExpires.getTime() < Date.now()) {
      user.clearOtp();
      await user.save();
      return res.status(400).json({
        message: "Your verification code has expired. Please request a new one.",
      });
    }

    if (user.otpAttempts >= OTP_MAX_ATTEMPTS) {
      user.clearOtp();
      await user.save();
      return res.status(429).json({
        message: "Too many incorrect attempts. Please request a new code.",
      });
    }

    const ok = await user.compareOtp(otp);
    if (!ok) {
      user.otpAttempts += 1;
      await user.save();
      const remaining = OTP_MAX_ATTEMPTS - user.otpAttempts;
      return res.status(400).json({
        message:
          remaining > 0
            ? `Incorrect code. ${remaining} attempt${remaining === 1 ? "" : "s"} remaining.`
            : "Too many incorrect attempts. Please request a new code.",
      });
    }

    user.isVerified = true;
    user.clearOtp();
    await user.save();

    const token = signToken({ sub: user._id.toString() });

    return res.json({
      message: "Email verified successfully.",
      token,
      user: user.toSafeJSON(),
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/resend-otp
 * Body: { email }
 * Generates and emails a new code. Always 200 with a generic message to avoid
 * leaking which addresses have accounts.
 */
router.post("/resend-otp", authLimiter, async (req, res, next) => {
  try {
    const { email } = req.body || {};
    const genericMsg = {
      message:
        "If an unverified account with that email exists, a new code has been sent.",
    };

    if (!email || typeof email !== "string" || !validator.isEmail(email)) {
      return res.json(genericMsg);
    }

    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user || user.isVerified) return res.json(genericMsg);

    const otp = await user.setOtp(OTP_TTL_MS);
    await user.save();

    const emailRes = await sendOtpEmail({
      to: user.email,
      name: user.name,
      otp,
      ttlMinutes: OTP_TTL_MIN,
    });

    // In dev, when SMTP isn't configured, surface the OTP so the user can
    // continue without checking email. Still 200 either way.
    if (emailRes.fallback && DEV_RETURN_OTP) {
      return res.json({
        message: `Email delivery isn't configured — your code is ${otp}.`,
        devOtp: otp,
      });
    }
    return res.json(genericMsg);
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/login
 * Body: { email, password }
 * Blocks unverified users with a 403.
 */
router.post("/login", authLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (
      !email ||
      typeof email !== "string" ||
      !password ||
      typeof password !== "string"
    ) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail }).select("+password");

    const invalid = () => res.status(401).json({ message: "Invalid email or password" });

    if (!user) return invalid();

    const ok = await user.comparePassword(password);
    if (!ok) return invalid();

    if (!user.isVerified) {
      return res.status(403).json({
        message:
          "Please verify your email before logging in. Check your inbox for the 6-digit code.",
        needsVerification: true,
        email: user.email,
      });
    }

    const token = signToken({ sub: user._id.toString() });

    return res.json({ token, user: user.toSafeJSON() });
  } catch (err) {
    next(err);
  }
});

router.get("/me", requireAuth, (req, res) => {
  res.json({ user: req.user.toSafeJSON() });
});

module.exports = router;

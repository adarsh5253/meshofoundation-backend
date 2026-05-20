const express = require("express");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const Razorpay = require("razorpay");

const Payment = require("../models/Payment");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

// --- Razorpay client ---
// Lazily initialised so a missing key only fails on the first request, not at
// import time (keeps the server bootable while you're still wiring keys).
let _client = null;
function getRazorpay() {
  if (_client) return _client;
  const { RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET } = process.env;
  if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
    const err = new Error(
      "Razorpay is not configured. Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET in .env"
    );
    err.status = 500;
    throw err;
  }
  // Catch the "swapped one but not the other" footgun — a live key_id with a
  // test key_secret will silently fail Razorpay auth at runtime; better to
  // refuse here with a clearer message.
  const idMode = RAZORPAY_KEY_ID.startsWith("rzp_live_")
    ? "live"
    : RAZORPAY_KEY_ID.startsWith("rzp_test_")
      ? "test"
      : null;
  if (!idMode) {
    const err = new Error(
      "RAZORPAY_KEY_ID has an unrecognised prefix (expected rzp_live_ or rzp_test_)."
    );
    err.status = 500;
    throw err;
  }
  _client = new Razorpay({
    key_id: RAZORPAY_KEY_ID,
    key_secret: RAZORPAY_KEY_SECRET,
  });
  return _client;
}

// Tighter rate limit on the order-creation endpoint to discourage abuse.
const paymentLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many payment requests. Please slow down." },
});

const ALLOWED_PURPOSES = ["donation", "career-application"];

/**
 * POST /api/payments/create-order
 * Auth required.
 * Body: { amount (paise), currency?, purpose, note? }
 * Creates a Razorpay order and persists a Payment row in `created` state.
 * Returns the order details the frontend needs to open Checkout.
 */
router.post("/create-order", requireAuth, paymentLimiter, async (req, res, next) => {
  try {
    const { amount, currency = "INR", purpose, note = "" } = req.body || {};

    // --- Validation ---
    const amt = Number(amount);
    if (!Number.isFinite(amt) || !Number.isInteger(amt)) {
      return res
        .status(400)
        .json({ message: "Amount must be an integer number of paise." });
    }
    if (amt < 100) {
      return res
        .status(400)
        .json({ message: "Minimum amount is 100 paise (₹1)." });
    }
    if (amt > 10_000_000) {
      // 1 lakh rupees — sanity ceiling, raise if you actually need bigger.
      return res
        .status(400)
        .json({ message: "Amount exceeds the per-transaction limit." });
    }
    if (!purpose || !ALLOWED_PURPOSES.includes(purpose)) {
      return res
        .status(400)
        .json({ message: "Unknown payment purpose." });
    }
    if (typeof note !== "string" || note.length > 200) {
      return res
        .status(400)
        .json({ message: "Note must be a string of up to 200 characters." });
    }

    // Receipt is shown in Razorpay dashboard. Keep it short — they cap at 40.
    const receipt = `mesho_${Date.now()}_${req.user._id
      .toString()
      .slice(-6)}`.slice(0, 40);

    let order;
    try {
      order = await getRazorpay().orders.create({
        amount: amt,
        currency,
        receipt,
        notes: {
          userId: req.user._id.toString(),
          email: req.user.email,
          purpose,
          ...(note ? { note } : {}),
        },
      });
    } catch (err) {
      // Razorpay surfaces auth issues as statusCode 401.
      if (err && err.statusCode === 401) {
        console.error("[razorpay] auth failed — check KEY_ID/KEY_SECRET");
        return res
          .status(401)
          .json({ message: "Payment provider authentication failed." });
      }
      console.error("[razorpay] order creation failed:", err);
      return res
        .status(500)
        .json({ message: "Could not create payment order. Please try again." });
    }

    await Payment.create({
      user: req.user._id,
      purpose,
      note,
      amount: amt,
      currency,
      receipt,
      razorpayOrderId: order.id,
      status: "created",
    });

    return res.status(201).json({
      order_id: order.id,
      amount: order.amount,
      currency: order.currency,
      receipt: order.receipt,
      key_id: process.env.RAZORPAY_KEY_ID, // public key, fine to send
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/payments/verify-payment
 * Auth required.
 * Body: { razorpay_order_id, razorpay_payment_id, razorpay_signature }
 *
 * Recomputes HMAC-SHA256(order_id + "|" + payment_id, KEY_SECRET) and compares
 * with the signature Razorpay returned in the success handler. If they match,
 * the payment is genuine and we mark the Payment row as `paid`.
 */
router.post("/verify-payment", requireAuth, async (req, res, next) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } =
      req.body || {};

    if (
      !razorpay_order_id ||
      !razorpay_payment_id ||
      !razorpay_signature ||
      typeof razorpay_order_id !== "string" ||
      typeof razorpay_payment_id !== "string" ||
      typeof razorpay_signature !== "string"
    ) {
      return res.status(400).json({ message: "Missing payment fields." });
    }

    const secret = process.env.RAZORPAY_KEY_SECRET;
    if (!secret) {
      return res
        .status(500)
        .json({ message: "Payment verification is not configured on the server." });
    }

    const expected = crypto
      .createHmac("sha256", secret)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest("hex");

    // Constant-time compare to avoid leaking match info via timing.
    const expectedBuf = Buffer.from(expected, "hex");
    const gotBuf = Buffer.from(razorpay_signature, "hex");
    const matches =
      expectedBuf.length === gotBuf.length &&
      crypto.timingSafeEqual(expectedBuf, gotBuf);

    if (!matches) {
      // Mark the payment as failed (best-effort) so the audit trail is honest.
      await Payment.findOneAndUpdate(
        { razorpayOrderId: razorpay_order_id, user: req.user._id },
        { status: "failed", razorpayPaymentId: razorpay_payment_id }
      ).catch(() => {});
      return res.status(400).json({ message: "Payment verification failed." });
    }

    const payment = await Payment.findOneAndUpdate(
      { razorpayOrderId: razorpay_order_id, user: req.user._id },
      {
        status: "paid",
        razorpayPaymentId: razorpay_payment_id,
        razorpaySignature: razorpay_signature,
      },
      { new: true }
    );

    if (!payment) {
      // Signature is valid but we don't have a record — possibly a stale order
      // from another user, or DB record was wiped. Treat as untrusted.
      return res.status(404).json({ message: "Order not found for this user." });
    }

    return res.json({
      success: true,
      message: "Payment verified successfully.",
      payment: {
        id: payment._id,
        purpose: payment.purpose,
        amount: payment.amount,
        currency: payment.currency,
        status: payment.status,
        razorpayOrderId: payment.razorpayOrderId,
        razorpayPaymentId: payment.razorpayPaymentId,
        createdAt: payment.createdAt,
      },
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/payments/payment-failed
 * Auth required.
 * Body: { razorpay_order_id, error? }
 * Records that Razorpay reported a failure on the modal. Best-effort, never 500.
 */
router.post("/payment-failed", requireAuth, async (req, res) => {
  try {
    const { razorpay_order_id } = req.body || {};
    if (razorpay_order_id) {
      await Payment.findOneAndUpdate(
        { razorpayOrderId: razorpay_order_id, user: req.user._id },
        { status: "failed" }
      );
    }
  } catch (err) {
    console.error("[payments] failed to record payment failure:", err);
  }
  return res.json({ ok: true });
});

module.exports = router;

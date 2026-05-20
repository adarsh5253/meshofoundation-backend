const mongoose = require("mongoose");

/**
 * One row per Razorpay order we create. Lifecycle:
 *   created  -> order placed with Razorpay, modal not yet opened
 *   paid     -> signature verified after a successful checkout
 *   failed   -> Razorpay reported payment.failed for this order
 *
 * We record `purpose` so a single payments table can serve donations and
 * career applications without separate collections.
 */
const paymentSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    purpose: {
      type: String,
      enum: ["donation", "career-application"],
      required: true,
    },
    // Free-form metadata about what the payment is for, e.g. job title.
    note: { type: String, default: "" },

    amount: { type: Number, required: true, min: 100 }, // paise
    currency: { type: String, default: "INR" },
    receipt: { type: String, required: true },

    razorpayOrderId: { type: String, required: true, unique: true, index: true },
    razorpayPaymentId: { type: String, default: null },
    razorpaySignature: { type: String, default: null },

    status: {
      type: String,
      enum: ["created", "paid", "failed"],
      default: "created",
      index: true,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Payment", paymentSchema);

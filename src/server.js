require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");

const { connectDB } = require("./config/db");
const authRoutes = require("./routes/auth");
const paymentRoutes = require("./routes/payments");
const profileRoutes = require("./routes/profile");

const app = express();

// --- CORS ---

// --- CORS ---
const allowedOrigins = [
  "http://localhost:5173",
  "https://meshofoundation-frontend.vercel.app",
  // https://meshofoundation-frontend.vercel.app/
];

app.use(
  cors({
    origin(origin, cb) {
      // Allow requests without an Origin header (Postman, curl, server-to-server)
      if (!origin) return cb(null, true);

      if (allowedOrigins.includes(origin)) return cb(null, true);

      return cb(new Error(`CORS: origin ${origin} is not allowed`));
    },
    credentials: true,
  })
);

// --- Body parsers ---
app.use(express.json({ limit: "100kb" }));

// --- Routes ---
app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    dbConnected: mongoose.connection.readyState === 1,
    timestamp: new Date().toISOString(),
  });
});

app.use("/api/auth", authRoutes);
app.use("/api/payments", paymentRoutes);
app.use("/api/profile", profileRoutes);

// 404
app.use((req, res) => {
  res.status(404).json({ message: `Not Found: ${req.method} ${req.originalUrl}` });
});

// Central error handler
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error("[error]", err);
  const status = err.status || 500;
  res.status(status).json({
    message: err.expose ? err.message : "Something went wrong on the server",
  });
});

// --- Start ---
const PORT = Number(process.env.PORT) || 5000;

// Tell ourselves which Razorpay mode is active so we don't accidentally take
// real payments in dev (or fail to take them in prod).
function reportRazorpayMode() {
  const id = process.env.RAZORPAY_KEY_ID || "";
  if (!id) {
    console.warn("[razorpay] NOT CONFIGURED — payment endpoints will return 500");
    return;
  }
  if (id.startsWith("rzp_live_")) {
    console.log("[razorpay] LIVE mode — real payments will be processed");
  } else if (id.startsWith("rzp_test_")) {
    console.log("[razorpay] TEST mode — using sandbox cards / no real money");
  } else {
    console.warn(`[razorpay] unrecognised key prefix: ${id.slice(0, 9)}…`);
  }
}

connectDB(process.env.MONGODB_URI)
  .then(() => {
    app.listen(PORT, () => {
      console.log(`[server] listening on http://localhost:${PORT}`);
      console.log(`[server] allowed origins: ${allowedOrigins.join(", ")}`);
      reportRazorpayMode();
    });
  })
  .catch((err) => {
    console.error("[startup] failed to start:", err.message);
    process.exit(1);
  });

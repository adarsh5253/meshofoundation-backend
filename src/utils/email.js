const nodemailer = require("nodemailer");

let cachedTransporter = null;

function getTransporter() {
  if (cachedTransporter) return cachedTransporter;

  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !port || !user || !pass) return null;

  cachedTransporter = nodemailer.createTransport({
    host,
    port,
    // Port 465 uses implicit SSL, 587 uses STARTTLS
    secure: port === 465,
    auth: { user, pass },
  });

  return cachedTransporter;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Send a one-time password (OTP) to verify the user's email.
 * If SMTP isn't configured OR sending fails, the OTP is logged to the server
 * console so developers can continue testing locally.
 */
async function sendOtpEmail({ to, name, otp, ttlMinutes = 10 }) {
  const subject = `Your Mesho Foundation verification code: ${otp}`;

  const text =
    `Hi ${name || "there"},\n\n` +
    `Your verification code for Mesho Foundation is:\n\n` +
    `    ${otp}\n\n` +
    `This code expires in ${ttlMinutes} minutes. ` +
    `If you didn't request this code, you can safely ignore this email.`;

  const html = `
    <div style="font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#111;">
      <h2 style="margin:0 0 8px;">Verify your email</h2>
      <p style="margin:0 0 20px;color:#555;">Hi ${escapeHtml(name || "there")}, use the code below to verify your account.</p>
      <div style="background:#f5f5f5;border-radius:12px;padding:20px;text-align:center;margin:20px 0;">
        <div style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:34px;font-weight:700;letter-spacing:10px;color:#111;">
          ${escapeHtml(otp)}
        </div>
      </div>
      <p style="color:#555;font-size:14px;margin:0 0 4px;">This code expires in ${ttlMinutes} minutes.</p>
      <hr style="border:none;border-top:1px solid #eee;margin:24px 0;" />
      <p style="color:#888;font-size:12px;margin:0;">If you didn't create an account with Mesho Foundation, you can safely ignore this email.</p>
    </div>
  `.trim();

  const logFallback = (reason) => {
    console.log(`\n==================== OTP (${reason}) ====================`);
    console.log(`To:     ${to}`);
    console.log(`Code:   ${otp}`);
    console.log(`Expires in: ${ttlMinutes} minutes`);
    console.log("=========================================================\n");
  };

  const transporter = getTransporter();
  if (!transporter) {
    logFallback("dev fallback — no SMTP configured");
    return { fallback: true };
  }

  const from = process.env.EMAIL_FROM || process.env.SMTP_USER;

  try {
    const info = await transporter.sendMail({ from, to, subject, text, html });
    console.log(`[email] OTP sent to ${to} (messageId=${info.messageId})`);
    return { fallback: false, messageId: info.messageId };
  } catch (err) {
    console.error("\n[email] SMTP send failed:", err.message);
    logFallback("SMTP failed fallback");
    return { fallback: true, error: err.message };
  }
}

module.exports = { sendOtpEmail };

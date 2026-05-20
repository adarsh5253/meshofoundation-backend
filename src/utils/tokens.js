const crypto = require("crypto");

/** Generate a URL-safe random token. Default 32 bytes → 64 hex chars. */
function generateToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

module.exports = { generateToken };

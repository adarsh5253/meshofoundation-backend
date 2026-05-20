const { verifyToken } = require("../utils/jwt");
const User = require("../models/User");

/**
 * Protect routes: require a valid JWT in the Authorization header.
 * Expected header format: `Authorization: Bearer <token>`
 */
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const [scheme, token] = header.split(" ");

    if (scheme !== "Bearer" || !token) {
      return res
        .status(401)
        .json({ message: "Missing or invalid Authorization header" });
    }

    const payload = verifyToken(token);
    const user = await User.findById(payload.sub);
    if (!user) {
      return res.status(401).json({ message: "User no longer exists" });
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Session expired. Please log in again." });
    }
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

module.exports = { requireAuth };

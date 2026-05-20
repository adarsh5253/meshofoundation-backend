const express = require("express");
const validator = require("validator");

const User = require("../models/User");
const { requireAuth } = require("../middleware/auth");

const router = express.Router();

// Mongoose enums must accept these (mirror the schema).
const GENDERS = ["", "male", "female", "other", "prefer-not-to-say"];
const QUALIFICATIONS = [
  "",
  "high-school",
  "intermediate",
  "diploma",
  "undergraduate",
  "graduate",
  "postgraduate",
  "doctorate",
];
const AVAILABILITY = ["", "weekdays", "weekends", "evenings", "flexible"];

/** Coerce a value to string and trim, returning undefined if not a string. */
function str(v, max = 500) {
  if (v == null) return undefined;
  if (typeof v !== "string") return undefined;
  return v.trim().slice(0, max);
}

/** Coerce a value to a finite number or null. */
function num(v) {
  if (v === "" || v == null) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

/** Validate URL string — accepts empty string, otherwise must look like http(s). */
function url(v) {
  const s = str(v, 500);
  if (s === undefined) return undefined;
  if (s === "") return "";
  return validator.isURL(s, { require_protocol: true }) ? s : undefined;
}

/**
 * GET /api/profile
 * Returns the current user including their profile sub-document.
 */
router.get("/", requireAuth, (req, res) => {
  res.json({ user: req.user.toSafeJSON() });
});

/**
 * PATCH /api/profile
 * Body: any subset of profile fields. Unknown fields are ignored.
 * Returns the updated user.
 */
router.patch("/", requireAuth, async (req, res, next) => {
  try {
    const body = req.body || {};
    const user = req.user;

    // Lazy-init the profile sub-doc on first save.
    if (!user.profile) user.profile = {};
    const p = user.profile;

    // --- Personal ---
    if ("dob" in body) {
      if (body.dob === null || body.dob === "") {
        p.dob = null;
      } else {
        const d = new Date(body.dob);
        if (Number.isNaN(d.getTime())) {
          return res.status(400).json({ message: "Invalid date of birth." });
        }
        if (d.getTime() > Date.now()) {
          return res.status(400).json({ message: "Date of birth can't be in the future." });
        }
        p.dob = d;
      }
    }
    if ("gender" in body) {
      const g = str(body.gender, 30) ?? "";
      if (!GENDERS.includes(g)) {
        return res.status(400).json({ message: "Invalid gender value." });
      }
      p.gender = g;
    }
    if ("phone" in body) {
      const phone = str(body.phone, 20) ?? "";
      // Permissive: digits, +, spaces, hyphens, parens. We don't enforce E.164.
      if (phone && !/^[0-9+\-()\s]{7,20}$/.test(phone)) {
        return res.status(400).json({ message: "Invalid phone number." });
      }
      p.phone = phone;
    }
    if ("bio" in body) {
      const bio = str(body.bio, 500);
      if (bio === undefined) {
        return res.status(400).json({ message: "Bio must be a string." });
      }
      p.bio = bio;
    }

    // --- Address ---
    if (body.address && typeof body.address === "object") {
      if (!p.address) p.address = {};
      const a = body.address;
      ["line1", "line2", "city", "state", "country"].forEach((k) => {
        if (k in a) {
          const s = str(a[k], 160);
          if (s !== undefined) p.address[k] = s;
        }
      });
      if ("pincode" in a) {
        const pin = str(a.pincode, 12) ?? "";
        if (pin && !/^[A-Za-z0-9\s-]{3,12}$/.test(pin)) {
          return res.status(400).json({ message: "Invalid pincode." });
        }
        p.address.pincode = pin;
      }
    }

    // --- Education ---
    if (body.education && typeof body.education === "object") {
      if (!p.education) p.education = {};
      const e = body.education;
      if ("highestQualification" in e) {
        const q = str(e.highestQualification, 30) ?? "";
        if (!QUALIFICATIONS.includes(q)) {
          return res.status(400).json({ message: "Invalid qualification." });
        }
        p.education.highestQualification = q;
      }
      if ("fieldOfStudy" in e) {
        const f = str(e.fieldOfStudy, 120);
        if (f !== undefined) p.education.fieldOfStudy = f;
      }
      if ("institution" in e) {
        const i = str(e.institution, 160);
        if (i !== undefined) p.education.institution = i;
      }
      if ("graduationYear" in e) {
        const y = num(e.graduationYear);
        if (y === undefined) {
          return res.status(400).json({ message: "Invalid graduation year." });
        }
        if (y !== null && (y < 1950 || y > 2100)) {
          return res.status(400).json({ message: "Graduation year out of range." });
        }
        p.education.graduationYear = y;
      }
    }

    // --- Professional ---
    if (body.professional && typeof body.professional === "object") {
      if (!p.professional) p.professional = {};
      const pr = body.professional;
      if ("currentRole" in pr) {
        const v = str(pr.currentRole, 120);
        if (v !== undefined) p.professional.currentRole = v;
      }
      if ("organization" in pr) {
        const v = str(pr.organization, 160);
        if (v !== undefined) p.professional.organization = v;
      }
      if ("yearsOfExperience" in pr) {
        const n = num(pr.yearsOfExperience);
        if (n === undefined) {
          return res.status(400).json({ message: "Invalid years of experience." });
        }
        if (n !== null && (n < 0 || n > 80)) {
          return res.status(400).json({ message: "Years of experience out of range." });
        }
        p.professional.yearsOfExperience = n;
      }
      if ("skills" in pr) {
        if (!Array.isArray(pr.skills)) {
          return res.status(400).json({ message: "Skills must be an array." });
        }
        const skills = pr.skills
          .map((s) => str(s, 60))
          .filter((s) => typeof s === "string" && s.length > 0);
        if (skills.length > 30) {
          return res.status(400).json({ message: "At most 30 skills." });
        }
        p.professional.skills = skills;
      }
    }

    // --- Resume + interests + availability + social ---
    if ("resumeUrl" in body) {
      const u = url(body.resumeUrl);
      if (u === undefined) {
        return res.status(400).json({
          message: "Resume URL must be a full http(s) link, e.g. https://drive.google.com/...",
        });
      }
      p.resumeUrl = u;
    }
    if ("interests" in body) {
      if (!Array.isArray(body.interests)) {
        return res.status(400).json({ message: "Interests must be an array." });
      }
      const interests = body.interests
        .map((s) => str(s, 60))
        .filter((s) => typeof s === "string" && s.length > 0);
      if (interests.length > 12) {
        return res.status(400).json({ message: "At most 12 interests." });
      }
      p.interests = interests;
    }
    if ("availability" in body) {
      const a = str(body.availability, 30) ?? "";
      if (!AVAILABILITY.includes(a)) {
        return res.status(400).json({ message: "Invalid availability value." });
      }
      p.availability = a;
    }
    if (body.social && typeof body.social === "object") {
      if (!p.social) p.social = {};
      for (const k of ["linkedin", "twitter", "github", "website"]) {
        if (k in body.social) {
          const u = url(body.social[k]);
          if (u === undefined) {
            return res.status(400).json({
              message: `Invalid ${k} URL — must be a full http(s) link.`,
            });
          }
          p.social[k] = u;
        }
      }
    }
    if ("avatarUrl" in body) {
      const u = url(body.avatarUrl);
      if (u === undefined) {
        return res.status(400).json({ message: "Invalid avatar URL." });
      }
      p.avatarUrl = u;
    }

    // Top-level name change — handy for users who signed up with a typo.
    if ("name" in body) {
      const n = str(body.name, 100);
      if (!n || n.length < 2) {
        return res.status(400).json({ message: "Name must be at least 2 characters." });
      }
      user.name = n;
    }

    // Stamp completedAt the first time a user fills in any of the meaningful fields.
    if (
      !p.completedAt &&
      (p.dob || p.phone || p.bio || (p.address && p.address.city))
    ) {
      p.completedAt = new Date();
    }

    await user.save();
    return res.json({ user: user.toSafeJSON() });
  } catch (err) {
    if (err && err.name === "ValidationError") {
      const first = Object.values(err.errors)[0];
      return res.status(400).json({ message: first?.message || "Validation failed" });
    }
    next(err);
  }
});

module.exports = router;

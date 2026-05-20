const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const validator = require("validator");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      minlength: [2, "Name must be at least 2 characters"],
      maxlength: [100, "Name must be at most 100 characters"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      trim: true,
      lowercase: true,
      unique: true,
      validate: {
        validator: (v) => validator.isEmail(v),
        message: "Please provide a valid email address",
      },
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [8, "Password must be at least 8 characters"],
      select: false,
    },

    // --- Email verification via OTP ---
    isVerified: {
      type: Boolean,
      default: false,
    },
    // bcrypt hash of the 6-digit OTP (never store in plaintext)
    otpHash: { type: String, select: false },
    otpExpires: { type: Date, select: false },
    otpAttempts: { type: Number, default: 0, select: false },

    // --- Profile (all optional; populated after signup via /api/profile) ---
    profile: {
      // Personal
      dob: { type: Date, default: null },
      gender: {
        type: String,
        enum: ["male", "female", "other", "prefer-not-to-say", ""],
        default: "",
      },
      phone: { type: String, default: "", trim: true, maxlength: 20 },
      bio: { type: String, default: "", maxlength: 500 },
      avatarUrl: { type: String, default: "" },

      // Address
      address: {
        line1: { type: String, default: "", maxlength: 120 },
        line2: { type: String, default: "", maxlength: 120 },
        city: { type: String, default: "", maxlength: 80 },
        state: { type: String, default: "", maxlength: 80 },
        country: { type: String, default: "India", maxlength: 80 },
        pincode: { type: String, default: "", maxlength: 12 },
      },

      // Education
      education: {
        highestQualification: {
          type: String,
          enum: [
            "",
            "high-school",
            "intermediate",
            "diploma",
            "undergraduate",
            "graduate",
            "postgraduate",
            "doctorate",
          ],
          default: "",
        },
        fieldOfStudy: { type: String, default: "", maxlength: 120 },
        institution: { type: String, default: "", maxlength: 160 },
        graduationYear: {
          type: Number,
          default: null,
          min: 1950,
          max: 2100,
        },
      },

      // Professional
      professional: {
        currentRole: { type: String, default: "", maxlength: 120 },
        organization: { type: String, default: "", maxlength: 160 },
        yearsOfExperience: {
          type: Number,
          default: null,
          min: 0,
          max: 80,
        },
        skills: {
          type: [String],
          default: [],
          validate: {
            validator: (arr) => arr.length <= 30,
            message: "At most 30 skills",
          },
        },
      },

      // Documents — stored as URLs (e.g. Google Drive, Dropbox).
      // The /api/profile/resume endpoint also accepts a direct upload and
      // populates this with a server-relative path.
      resumeUrl: { type: String, default: "", maxlength: 500 },

      // Volunteering preferences
      interests: {
        type: [String],
        default: [],
        // Free-form tag list, but we cap it to keep the UI sane.
        validate: {
          validator: (arr) => arr.length <= 12,
          message: "At most 12 interests",
        },
      },
      availability: {
        type: String,
        enum: ["", "weekdays", "weekends", "evenings", "flexible"],
        default: "",
      },

      // Social / professional links
      social: {
        linkedin: { type: String, default: "", maxlength: 200 },
        twitter: { type: String, default: "", maxlength: 200 },
        github: { type: String, default: "", maxlength: 200 },
        website: { type: String, default: "", maxlength: 200 },
      },

      // Bookkeeping — useful for "complete your profile" prompts.
      completedAt: { type: Date, default: null },
    },
  },
  { timestamps: true }
);

// Hash password before saving when modified/new
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.comparePassword = async function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

/** Generate a fresh 6-digit OTP, hash+store it, and return the plaintext code to email. */
userSchema.methods.setOtp = async function (ttlMs) {
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const salt = await bcrypt.genSalt(10);
  this.otpHash = await bcrypt.hash(otp, salt);
  this.otpExpires = new Date(Date.now() + ttlMs);
  this.otpAttempts = 0;
  return otp;
};

/** Compare a candidate OTP against the stored hash. */
userSchema.methods.compareOtp = async function (candidate) {
  if (!this.otpHash) return false;
  return bcrypt.compare(String(candidate), this.otpHash);
};

userSchema.methods.clearOtp = function () {
  this.otpHash = undefined;
  this.otpExpires = undefined;
  this.otpAttempts = 0;
};

userSchema.methods.toSafeJSON = function () {
  // Mongoose subdocs serialise fine via JSON.stringify, but `toObject()` gives
  // us a plain object we can safely send.
  const profile = this.profile ? this.profile.toObject() : {};
  return {
    id: this._id.toString(),
    name: this.name,
    email: this.email,
    isVerified: this.isVerified,
    createdAt: this.createdAt,
    profile,
  };
};

module.exports = mongoose.model("User", userSchema);

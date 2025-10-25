import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import {
  BadRequestError,
  NotFoundError,
  UnauthenticatedError,
} from "../errors/index.js";

const UserSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
        "Please enter a valid email address",
      ],
    },
    password: {
      type: String,
    },
    name: {
      type: String,
      maxlength: 50,
      minlength: 3,
    },
    login_pin: {
      type: String,
      minlength: 4,
      maxlength: 4,
    },
    phone_number: {
      type: String,
      match: [
        /^[0-9]{10}$/,
        "Please add a valid phone number without space =s or special characters",
      ],
      unique: true,
      sparse: true,
    },
    date_of_birth: Date,

    biometricKey: String,
    gender: {
      type: String,
      enum: ["male", "female", "other"],
    },
    wrong_pin_attempts: {
      type: Number,
      default: 0,
    },
    blocked_until_pin: {
      type: Date,
      default: null,
    },
    wrong_password_attempts: {
      type: Number,
      default: 0,
    },
    blocked_until_password: {
      type: Date,
      default: null,
    },
    balance: {
      type: Number,
      default: 50000.0,
    },
  },
  { timestamps: true }
);

UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
});

UserSchema.pre("save", async function () {
  if (!this.isModified("login_pin")) {
    const salt = await bcrypt.genSalt(10);
    this.login_pin = await bcrypt.hash(this.login_pin, salt);
  }
});

UserSchema.statics.updatePIN = async function (email, newPIN) {
  try {
    const user = await this.findOne({ email });
    if (!user) throw new NotFoundError("User Not Found");

    const salt = await bcrypt.genSalt(10);
    const hashedPIN = await bcrypt.hash(newPIN, salt);

    await this.findOneAndUpdate(
      { email },
      { login_pin: hashedPIN, wrong_pin_attempts: 0, blocked_until_pin: null }
    );
    return { success: true, message: "PIN updated successfully" };
  } catch (error) {
    throw error;
  }
};

UserSchema.statics.updatePassword = async function (email, newPassword) {
  try {
    const user = await this.findOne({ email });
    if (!user) throw new NotFoundError("User Not Found");

    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword)
      throw new BadRequestError(
        "New password must be different from the old password"
      );

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await this.findOneAndUpdate(
      { email },
      {
        password: hashedPassword,
        wrong_password_attempts: 0,
        blocked_until_password: null,
      }
    );
    return { success: true, message: "Password updated successfully" };
  } catch (error) {
    throw error;
  }
};

UserSchema.method.comparePassword = async function (candidatePassword) {
  if (this.blocked_until_password && this.blocked_until_password > new Date())
    throw new UnauthenticatedError(
      "Invalid login attempts exceeded. Please try after 30 minutes."
    );

  const isMatch = await bcrypt.compare(candidatePassword, this.password);

  if (!isMatch) {
    this.wrong_password_attempts += 1;
    if (this.wrong_password_attempts >= 3) {
      this.blocked_until_password = new Date(Date.now() + 30 * 60 * 1000);
      this.wrong_password_attempts = 0;
    }
    await this.save();
    throw new UnauthenticatedError("Invalid Credentials");
  } else {
    this.wrong_password_attempts = 0;
    this.blocked_until_password = null;
    await this.save();
  }
  return isMatch;
};

UserSchema.method.comparePIN = async function comparePIN(candidatePIN) {
  if (this.blocked_until_pin && this.blocked_until_pin > new Date())
    throw new UnauthenticatedError(
      "Limit Exceeded. Please try after 30 minutes."
    );

  const hashedPIN = this.login_pin;

  const isMatch = await bcrypt.compare(candidatePIN, hashedPIN);

  if (!isMatch) {
    this.wrong_pin_attempts += 1;
    if (this.wrong_pin_attempts >= 3) {
      this.blocked_until_pin = new Date(Date.now() + 30 * 60 * 1000);
      this.wrong_pin_attempts = 0;
    }
    await this.save();
  } else {
    this.wrong_pin_attempts = 0;
    this.blocked_until_pin = null;
    await this.save();
  }
  return isMatch;
};

UserSchema.methods.createAccessToken = function () {
  return jwt.sign(
    { userId: this._id, name: this.name },
    process.env.JWT_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
  );
};

UserSchema.methods.createRefreshToken = function () {
  return jwt.sign(
    { userId: this._id, name: this.name },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
  );
};

const User = mongoose.model("User", UserSchema);
export default User;

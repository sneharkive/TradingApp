import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const OtpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  otp: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expired: 60 * 5,
  },
  otp_type: {
    type: String,
    enum: ["phone", "email", "reset_password", "reset_pin"],
    required: true,
  },
});

OtpSchema.pre("save", async function(next){
  if(this.isNew){
    const salt = await bcrypt.genSalt(10);
    await sendVerificationMail(this.email, this.otp, this.optType);
    this.otp = await bcrypt.hash(this.otp, salt);
  }

  next();
});

OtpSchema.methods.compareOtp = async function (enteredOtp){
  return await bcrypt.compare(enteredOtp, this.otp);
}

async function sendVerificationMail(email, otp, otpType){
  try{
    const mailResponse = await mailSender(email, otp, otpType);
  }
  catch(error){
    console.log(error);
    throw error;
  }
}
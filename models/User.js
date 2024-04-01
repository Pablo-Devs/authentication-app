import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  googleId: String,
  otp: String,
  otpExpires: Date
});

export default mongoose.model('User', userSchema);
import express from 'express';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import passport from 'passport';
import User from './models/User.js';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

const app = express();
app.use(bodyParser.json());

// Load environment variables from .env file
import dotenv from 'dotenv';
dotenv.config();

// MongoDB connection
mongoose.connect(`${process.env.MONGO_URL}`)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// Passport middleware
app.use(passport.initialize());

// Passport local strategy
passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
},
    async (email, password, done) => {
        try {
            const user = await User.findOne({ email });
            if (!user) return done(null, false, { message: 'Email not found' });

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) return done(null, false, { message: 'Invalid password' });

            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

// Passport Google OAuth strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
},
    async (accessToken, refreshToken, profile, done) => {
        try {
            let user = await User.findOne({ googleId: profile.id });
            if (!user) {
                user = new User({
                    googleId: profile.id,
                    email: profile.emails[0].value
                });
                await user.save();
            }
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

// Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

// Signup route
app.post('/signup', async (req, res) => {
    try {
        const existingUser = await User.findOne({ email: req.body.email });
        if (existingUser) return res.status(400).json({ message: 'Email already exists' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);

        const user = new User({
            email: req.body.email,
            password: hashedPassword
        });
        await user.save();
        res.status(200).json({ message: 'User created successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Login route with email/password
app.post('/login', passport.authenticate('local', { session: false }), async (req, res) => {
    try {
        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000);
        req.user.otp = otp;
        req.user.otpExpires = Date.now() + 600000; // OTP expires in 10 minutes
        await req.user.save();

        // Send OTP to user's email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: req.user.email,
            subject: 'Login OTP',
            text: `Your OTP for login is: ${otp}`
        };
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending OTP:', error);
                res.status(500).json({ message: 'Error sending OTP' });
            } else {
                console.log('OTP sent:', info.response);
                res.status(200).json({ message: 'OTP sent to your email' });
            }
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// OTP verification route
app.post('/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'User not found' });

        if (user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }

        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
        res.header('auth-token', token).json({ token });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Google login route
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { session: false }),
    (req, res) => {
        const token = jwt.sign({ _id: req.user._id }, process.env.JWT_SECRET);
        res.header('auth-token', token).redirect('/dashboard');
    }
);

const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
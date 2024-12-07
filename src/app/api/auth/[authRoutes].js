import prisma from "../../../src/utils/prisma-client";
import bcrypt from "bcrypt";
import { handleError } from "../../../src/utils/error-handler";
import { authenticate } from "../../../src/middlewares/auth";
import { isAdmin } from "../../../src/middlewares/admin";
import { signToken } from "../../../src/config/jwt-config";
import crypto from "crypto";
import { sendMail } from "../../../src/utils/nodemailer-setup";

// Expiration time for OTP (in minutes)
const OTP_EXPIRATION_MINUTES = process.env.OTP_EXPIRATION_MINUTES;

export default async function handler(req, res) {
  const { authRoutes } = req.query;

  switch (authRoutes) {
    case "register":
      if (req.method === "POST") {
        await register(req, res, "USER"); // Default role is USER for public registration
      } else {
        res.setHeader("Allow", ["POST"]);
        res.status(405).end(`Method ${req.method} Not Allowed`);
      }
      break;
    case "admin":
      if (req.method === "POST") {
        authenticate(req, res, () =>
          isAdmin(req, res, () => register(req, res, req.body.role))
        );
      } else {
        res.setHeader("Allow", ["POST"]);
        res.status(405).end(`Method ${req.method} Not Allowed`);
      }
      break;
    case "login":
      if (req.method === "POST") {
        await login(req, res);
      } else {
        res.setHeader("Allow", ["POST"]);
        res.status(405).end(`Method ${req.method} Not Allowed`);
      }
      break;
    case "forgot-password":
      if (req.method === "POST") {
        await forgotPassword(req, res);
      } else {
        res.setHeader("Allow", ["POST"]);
        res.status(405).end(`Method ${req.method} Not Allowed`);
      }
      break;

    case "reset-password":
      if (req.method === "POST") {
        await resetPassword(req, res);
      } else {
        res.setHeader("Allow", ["POST"]);
        res.status(405).end(`Method ${req.method} Not Allowed`);
      }
      break;
    case "send-verification":
      if (req.method === "POST") {
        await sendVerification(req, res);
      } else {
        res.setHeader("Allow", ["POST"]);
        res.status(405).end(`Method ${req.method} Not Allowed`);
      }
      break;
    case "verify-account":
      if (req.method === "POST") {
        await verifyAccount(req, res);
      } else {
        res.setHeader("Allow", ["POST"]);
        res.status(405).end(`Method ${req.method} Not Allowed`);
      }
      break;
    default:
      res.status(404).json({ error: "Not found" });
  }
}

async function register(req, res, defaultRole) {
  const { name, email, password, role = defaultRole } = req.body;

  try {
    // Check if the email already exists in the database
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });
    if (existingUser) {
      return res.status(400).json({ error: "Email is already registered" });
    }

    // Hash the password before saving it to the database
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        role,
      },
    });

    // Remove the password before sending the response
    const { password: _, ...userWithoutPassword } = user;

    res.status(201).json({
      message: "User registered successfully",
      user: userWithoutPassword,
    });
  } catch (error) {
    handleError(res, error);
  }
}

async function login(req, res) {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = signToken({
      userId: user.id,
      userName: user.name,
      role: user.role,
    });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    handleError(res, error);
  }
}

async function forgotPassword(req, res) {
  const { email } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Generate OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiresAt = new Date(Date.now() + OTP_EXPIRATION_MINUTES * 60000);

    // Update user with OTP and expiration
    await prisma.user.update({
      where: { email },
      data: { otp, otpExpiresAt },
    });

    // Send OTP to user's email
    await sendMail({
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP is ${otp}. It expires in ${OTP_EXPIRATION_MINUTES} minutes.`,
    });

    res.status(200).json({ message: "OTP sent to email" });
  } catch (error) {
    handleError(res, error);
  }
}

async function resetPassword(req, res) {
  const { email, otp, newPassword } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user || user.otp !== otp || user.otpExpiresAt < new Date()) {
      return res.status(400).json({ error: "Invalid OTP or OTP expired" });
    }

    if (!newPassword) {
      return res.status(400).json({ error: "New Password not provided!" });
    }

    // Generate new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { email },
      data: {
        password: hashedPassword,
        otp: null, // Clear OTP
        otpExpiresAt: null,
      },
    });

    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    handleError(res, error);
  }
}

async function sendVerification(req, res) {
  const { email } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Generate OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiresAt = new Date(Date.now() + OTP_EXPIRATION_MINUTES * 60000);

    // Update user with OTP and expiration
    await prisma.user.update({
      where: { email },
      data: { otp, otpExpiresAt },
    });

    // Send OTP to user's email
    await sendMail({
      to: email,
      subject: "Account Verification OTP",
      text: `Your OTP is ${otp}. It expires in ${OTP_EXPIRATION_MINUTES} minutes.`,
    });

    res.status(200).json({ message: "OTP sent to email" });
  } catch (error) {
    handleError(res, error);
  }
}

async function verifyAccount(req, res) {
  const { email, otp } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user || user.otp !== otp || user.otpExpiresAt < new Date()) {
      return res.status(400).json({ error: "Invalid OTP or OTP expired" });
    }

    // Mark user as verified
    await prisma.user.update({
      where: { email },
      data: {
        verified: true,
        otp: null, // Clear OTP
        otpExpiresAt: null,
      },
    });

    res.status(200).json({ message: "Account verified successfully" });
  } catch (error) {
    handleError(res, error);
  }
}

const express = require("express");
const router = express.Router();
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const auth = require("../controllers/auth.controllers");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = process.env;

let restrict = async (req, res, next) => {
  let token = req.cookies.token;
  console.log("Token:", token);
  if (!token) {
    return res.redirect("/login");
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });
    console.log("User:", user);
    if (!user) {
      return res.redirect("/login");
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("Authentication error:", error);

    return res.redirect("/login");
  }
};

// Register
router.get("/register", auth.register);
router.post("/register", auth.register);

// Login
router.get("/login", auth.login);
router.post("/login", auth.login);

// Dashboard
router.get("/dashboard", restrict, auth.dashboard);

// Send email forgot password
router.get("/forgot-password", auth.forgotPassword);
router.post("/forgot-password", auth.forgotPassword);

// Reset Password
router.get("/reset-password", auth.resetPassword);
router.post("/reset-password", auth.resetPassword);

// Notification
router.get("/notification-message/:id", auth.notificationMessage);

module.exports = router;

const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = process.env;
const Sentry = require("../libs/sentry");
const { sendMail } = require("../libs/nodemailer");

module.exports = {
  register: async (req, res, next) => {
    if (req.method === "GET") {
      return res.render("register");
    }

    if (req.method === "POST") {
      Sentry.captureException("register");
      try {
        let { name, email, password } = req.body;
        if (!name || !email || !password) {
          return res.status(400).json({
            status: false,
            message: "name, email and password are required!",
            data: null,
          });
        }

        let exist = await prisma.user.findFirst({ where: { email } });
        if (exist) {
          return res.status(400).json({
            status: false,
            message: "email has already been used!",
            data: null,
          });
        }

        let encryptPass = await bcrypt.hash(password, 10);
        let userData = {
          name,
          email,
          password: encryptPass,
        };

        let user = await prisma.user.create({ data: userData });

        const notification = await prisma.notification.create({
          data: {
            title: "New User Registered",
            message: `${user.name} has registered with email ${user.email}`,
            userId: user.id,
          },
        });
        delete user.password;

        req.app.get("io").emit("register", { name });
        req.app.get("io").emit(`user-${user.id}`, notification);
        setTimeout(() => {
          return res.status(201).redirect("/login");
        }, 5000);
      } catch (error) {
        Sentry.captureException(error);
        next(error);
      }
    }
  },

  login: async (req, res, next) => {
    if (req.method === "GET") {
      return res.render("login");
    }

    if (req.method === "POST") {
      try {
        Sentry.captureException("login");

        let { email, password } = req.body;
        if (!email || !password) {
          return res.status(400).json({
            status: false,
            message: "email and password are required!",
            data: null,
          });
        }

        let user = await prisma.user.findFirst({ where: { email } });
        if (!user) {
          return res.status(400).json({
            status: false,
            message: "invalid email or password!",
            data: null,
          });
        }

        let isPassCorrect = await bcrypt.compare(password, user.password);
        if (!isPassCorrect) {
          return res.status(400).json({
            status: false,
            message: "invalid email or password!",
            data: null,
          });
        }

        delete user.password;
        let token = jwt.sign({ userId: user.id }, JWT_SECRET);
        console.info(token);
        res.cookie("token", token);
        return res.redirect("/dashboard");
      } catch (error) {
        Sentry.captureException(error);
        next(error);
      }
    }
  },

  dashboard: async (req, res, next) => {
    Sentry.captureException("dashboard");
    try {
      const user = await req.user;
      res.render("dashboard", {
        status: true,
        message: "Successfully logged in to the dashboard",
        user: user,
      });
    } catch (error) {
      Sentry.captureException(error);
      next(error);
    }
  },

  forgotPassword: async (req, res, next) => {
    if (req.method === "GET") {
      return res.render("forgot-password");
    }

    if (req.method === "POST") {
      Sentry.captureException("forgotPassword");
      try {
        const { email } = req.body;
        if (!email) {
          return res.status(400).json({
            status: false,
            message: "Email is required!",
            data: null,
          });
        }

        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
          return res.status(404).json({
            status: false,
            message: "User not found!",
            data: null,
          });
        }

        const token = jwt.sign({ id: user.id }, JWT_SECRET);

        const resetPassURL = `${req.protocol}://${req.get(
          "host"
        )}/reset-password?token=${token}`;

        const emailContent = `To reset your password visit the following address, otherwise just ignore this email and nothing will happen. \n
        ${resetPassURL}`;

        await sendMail(user.email, "Reset Password", emailContent);

        const notification = await prisma.notification.create({
          data: {
            title: "Forgot Password",
            message: `The forgot password link has been sent to email ${user.email}`,
            userId: user.id,
          },
        });

        req.app.get("io").emit("forgot-password", { email });
        req.app.get("io").emit(`user-${user.id}`, notification);

        setTimeout(() => {
          return res.status(201).redirect("/login");
        }, 5000);
      } catch (error) {
        Sentry.captureException(error);
        next(error);
      }
    }
  },

  resetPassword: async (req, res, next) => {
    if (req.method === "GET") {
      const token = req.query.token;
      return res.render("reset-password", { token: token });
    }

    if (req.method === "POST") {
      Sentry.captureException("resetPassword");
      try {
        const { name, token, password, confirmPassword } = req.body;

        if (!token || !password || !confirmPassword) {
          return res.status(400).json({
            status: false,
            message: "Token and new password are required!",
            data: null,
          });
        }

        if (password !== confirmPassword) {
          return res.status(400).json({
            status: false,
            message: "Passwords do not match!",
            data: null,
          });
        }

        let decodedToken;
        try {
          decodedToken = jwt.verify(token, JWT_SECRET);
        } catch (error) {
          return res.status(400).json({
            status: false,
            message: "Invalid or expired token!",
            data: null,
          });
        }

        const user = await prisma.user.findUnique({
          where: { id: decodedToken.id },
        });
        if (!user) {
          return res.status(404).json({
            status: false,
            message: "User not found!",
            data: null,
          });
        }

        const encryptPass = await bcrypt.hash(password, 10);

        await prisma.user.update({
          where: { id: decodedToken.id },
          data: { password: encryptPass },
        });

        const notification = await prisma.notification.create({
          data: {
            title: "New Password Reset",
            message: `Password successfully reset for username ${user.name} and email ${user.email}`,
            userId: user.id,
          },
        });

        req.app.get("io").emit("reset-password", { name });
        req.app.get("io").emit(`user-${user.id}`, notification);
        setTimeout(() => {
          return res.status(201).redirect("/login");
        }, 5000);
      } catch (error) {
        Sentry.captureException(error);
        next(error);
      }
    }
  },

  notificationMessage: async (req, res, next) => {
    if (req.method === "GET") {
      try {
        const userId = Number(req.params.id);

        const user = await prisma.user.findUnique({
          where: {
            id: userId,
          },
        });

        let message = "";

        if (!user) {
          message = "User not found";
        }

        const notifications = await prisma.notification.findMany({
          where: {
            userId: userId,
          },
        });

        res.render("notification-message", { notifications, message, userId });
      } catch (error) {
        next(error);
      }
    }
  },
};

require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = Number(process.env.PORT) || 5000;

if (!process.env.MONGODB_URI || !process.env.JWT_SECRET) {
  throw new Error("Missing MONGODB_URI or JWT_SECRET in .env");
}

if (process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must contain at least 32 characters");
}

// ================= SECURITY CONFIGURATION =================

app.disable("x-powered-by");
app.use(helmet());

app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || "http://localhost:3000"
}));

app.use(express.json({ limit: "20kb" }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

app.use("/api", apiLimiter);

// ================= DATABASE MODEL =================

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 80
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    maxlength: 254
  },
  password: {
    type: String,
    required: true,
    select: false
  },
  completedLessons: {
    type: [String],
    default: []
  },
  quizResults: {
    type: [{
      quizId: String,
      score: Number,
      total: Number,
      completedAt: {
        type: Date,
        default: Date.now
      }
    }],
    default: []
  }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

// ================= AWARENESS LESSONS =================

const lessons = [
  {
    id: "phishing",
    title: "Phishing Awareness",
    category: "Email Security",
    description: "Recognize fraudulent emails and suspicious links.",
    tips: [
      "Check the sender's email address.",
      "Avoid clicking unexpected links.",
      "Never share passwords or OTPs.",
      "Report suspicious messages."
    ]
  },
  {
    id: "passwords",
    title: "Password Security",
    category: "Account Security",
    description: "Learn to protect accounts using strong passwords.",
    tips: [
      "Use long, unique passwords.",
      "Use a reputable password manager.",
      "Enable multi-factor authentication.",
      "Never share your password."
    ]
  },
  {
    id: "malware",
    title: "Malware Protection",
    category: "Device Security",
    description: "Understand malware, viruses, and ransomware.",
    tips: [
      "Download software from trusted sources.",
      "Keep your operating system updated.",
      "Use reputable security software.",
      "Back up important files."
    ]
  },
  {
    id: "privacy",
    title: "Online Privacy",
    category: "Data Protection",
    description: "Protect your personal information online.",
    tips: [
      "Review social media privacy settings.",
      "Avoid sharing sensitive personal information.",
      "Verify websites before entering data.",
      "Use secure network connections."
    ]
  },
  {
    id: "wifi",
    title: "Wi-Fi Security",
    category: "Network Security",
    description: "Learn how to use wireless networks safely.",
    tips: [
      "Secure your router with a strong password.",
      "Use modern Wi-Fi security settings.",
      "Avoid sensitive transactions on untrusted networks.",
      "Keep router firmware updated."
    ]
  }
];

// ================= QUIZ QUESTIONS =================

const questions = [
  {
    id: 1,
    question: "What is phishing?",
    options: [
      "A data backup technique",
      "A fraudulent attempt to steal information",
      "A firewall configuration",
      "A software update"
    ],
    answer: 1
  },
  {
    id: 2,
    question: "Which is the best password practice?",
    options: [
      "Use 12345678",
      "Reuse the same password everywhere",
      "Use your date of birth",
      "Use long, unique passwords"
    ],
    answer: 3
  },
  {
    id: 3,
    question: "What should you do with a suspicious link?",
    options: [
      "Open it immediately",
      "Enter your password",
      "Avoid clicking and report it",
      "Forward it to everyone"
    ],
    answer: 2
  },
  {
    id: 4,
    question: "What does MFA mean?",
    options: [
      "Multiple File Access",
      "Multi-Factor Authentication",
      "Main Firewall Application",
      "Managed File Account"
    ],
    answer: 1
  },
  {
    id: 5,
    question: "Why should you update software?",
    options: [
      "To fix security vulnerabilities",
      "To remove every cyber risk",
      "To eliminate the need for passwords",
      "To disable account security"
    ],
    answer: 0
  }
];

// ================= AUTHENTICATION MIDDLEWARE =================

function authenticateToken(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Authentication token required"
    });
  }

  const token = authorization.slice(7);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ["HS256"]
    });

    if (!decoded.userId) {
      return res.status(401).json({
        message: "Invalid authentication token"
      });
    }

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      message: "Invalid or expired token"
    });
  }
}

// ================= HOME AND HEALTH CHECK =================

app.get("/", (req, res) => {
  res.json({
    name: "Cybersecurity Awareness Platform",
    message: "Backend API is running successfully",
    version: "1.0.0"
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    database: mongoose.connection.readyState === 1
      ? "connected"
      : "disconnected"
  });
});

// ================= USER REGISTRATION =================

app.post("/api/auth/register", authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (
      typeof name !== "string" ||
      !name.trim() ||
      name.trim().length > 80 ||
      typeof email !== "string" ||
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||
      typeof password !== "string" ||
      password.length < 12 ||
      password.length > 128
    ) {
      return res.status(400).json({
        message: "Provide a valid name and email. Password must be 12–128 characters."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await User.findOne({
      email: normalizedEmail
    });

    if (existingUser) {
      return res.status(409).json({
        message: "An account with this email already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password: hashedPassword
    });

    res.status(201).json({
      message: "Registration successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "An account with this email already exists"
      });
    }

    console.error("Registration error:", error.message);

    res.status(500).json({
      message: "Unable to register user"
    });
  }
});

// ================= USER LOGIN =================

app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      email.length > 254 ||
      password.length > 128
    ) {
      return res.status(400).json({
        message: "Valid email and password are required"
      });
    }

    const user = await User.findOne({
      email: email.trim().toLowerCase()
    }).select("+password");

    if (
      !user ||
      !(await bcrypt.compare(password, user.password))
    ) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const token = jwt.sign(
      { userId: user._id.toString() },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRES_IN || "1h",
        algorithm: "HS256"
      }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error("Login error:", error.message);

    res.status(500).json({
      message: "Unable to log in"
    });
  }
});

// ================= GET ALL LESSONS =================

app.get("/api/lessons", (req, res) => {
  res.json({
    total: lessons.length,
    lessons
  });
});

// ================= GET ONE LESSON =================

app.get("/api/lessons/:id", (req, res) => {
  const lesson = lessons.find(
    item => item.id === req.params.id
  );

  if (!lesson) {
    return res.status(404).json({
      message: "Lesson not found"
    });
  }

  res.json({ lesson });
});

// ================= COMPLETE A LESSON =================

app.post(
  "/api/lessons/:id/complete",
  authenticateToken,
  async (req, res) => {
    try {
      const lesson = lessons.find(
        item => item.id === req.params.id
      );

      if (!lesson) {
        return res.status(404).json({
          message: "Lesson not found"
        });
      }

      const user = await User.findById(req.user.userId);

      if (!user) {
        return res.status(404).json({
          message: "User not found"
        });
      }

      if (!user.completedLessons.includes(lesson.id)) {
        user.completedLessons.push(lesson.id);
        await user.save();
      }

      res.json({
        message: "Lesson completed successfully",
        completedLessons: user.completedLessons,
        completedCount: user.completedLessons.length,
        totalLessons: lessons.length
      });
    } catch (error) {
      console.error("Lesson error:", error.message);

      res.status(500).json({
        message: "Unable to update lesson progress"
      });
    }
  }
);

// ================= GET QUIZ QUESTIONS =================

app.get("/api/quizzes", (req, res) => {
  res.json({
    quizId: "cybersecurity-basics",
    title: "Cybersecurity Awareness Quiz",
    totalQuestions: questions.length,
    questions: questions.map(({ answer, ...question }) => question)
  });
});

// ================= SUBMIT QUIZ =================

app.post(
  "/api/quizzes/submit",
  authenticateToken,
  async (req, res) => {
    try {
      const { answers } = req.body;

      if (
        !Array.isArray(answers) ||
        answers.length !== questions.length ||
        answers.some(
          answer =>
            !Number.isInteger(answer) ||
            answer < 0 ||
            answer >= 4
        )
      ) {
        return res.status(400).json({
          message: "Submit one valid option for every question"
        });
      }

      const score = questions.reduce(
        (total, question, index) =>
          total + (answers[index] === question.answer ? 1 : 0),
        0
      );

      const user = await User.findById(req.user.userId);

      if (!user) {
        return res.status(404).json({
          message: "User not found"
        });
      }

      user.quizResults.push({
        quizId: "cybersecurity-basics",
        score,
        total: questions.length,
        completedAt: new Date()
      });

      await user.save();

      res.json({
        message: "Quiz submitted successfully",
        score,
        total: questions.length,
        percentage: Math.round(
          (score / questions.length) * 100
        ),
        passed: score >= 4
      });
    } catch (error) {
      console.error("Quiz error:", error.message);

      res.status(500).json({
        message: "Unable to submit quiz"
      });
    }
  }
);

// ================= USER DASHBOARD =================

app.get("/api/dashboard", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    const averageScore = user.quizResults.length
      ? Math.round(
          user.quizResults.reduce(
            (sum, result) =>
              sum + (result.score / result.total) * 100,
            0
          ) / user.quizResults.length
        )
      : 0;

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      },
      progress: {
        totalLessons: lessons.length,
        completedLessons: user.completedLessons,
        completedCount: user.completedLessons.length,
        completionPercentage: Math.round(
          (user.completedLessons.length / lessons.length) * 100
        ),
        quizAttempts: user.quizResults.length,
        averageQuizPercentage: averageScore,
        recentQuizResults: user.quizResults
          .slice(-10)
          .reverse()
      }
    });
  } catch (error) {
    console.error("Dashboard error:", error.message);

    res.status(500).json({
      message: "Unable to load dashboard"
    });
  }
});

// ================= 404 HANDLER =================

app.use("/api", (req, res) => {
  res.status(404).json({
    message: "API endpoint not found"
  });
});

// ================= ERROR HANDLER =================

app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  if (err instanceof SyntaxError && "body" in err) {
    return res.status(400).json({
      message: "Invalid JSON request body"
    });
  }

  console.error("Server error:", err.message);

  res.status(500).json({
    message: "Internal server error"
  });
});

// ================= START SERVER =================

async function startServer() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);

    console.log("MongoDB connected successfully");

    app.listen(PORT, () => {
      console.log(
        `Cybersecurity Awareness Platform running at http://localhost:${PORT}`
      );
    });
  } catch (error) {
    console.error("Failed to start server:", error.message);
    process.exit(1);
  }
}

startServer();

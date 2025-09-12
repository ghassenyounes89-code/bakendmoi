const express = require("express")
const mongoose = require("mongoose")
const cors = require("cors")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
require("dotenv").config()

const app = express()

// Middleware
app.use(cors())
app.use(express.json())

// MongoDB Connection - using users-app database based on your MongoDB Compass
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/users-app"

console.log("Connecting to MongoDB at:", MONGODB_URI)

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})

const db = mongoose.connection
db.on("error", console.error.bind(console, "MongoDB connection error:"))
db.once("open", () => {
  console.log("Successfully connected to MongoDB")

  // List all collections for debugging
  db.db.listCollections().toArray((err, names) => {
    if (err) {
      console.log("Error listing collections:", err)
    } else {
      console.log("Collections in database:")
      if (names.length === 0) {
        console.log("No collections found. They will be created when data is inserted.")
      } else {
        names.forEach((name) => {
          console.log(" - ", name.name)
        })
      }
    }
  })
})

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
})

// Use existing collection name or create new one
const User = mongoose.model("User", userSchema, "users")

// Comment Schema
const commentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true },
  approved: { type: Boolean, default: false },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
})

// Use existing collection name or create new one
const Comment = mongoose.model("Comment", commentSchema, "comments")

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    return res.status(401).json({ message: "Access token required" })
  }

  jwt.verify(token, process.env.JWT_SECRET || "your-secret-key", (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" })
    }
    req.user = user
    next()
  })
}

// Auth Routes
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body

    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" })
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email })
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" })
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12)

    // Create user
    const user = new User({ name, email, password: hashedPassword })
    await user.save()

    // Generate token
    const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET || "your-secret-key", {
      expiresIn: "24h",
    })

    res.status(201).json({
      message: "User created successfully",
      token,
      user: { id: user._id, name: user.name, email: user.email },
    })
  } catch (error) {
    console.error("Registration error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" })
    }

    // Find user
    const user = await User.findOne({ email })
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" })
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password)
    if (!isValidPassword) {
      return res.status(400).json({ message: "Invalid credentials" })
    }

    // Generate token
    const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET || "your-secret-key", {
      expiresIn: "24h",
    })

    res.json({
      message: "Login successful",
      token,
      user: { id: user._id, name: user.name, email: user.email },
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// Comment Routes
app.post("/api/comments", async (req, res) => {
  try {
    const { name, email, message } = req.body

    // Validate input
    if (!name || !email || !message) {
      return res.status(400).json({ message: "All fields are required" })
    }

    const comment = new Comment({ name, email, message, approved: true })
    await comment.save()

    res.status(201).json({ message: "Comment submitted successfully" })
  } catch (error) {
    console.error("Comment submission error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

app.get("/api/comments", async (req, res) => {
  try {
    // Get only approved comments, sorted by date
    const comments = await Comment.find({ approved: true }).sort({ createdAt: -1 }).limit(20)
    res.json(comments)
  } catch (error) {
    console.error("Fetch comments error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// Admin routes (protected)
app.get("/api/comments/admin", authenticateToken, async (req, res) => {
  try {
    const comments = await Comment.find().sort({ createdAt: -1 })
    res.json(comments)
  } catch (error) {
    console.error("Admin fetch comments error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

app.put("/api/comments/:id/approve", authenticateToken, async (req, res) => {
  try {
    const comment = await Comment.findByIdAndUpdate(req.params.id, { approved: true }, { new: true })

    if (!comment) {
      return res.status(404).json({ message: "Comment not found" })
    }

    res.json({ message: "Comment approved", comment })
  } catch (error) {
    console.error("Approve comment error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    database: mongoose.connection.readyState === 1 ? "Connected" : "Disconnected",
    timestamp: new Date().toISOString(),
  })
})

// Get user profile (protected)
app.get("/api/user/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password")
    if (!user) {
      return res.status(404).json({ message: "User not found" })
    }
    res.json(user)
  } catch (error) {
    console.error("Get user profile error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

const PORT = process.env.PORT || 5000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
  console.log(`Health check available at: http://localhost:${PORT}/api/health`)
})

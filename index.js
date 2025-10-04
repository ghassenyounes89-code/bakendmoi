const express = require("express")
const mongoose = require("mongoose")
const cors = require("cors")
const jwt = require("jsonwebtoken")
require("dotenv").config()

const app = express()

// Middleware
app.use(cors())
app.use(express.json())

// Config & Helpers
const JWT_SECRET = process.env.JWT_SECRET || "a-strong-and-unique-secret-key" 
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/users-app"

// Helper function to generate JWT
const generateToken = (visitor) => {
  return jwt.sign(
    {
      visitorId: visitor._id,
      email: visitor.email,
      name: visitor.name,
      commentCount: visitor.commentCount,
      role: visitor.role, 
    },
    JWT_SECRET,
    { expiresIn: "24h" },
  )
}

// MongoDB Connection
console.log("Connecting to MongoDB at:", MONGODB_URI)

mongoose.connect(MONGODB_URI);

const db = mongoose.connection
db.on("error", console.error.bind(console, "MongoDB connection error:"))
db.once("open", () => {
  console.log("Successfully connected to MongoDB")
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

// Mongoose Schemas
const visitorSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  commentCount: { type: Number, default: 0 },
  lastCommentAt: { type: Date },
  createdAt: { type: Date, default: Date.now },
  role: { type: String, default: "visitor", enum: ["visitor", "admin"] },
})

const Visitor = mongoose.model("Visitor", visitorSchema, "visitors")

const commentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true },
  approved: { type: Boolean, default: false }, 
  visitorId: { type: mongoose.Schema.Types.ObjectId, ref: "Visitor" },
  commentNumber: { type: Number, default: 1 },
  createdAt: { type: Date, default: Date.now },
})

const Comment = mongoose.model("Comment", commentSchema, "comments")

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    return res.status(401).json({ message: "Access token required" })
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" })
    }
    req.user = user 
    next()
  })
}

// Admin Authentication Middleware
const authenticateAdmin = (req, res, next) => {
  authenticateToken(req, res, () => {
    if (req.user && req.user.role === "admin") {
      next()
    } else {
      return res.status(403).json({ message: "Access denied: Admin privileges required" })
    }
  })
}

// ------------------------------------
// PUBLIC & VISITOR ROUTES
// ------------------------------------

// Endpoint for both Login and Register (front-end sends name and email)
app.post("/api/visitor/login", async (req, res) => {
  try {
    const { email, name } = req.body

    if (!email) {
      return res.status(400).json({ message: "Email is required" })
    }

    let visitor = await Visitor.findOne({ email })

    if (visitor) {
      // Update visitor name on login if it changed
      if (name && visitor.name !== name) {
        visitor.name = name
        await visitor.save()
      }
    } else {
      // Create new visitor if doesn't exist
      if (!name) {
        return res.status(400).json({ message: "Name is required for new visitors" })
      }
      visitor = new Visitor({ name, email })
      await visitor.save()
    }

    const token = generateToken(visitor)

    res.json({
      message: "Visitor login successful",
      token,
      visitor: {
        id: visitor._id,
        name: visitor.name,
        email: visitor.email,
        commentCount: visitor.commentCount,
        role: visitor.role,
      },
    })
  } catch (error) {
    console.error("Visitor login error:", error)
    if (error.code === 11000) { 
        return res.status(409).json({ message: "Email already in use." })
    }
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// Update visitor name
app.put("/api/visitor/profile", authenticateToken, async (req, res) => {
  try {
    const { name } = req.body

    if (!name) {
      return res.status(400).json({ message: "Name is required" })
    }

    const visitor = await Visitor.findByIdAndUpdate(req.user.visitorId, { name }, { new: true })

    if (!visitor) {
      return res.status(404).json({ message: "Visitor not found" })
    }

    const token = generateToken(visitor)

    res.json({
      message: "Profile updated successfully",
      token,
      visitor: {
        id: visitor._id,
        name: visitor.name,
        email: visitor.email,
        commentCount: visitor.commentCount,
        role: visitor.role,
      },
    })
  } catch (error) {
    console.error("Update profile error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// Submit a new comment (requires authentication)
app.post("/api/comments", authenticateToken, async (req, res) => {
  try {
    const { message } = req.body

    if (!message) {
      return res.status(400).json({ message: "Message is required" })
    }

    const visitor = await Visitor.findById(req.user.visitorId)
    if (!visitor) {
      return res.status(404).json({ message: "Visitor not found" })
    }

    const newCommentCount = visitor.commentCount + 1

    const comment = new Comment({
      name: visitor.name, 
      email: visitor.email, 
      message,
      approved: true, 
      visitorId: visitor._id,
      commentNumber: newCommentCount,
    })
    await comment.save()

    // Update visitor's comment count and last comment date
    visitor.commentCount = newCommentCount
    visitor.lastCommentAt = new Date()
    await visitor.save()

    res.status(201).json({
      message: "Comment submitted successfully and awaiting approval",
      commentNumber: newCommentCount,
      comment: {
        id: comment._id,
        name: comment.name,
        message: comment.message,
        commentNumber: comment.commentNumber,
        createdAt: comment.createdAt,
      },
    })
  } catch (error) {
    console.error("Comment submission error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// Get all approved comments
app.get("/api/comments", async (req, res) => {
  try {
    const comments = await Comment.find({ approved: true })
      .sort({ createdAt: -1 })
      .limit(50)
      .select("name message commentNumber createdAt") 

    res.json(comments)
  } catch (error) {
    console.error("Fetch comments error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// Get visitor's own comments
app.get("/api/comments/my-comments", authenticateToken, async (req, res) => {
  try {
    const comments = await Comment.find({ visitorId: req.user.visitorId })
      .sort({ createdAt: -1 })
      .select("name message commentNumber createdAt approved")

    res.json(comments)
  } catch (error) {
    console.error("Fetch my comments error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// Get visitor profile
app.get("/api/visitor/profile", authenticateToken, async (req, res) => {
  try {
    const visitor = await Visitor.findById(req.user.visitorId)
    if (!visitor) {
      return res.status(404).json({ message: "Visitor not found" })
    }

    res.json({
      id: visitor._id,
      name: visitor.name,
      email: visitor.email,
      commentCount: visitor.commentCount,
      lastCommentAt: visitor.lastCommentAt,
      createdAt: visitor.createdAt,
      role: visitor.role,
    })
  } catch (error) {
    console.error("Get visitor profile error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// ------------------------------------
// ADMIN ROUTES (PROTECTED)
// ------------------------------------

// Get all comments (for admin)
app.get("/api/comments/admin", authenticateAdmin, async (req, res) => {
  try {
    const comments = await Comment.find().sort({ createdAt: -1 }).populate("visitorId", "name email commentCount role")

    res.json(comments)
  } catch (error) {
    console.error("Admin fetch comments error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// Approve a comment (for admin)
app.put("/api/comments/:id/approve", authenticateAdmin, async (req, res) => {
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

const PORT = process.env.PORT || 5000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
  console.log(`Health check available at: http://localhost:${PORT}/api/health`)
})
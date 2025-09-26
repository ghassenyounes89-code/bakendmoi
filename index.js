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

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/users-app"

console.log("Connecting to MongoDB at:", MONGODB_URI)

// FIX: Removed deprecated Mongoose options (useNewUrlParser, useUnifiedTopology)
mongoose.connect(MONGODB_URI)

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

// Visitor Schema
const visitorSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  commentCount: { type: Number, default: 0 },
  lastCommentAt: { type: Date },
  createdAt: { type: Date, default: Date.now },
  // SECURITY ADDITION: Flag to identify admin users
  isAdmin: { type: Boolean, default: false }, 
})

// Use existing collection name or create new one
const Visitor = mongoose.model("Visitor", visitorSchema, "visitors")

// Comment Schema
const commentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true },
  approved: { type: Boolean, default: false },
  visitorId: { type: mongoose.Schema.Types.ObjectId, ref: "Visitor" },
  commentNumber: { type: Number, default: 1 }, // Which comment number this is for the visitor
  createdAt: { type: Date, default: Date.now },
})

// Use existing collection name or create new one
const Comment = mongoose.model("Comment", commentSchema, "comments")

// --- Auth Middleware for General Visitors ---
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

// --- Auth Middleware for Admins ---
const authenticateAdmin = async (req, res, next) => {
    const authHeader = req.headers["authorization"]
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({ message: "Access token required" })
    }

    jwt.verify(token, process.env.JWT_SECRET || "your-secret-key", async (err, user) => {
        if (err) {
            return res.status(403).json({ message: "Invalid token" })
        }
        
        try {
            // Check if the user is an admin by querying the database
            const visitor = await Visitor.findById(user.visitorId);

            if (!visitor || !visitor.isAdmin) {
                // Forbidden: user is not found or not an admin
                return res.status(403).json({ message: "Admin access denied" });
            }

            req.user = user
            next()
        } catch (error) {
            console.error("Admin authentication error:", error)
            return res.status(500).json({ message: "Server error during admin check" })
        }
    })
}

// --- Visitor Auth Routes ---
app.post("/api/visitor/login", async (req, res) => {
  try {
    const { email, name } = req.body

    // Validate input
    if (!email) {
      return res.status(400).json({ message: "Email is required" })
    }

    // Check if visitor exists
    let visitor = await Visitor.findOne({ email })

    if (!visitor) {
      // Create new visitor if doesn't exist
      if (!name) {
        return res.status(400).json({ message: "Name is required for new visitors" })
      }
      
      visitor = new Visitor({ name, email })
      await visitor.save()
    }

    // Generate token
    const token = jwt.sign(
      { 
        visitorId: visitor._id, 
        email: visitor.email,
        name: visitor.name,
        commentCount: visitor.commentCount,
        isAdmin: visitor.isAdmin // Include admin status in token
      }, 
      process.env.JWT_SECRET || "your-secret-key", 
      { expiresIn: "24h" }
    )

    res.json({
      message: "Visitor login successful",
      token,
      visitor: { 
        id: visitor._id, 
        name: visitor.name, 
        email: visitor.email,
        commentCount: visitor.commentCount,
        isAdmin: visitor.isAdmin 
      },
    })
  } catch (error) {
    console.error("Visitor login error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// Update visitor name (if they want to change it)
app.put("/api/visitor/profile", authenticateToken, async (req, res) => {
  try {
    const { name } = req.body

    if (!name) {
      return res.status(400).json({ message: "Name is required" })
    }

    const visitor = await Visitor.findByIdAndUpdate(
      req.user.visitorId, 
      { name }, 
      { new: true }
    )

    if (!visitor) {
      return res.status(404).json({ message: "Visitor not found" })
    }

    // Generate new token with updated name
    const token = jwt.sign(
      { 
        visitorId: visitor._id, 
        email: visitor.email,
        name: visitor.name,
        commentCount: visitor.commentCount,
        isAdmin: visitor.isAdmin
      }, 
      process.env.JWT_SECRET || "your-secret-key", 
      { expiresIn: "24h" }
    )

    res.json({
      message: "Profile updated successfully",
      token,
      visitor: { 
        id: visitor._id, 
        name: visitor.name, 
        email: visitor.email,
        commentCount: visitor.commentCount,
        isAdmin: visitor.isAdmin
      },
    })
  } catch (error) {
    console.error("Update profile error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// --- Comment Routes (protected by visitor authentication) ---
app.post("/api/comments", authenticateToken, async (req, res) => {
  try {
    const { message } = req.body

    // Validate input
    if (!message) {
      return res.status(400).json({ message: "Message is required" })
    }

    // Get visitor data
    const visitor = await Visitor.findById(req.user.visitorId)
    if (!visitor) {
      return res.status(404).json({ message: "Visitor not found" })
    }

    // Increment comment count
    const newCommentCount = visitor.commentCount + 1

    // Create comment with comment number
    const comment = new Comment({ 
      name: visitor.name, 
      email: visitor.email, 
      message, 
      approved: true, // Consider changing to false if you want manual admin review
      visitorId: visitor._id,
      commentNumber: newCommentCount
    })
    await comment.save()

    // Update visitor's comment count and last comment date
    visitor.commentCount = newCommentCount
    visitor.lastCommentAt = new Date()
    await visitor.save()

    res.status(201).json({ 
      message: "Comment submitted successfully",
      commentNumber: newCommentCount,
      comment: {
        id: comment._id,
        name: comment.name,
        message: comment.message,
        commentNumber: comment.commentNumber,
        createdAt: comment.createdAt
      }
    })
  } catch (error) {
    console.error("Comment submission error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

app.get("/api/comments", async (req, res) => {
  try {
    // Get only approved comments, sorted by date
    const comments = await Comment.find({ approved: true })
      .sort({ createdAt: -1 })
      .limit(20)
      .select('name message commentNumber createdAt')
    
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
      .select('name message commentNumber createdAt approved')
    
    res.json(comments)
  } catch (error) {
    console.error("Fetch my comments error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// --- Admin Routes (protected by admin authentication) ---
// CHANGE: Using authenticateAdmin
app.get("/api/comments/admin", authenticateAdmin, async (req, res) => {
  try {
    const comments = await Comment.find()
      .sort({ createdAt: -1 })
      .populate('visitorId', 'name email commentCount isAdmin')
    
    res.json(comments)
  } catch (error) {
    console.error("Admin fetch comments error:", error)
    res.status(500).json({ message: "Server error", error: error.message })
  }
})

// CHANGE: Using authenticateAdmin
app.put("/api/comments/:id/approve", authenticateAdmin, async (req, res) => {
  try {
    const comment = await Comment.findByIdAndUpdate(
      req.params.id, 
      { approved: true }, 
      { new: true }
    )

    if (!comment) {
      return res.status(404).json({ message: "Comment not found" })
    }

    res.json({ message: "Comment approved", comment })
  } catch (error) {
    console.error("Approve comment error:", error)
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
      isAdmin: visitor.isAdmin
    })
  } catch (error) {
    console.error("Get visitor profile error:", error)
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
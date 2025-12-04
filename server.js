// server.js
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret"; // replace in prod
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/expense_tracker";
const SALT_ROUNDS = 10;

// Connect to MongoDB
mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
    // modern mongoose doesn't need deprecated flags
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("MongoDB connection error:", err));

app.use(cors());
app.use(express.json()); // built-in body parser

// ========== Schemas & Models ==========
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const TransactionSchema = new mongoose.Schema({
  username: { type: String, required: true },
  description: { type: String, required: true },
  amount: { type: Number, required: true },
  type: { type: String, enum: ["income", "expense"], required: true },
  category: { type: String, required: true },
  date: { type: Date, required: true, default: Date.now }
});

const ProfileSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  name: { type: String, default: "" },
  email: { type: String, default: "" },
  profilePic: { type: String, default: "" },
  bio: { type: String, default: "" }
});

const UserDataSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  totalIncome: { type: Number, default: 0 },
  totalExpense: { type: Number, default: 0 },
  // Mongoose Map type: keys -> category, value -> Number (budget/balance)
  categoryBalance: { type: Map, of: Number, default: {} }
});

const User = mongoose.model("User", UserSchema);
const Transaction = mongoose.model("Transaction", TransactionSchema);
const Profile = mongoose.model("Profile", ProfileSchema);
const UserData = mongoose.model("UserData", UserDataSchema);

// ========== Auth middleware ==========
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token missing" });

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token" });
    // payload contains { username, iat, exp } (we sign username below)
    req.user = payload;
    next();
  });
};

// ========== API routes (prefixed with /api) ==========

// Register
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    await new User({ username, password: hashedPassword }).save();

    // initialize user data
    await new UserData({ username }).save();

    // (optional) initialize an empty profile (not strictly necessary)
    // await new Profile({ username }).save();

    res.json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Error registering user" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid password" });

    // Sign token with username as payload
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Error during login" });
  }
});

// Get profile
app.get("/api/profile", authenticateToken, async (req, res) => {
  const username = req.user.username;
  try {
    const profile = await Profile.findOne({ username });
    if (!profile) return res.status(404).json({ error: "Profile not found" });
    res.json(profile);
  } catch (err) {
    console.error("Profile fetch error:", err);
    res.status(500).json({ error: "Error fetching profile" });
  }
});

// Update profile
app.put("/api/profile", authenticateToken, async (req, res) => {
  const username = req.user.username;
  const { name, email, bio } = req.body;
  try {
    let profile = await Profile.findOne({ username });
    if (!profile) profile = new Profile({ username });

    if (name !== undefined) profile.name = name;
    if (email !== undefined) profile.email = email;
    if (bio !== undefined) profile.bio = bio;

    await profile.save();
    res.json({ message: "Profile updated successfully", profile });
  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ error: "Error updating profile" });
  }
});

// Update profile picture (URL)
app.put("/api/profile/picture", authenticateToken, async (req, res) => {
  const username = req.user.username;
  const { profilePic } = req.body;
  if (!profilePic) return res.status(400).json({ error: "Profile picture URL required" });

  try {
    const profile = await Profile.findOneAndUpdate(
      { username },
      { profilePic },
      { new: true, upsert: true }
    );
    res.json({ message: "Profile picture updated", profile });
  } catch (err) {
    console.error("Profile picture update error:", err);
    res.status(500).json({ error: "Error updating profile picture" });
  }
});

// Add transaction (protected) — date optional
app.post("/api/transaction", authenticateToken, async (req, res) => {
  let { description, amount, type, category, date } = req.body;
  const username = req.user.username;

  // basic validation
  if (!description || amount === undefined || !type || !category) {
    return res.status(400).json({ error: "Missing fields: description, amount, type, category are required" });
  }

  // coerce amount to number
  amount = Number(amount);
  if (Number.isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: "Amount must be a positive number" });
  }

  if (!["income", "expense"].includes(type)) {
    return res.status(400).json({ error: "Type must be 'income' or 'expense'" });
  }

  try {
    const userData = await UserData.findOne({ username });
    if (!userData) return res.status(404).json({ error: "User data not found" });

    // Budget check for expenses
    if (type === "expense") {
      // if category has budget set, check it
      if (userData.categoryBalance && userData.categoryBalance.has(category)) {
        const currentBalance = Number(userData.categoryBalance.get(category)) || 0;
        if (currentBalance - amount < 0) {
          console.log(`❌ Expense rejected! Budget exceeded for category: ${category}`);
          return res.status(400).json({ error: `Expense exceeds budget for ${category}! Remaining: ${currentBalance}` });
        }
      }
    }

    const transaction = new Transaction({
      username,
      description,
      amount,
      type,
      category,
      date: date ? new Date(date) : new Date()
    });
    await transaction.save();

    // Update totals and category balance
    if (type === "income") {
      userData.totalIncome += amount;
      // you might want to decide whether income should increase categoryBalance
      const current = Number(userData.categoryBalance.get(category)) || 0;
      userData.categoryBalance.set(category, current + amount);
    } else {
      userData.totalExpense += amount;
      const current = Number(userData.categoryBalance.get(category)) || 0;
      userData.categoryBalance.set(category, current - amount);
    }

    await userData.save();

    res.json({ message: "Transaction added successfully", transaction });
  } catch (err) {
    console.error("Add transaction error:", err);
    res.status(500).json({ error: "Error adding transaction" });
  }
});

// Get all transactions for user
app.get("/api/transactions", authenticateToken, async (req, res) => {
  const username = req.user.username;
  try {
    const transactions = await Transaction.find({ username }).sort({ date: -1 });
    res.json(transactions);
  } catch (err) {
    console.error("Fetch transactions error:", err);
    res.status(500).json({ error: "Error fetching transactions" });
  }
});

// Generate report
app.get("/api/report", authenticateToken, async (req, res) => {
  const username = req.user.username;
  try {
    const userData = await UserData.findOne({ username });
    if (!userData) return res.status(404).json({ error: "User data not found" });

    const netBalance = userData.totalIncome - userData.totalExpense;
    res.json({
      totalIncome: userData.totalIncome,
      totalExpense: userData.totalExpense,
      netBalance,
      // convert Mongoose Map to plain object
      categorySummary: Object.fromEntries(userData.categoryBalance || [])
    });
  } catch (err) {
    console.error("Report error:", err);
    res.status(500).json({ error: "Error generating report" });
  }
});

// Set budget for a category
app.post("/api/budget", authenticateToken, async (req, res) => {
  const { category, limit } = req.body;
  if (!category || limit === undefined) return res.status(400).json({ error: "Category and limit are required" });

  const username = req.user.username;
  const numericLimit = Number(limit);
  if (Number.isNaN(numericLimit)) return res.status(400).json({ error: "Limit must be a number" });

  try {
    const userData = await UserData.findOne({ username });
    if (!userData) return res.status(404).json({ error: "User data not found" });

    userData.categoryBalance.set(category, numericLimit);
    await userData.save();

    res.json({
      message: `Budget for ${category} set to ${numericLimit}`,
      categoryBalance: Object.fromEntries(userData.categoryBalance)
    });
  } catch (err) {
    console.error("Set budget error:", err);
    res.status(500).json({ error: "Error setting budget" });
  }
});

// Get budget overview
app.get("/api/budget", authenticateToken, async (req, res) => {
  const username = req.user.username;
  try {
    const userData = await UserData.findOne({ username });
    if (!userData) return res.status(404).json({ error: "User data not found" });

    res.json(Object.fromEntries(userData.categoryBalance || []));
  } catch (err) {
    console.error("Get budget error:", err);
    res.status(500).json({ error: "Error fetching budget" });
  }
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  if (JWT_SECRET === "your_jwt_secret") {
    console.warn("WARNING: Using default JWT_SECRET. Set process.env.JWT_SECRET in production!");
  }
  console.log(`Server running on http://localhost:${PORT}`);
});

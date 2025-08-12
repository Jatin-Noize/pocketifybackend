const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/expense_tracker";

// Connect to MongoDB

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  retryWrites: true,
  w: 'majority'
})
.then(() => console.log("Connected to MongoDB"))
.catch(err => console.error("MongoDB connection error:", err));

app.use(cors());
app.use(bodyParser.json());

// Define Mongoose Schemas
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const TransactionSchema = new mongoose.Schema({
  username: { type: String, required: true },
  description: { type: String, required: true },
  amount: { type: Number, required: true },
  type: { type: String, enum: ['income', 'expense'], required: true },
  category: { type: String, required: true },
  date: { type: Date, required: true, default: Date.now }
});

const ProfileSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  name: { type: String, default: "" },
  email: { type: String, default: "" },
  profilePic: { type: String, default: "" },
  bio: { type: String, default: "" },
});

const Profile = mongoose.model('Profile', ProfileSchema);

const UserDataSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  totalIncome: { type: Number, default: 0 },
  totalExpense: { type: Number, default: 0 },
  categoryBalance: { type: Map, of: Number, default: {} }
});

// Create Models
const User = mongoose.model('User', UserSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const UserData = mongoose.model('UserData', UserDataSchema);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user; // Contains { username }
    next();
  });
};

// Register endpoint
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  
  try {
    // Check if user exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    
    // Initialize the user's data storage
    const userData = new UserData({ username });
    await userData.save();
    
    res.json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "Error registering user" });
  }
});

// Get profile data
app.get("/profile", authenticateToken, async (req, res) => {
  const username = req.user.username;
  try {
    const profile = await Profile.findOne({ username });
    if (!profile) {
      return res.status(404).json({ error: "Profile not found" });
    }
    res.json(profile);
  } catch (error) {
    res.status(500).json({ error: "Error fetching profile" });
  }
});

// Update profile
app.put("/profile", authenticateToken, async (req, res) => {
  const username = req.user.username;
  const { name, email, bio } = req.body;

  try {
    let profile = await Profile.findOne({ username });
    if (!profile) {
      profile = new Profile({ username });
    }

    if (name) profile.name = name;
    if (email) profile.email = email;
    if (bio) profile.bio = bio;

    await profile.save();
    res.json({ message: "Profile updated successfully", profile });
  } catch (error) {
    res.status(500).json({ error: "Error updating profile" });
  }
});

// Update profile picture (basic URL-based, not file upload)
app.put("/profile/picture", authenticateToken, async (req, res) => {
  const username = req.user.username;
  const { profilePic } = req.body;

  if (!profilePic) {
    return res.status(400).json({ error: "Profile picture URL required" });
  }

  try {
    const profile = await Profile.findOneAndUpdate(
      { username },
      { profilePic },
      { new: true, upsert: true }
    );
    res.json({ message: "Profile picture updated", profile });
  } catch (error) {
    res.status(500).json({ error: "Error updating profile picture" });
  }
});

// Login endpoint
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "User not found" });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid password" });
    }
    
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: "Error during login" });
  }
});

// Protected endpoint: Add a transaction (with budget check)
app.post("/transaction", authenticateToken, async (req, res) => {
  const { description, amount, type, category, date } = req.body;
  if (!description || !amount || !type || !category || !date) {
    return res.status(400).json({ error: "Missing fields" });
  }
  
  const username = req.user.username;
  
  try {
    // Check if it's an expense and if the category has a budget
    if (type === "expense") {
      const userData = await UserData.findOne({ username });  
      if (!userData) {
        return res.status(404).json({ error: "User data not found" });
      }
      
      // Check if the category has a budget set
      if (userData.categoryBalance.has(category)) {
        const currentBalance = userData.categoryBalance.get(category);
        if (currentBalance - amount < 0) {
          console.log(`❌ Expense rejected! Budget exceeded for category: ${category}`);
          return res.status(400).json({ 
            error: `Expense exceeds budget for ${category}! Remaining: ${currentBalance}` 
          });
        }
      }
    }
    
    // Create transaction
    const transaction = new Transaction({
      username,
      description,
      amount,
      type,
      category,
      date: new Date(date)
    });
    await transaction.save();
    
    // Update user data
    const userData = await UserData.findOne({ username });
    if (!userData) {
      return res.status(404).json({ error: "User data not found" });
    }
    
    if (type === "income") {
      userData.totalIncome += amount;
    } else if (type === "expense") {
      userData.totalExpense += amount;
    }
    
    // Update category balance (subtract for expenses, add for income)
    const currentBalance = userData.categoryBalance.get(category) || 0;
    userData.categoryBalance.set(
      category, 
      currentBalance + (type === "income" ? amount : -amount)
    );
    
    await userData.save();
    
    res.json({ message: "Transaction added successfully", transaction });
  } catch (error) {
    res.status(500).json({ error: "Error adding transaction" });
  }
});

// Protected endpoint: Get all transactions for the authenticated user
app.get("/transactions", authenticateToken, async (req, res) => {
  const username = req.user.username;
  
  try {
    const transactions = await Transaction.find({ username }).sort({ date: -1 });
    res.json(transactions);
  } catch (error) {
    res.status(500).json({ error: "Error fetching transactions" });
  }
});

// Protected endpoint: Generate financial report for the authenticated user
app.get("/report", authenticateToken, async (req, res) => {
  const username = req.user.username;
  
  try {
    const userData = await UserData.findOne({ username });
    if (!userData) {
      return res.status(404).json({ error: "User data not found" });
    }
    
    const netBalance = userData.totalIncome - userData.totalExpense;
    res.json({
      totalIncome: userData.totalIncome,
      totalExpense: userData.totalExpense,
      netBalance,
      categorySummary: Object.fromEntries(userData.categoryBalance)
    });
  } catch (error) {
    res.status(500).json({ error: "Error generating report" });
  }
});

// Protected endpoint: Set a budget for a category for the authenticated user
app.post("/budget", authenticateToken, async (req, res) => {
  const { category, limit } = req.body;
  if (!category || limit === undefined) {
    return res.status(400).json({ error: "Category and limit are required" });
  }
  
  const username = req.user.username;
  
  try {
    const userData = await UserData.findOne({ username });
    if (!userData) {
      return res.status(404).json({ error: "User data not found" });
    }
    
    userData.categoryBalance.set(category, limit);
    await userData.save();
    
    res.json({ 
      message: `Budget for ${category} set to ${limit}`, 
      categoryBalance: Object.fromEntries(userData.categoryBalance) 
    });
  } catch (error) {
    res.status(500).json({ error: "Error setting budget" });
  }
});

// Protected endpoint: Get budget overview for the authenticated user
app.get("/budget", authenticateToken, async (req, res) => {
  const username = req.user.username;
  
  try {
    const userData = await UserData.findOne({ username });
    if (!userData) {
      return res.status(404).json({ error: "User data not found" });
    }
    
    res.json(Object.fromEntries(userData.categoryBalance));
  } catch (error) {
    res.status(500).json({ error: "Error fetching budget" });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://localhost:${PORT}`);
}); 
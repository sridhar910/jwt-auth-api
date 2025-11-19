const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const authMiddleware = require('./middleware/authMiddleware');
require('dotenv').config(); // Load environment variables

const app = express();
const port = 3000;

app.use(bodyParser.json());

// ==================== MongoDB Connection ====================
mongoose.connect('mongodb://127.0.0.1:27017/authDB', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => console.log('❌ MongoDB error:', err));

// ==================== ROUTES ====================

// Register a new user
app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(409).json({ error: 'Email already registered' });

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save user
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Login user and generate JWT
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ error: 'Invalid email or password' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid email or password' });

        // Generate JWT with 1-hour expiry
        const token = jwt.sign(
            { id: user._id, email: user.email },
            process.env.JWT_SECRET, // Use secret from .env
            { expiresIn: '1h' }     // Token valid for 1 hour
        );

        res.json({ message: 'Login successful', token });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Protected route
app.get('/dashboard', authMiddleware, (req, res) => {
    res.json({ message: `Welcome ${req.user.email}` });
});

// Default route
app.use((req, res) => res.status(404).json({ error: 'Route not found' }));

// Start server
app.listen(port, () => console.log(`🚀 Server running at http://localhost:${port}/`));
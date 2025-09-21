require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

// in-memory user store
const users = [];

// register route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password required' });

    const existing = users.find(u => u.username === username);
    if (existing) return res.status(409).json({ message: 'User already exists' });

    try {
        const hashed = await bcrypt.hash(password, 10);
        users.push({ username, password: hashed });
        return res.json({ message: 'User registered successfully' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});

// login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password required' });

    const user = users.find(u => u.username === username);
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    try {
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
        return res.json({ message: 'Login successful', token });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error' });
    }
});

// middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: 'Unauthorized' });

    const parts = authHeader.split(' ');
    const token = parts.length === 2 ? parts[1] : null;
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    jwt.verify(token, JWT_SECRET, (err, payload) => {
        if (err) return res.status(401).json({ message: 'Unauthorized' });
        req.user = payload;
        next();
    });
}

// protected route
app.get('/profile', authenticateToken, (req, res) => {
    return res.json({ message: `Welcome ${req.user.username}` });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

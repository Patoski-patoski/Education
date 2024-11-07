import jwt from 'jsonwebtoken';
import bcrypt from "bcrypt";
import express from "express";
import cookieParser from 'cookie-parser';

const app = express();
app.use(express.json());
app.use(cookieParser())

const userData = {};
const JWT_SECRET = ';,lmnyt6t7ye8u9i--x,,..8883';

app.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    userData.id = 1;
    userData.username = username;
    userData.password = hashedPassword;

    console.log('User signed up');
    res.status(201).json({ message: "Signup successfully" });
});

app.post('/login', async (req, res) => {
    const { password } = req.body;

    // Check if user data exists
    if (!userData || !userData.password) {
        return res.status(400).json({ message: "User not found. Please sign up first." });
    }

    const isPasswordValid = await bcrypt.compare(password, userData.password);
    if (!isPasswordValid) {
        return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: userData.id, username: userData.username }, JWT_SECRET, { expiresIn: "1h" });

    //set the token as an HTTP-only cookie
    res.cookie("token", token, {
        httpOnly: true,
        maxAge: 1000 * 60 * 60,
        secure: process.env.NODE_ENV === 'production',
    });

    res.json({ message: "Login successful" });
});

// Middleware to protect routes
function authenticateToken(req, res, next) {
    const token = req.cookies.token; // Get token from cookies

    if (!token) {
        return res.status(401).json({ message: "Access token missing or invalid" });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Attach decoded user info to req object
        next(); // Pass control to the next handler
    } catch (err) {
        return res.status(403).json({ message: "Invalid token" });
    }
}

// Protected route example
app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: "This is protected data", user: req.user });
});

app.listen(3000, () => {
    console.log('Listening live at port 3000');
});

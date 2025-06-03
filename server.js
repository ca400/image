const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(express.static('public')); // for CSS, JS, images

// Serve uploaded images statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Ensure uploads folder exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    // Unique filename: timestamp + original name
    cb(null, Date.now() + '-' + file.originalname);
  },
});
const upload = multer({ storage });

// Simulated in-memory user data
let users = [];

// Middleware to verify JWT token for protected routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || req.query.token || req.cookies?.token;
  const token = authHeader && authHeader.split(' ')[1] || authHeader;
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });
    req.user = user;
    next();
  });
}

// Serve register.html on homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

// Serve login.html (create it if you want login page separately)
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Serve upload.html (protected)
app.get('/upload.html', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'upload.html'));
});

// Register route
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: 'User already exists!' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ email, password: hashedPassword });
  res.json({ message: 'User registered successfully!' });
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email);
  if (!user) return res.status(400).json({ message: 'Invalid email or password!' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: 'Invalid email or password!' });

  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ message: 'Login successful!', token });
});

// Image upload route (protected)
app.post('/upload', authenticateToken, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });

  // Return URL of uploaded image
  const imageUrl = `/uploads/${req.file.filename}`;
  res.json({ message: 'Image uploaded successfully!', imageUrl });
});

// Route to get all uploaded images
app.get('/uploaded-images', authenticateToken, (req, res) => {
  fs.readdir(uploadDir, (err, files) => {
    if (err) return res.status(500).json({ message: 'Unable to read uploads.' });

    // Return list of image URLs
    const images = files.map(file => `/uploads/${file}`);
    res.json({ images });
  });
});

app.listen(port, () => console.log(`Server running at http://localhost:${port}`));

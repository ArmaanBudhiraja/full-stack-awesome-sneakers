require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');

const userRoutes = require('./routes/userRoutes');
const productRoutes = require('./routes/productRoutes');

const app = express();

// ✅ Allowed origins for local frontend
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:5176',
  'http://localhost:5174' // Vite sometimes runs here
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true); // allow Postman/server-to-server
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('CORS not allowed'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true,
  optionsSuccessStatus: 200,
};

// ✅ Apply CORS and JSON parsing
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ Serve product images locally
app.use('/images', express.static(path.join(__dirname, 'images')));

// ✅ Serve other static files if needed
app.use(express.static(path.join(__dirname, 'public')));

// ✅ API Routes
app.use('/api/user', userRoutes);
app.use('/api/products', productRoutes);

// ✅ Test route
app.get('/api', (req, res) => {
  res.send('API is running!');
});

// ✅ Listen locally
const port = process.env.PORT || 4004;
app.listen(port, '0.0.0.0', () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});

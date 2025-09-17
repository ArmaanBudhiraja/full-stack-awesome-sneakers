// middleware/authMiddleware.js
const jwt = require('jsonwebtoken');
const pool = require('../db');

const authMiddleware = async (req, res, next) => {
  try {
    // 1. Get the token from the request header
    const token = req.headers.authorization?.split(' ')[1]; // "Bearer TOKEN"
    if (!token) {
      return res.status(401).json({ message: 'No token provided, authorization denied' });
    }

    // 2. Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach the decoded user payload to the request object

    // 3. Optional: Check if the user still exists in the database
    // This is a good practice for more robust applications
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    if (userResult.rows.length === 0) {
      return res.status(401).json({ message: 'User not found, authorization denied' });
    }

    // 4. Proceed to the next middleware or route handler
    next();
  } catch (err) {
    console.error('Token verification failed:', err);
    res.status(401).json({ message: 'Token is not valid' });
  }
};

module.exports = authMiddleware;
// Load required modules
const jwt = require('jsonwebtoken');
require('dotenv').config(); // Load environment variables from .env

/**
 * Middleware to protect routes and ensure only logged-in users can access.
 * It checks for a JWT token in the Authorization header and verifies it.
 */
function authMiddleware(req, res, next) {
    try {
        // Get the Authorization header (should be in format: "Bearer <token>")
        const authHeader = req.headers['authorization'];

        if (!authHeader) {
            return res.status(401).json({ error: 'No token provided' });
        }

        // Split the header to extract the token
        const tokenParts = authHeader.split(' ');

        // Check format
        if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
            return res.status(401).json({ error: 'Malformed token' });
        }

        const token = tokenParts[1];

        // Verify token using the secret from .env
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Save decoded user info to request object
        req.user = decoded;

        // Proceed to the next middleware or route
        next();

    } catch (err) {
        // Catch invalid or expired token
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
}

module.exports = authMiddleware;
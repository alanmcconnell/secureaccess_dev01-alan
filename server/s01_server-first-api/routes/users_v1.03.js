const express = require('express');
const router = express.Router();
const {
  getAllUsers,
  getUserById,
  createUser,
  updateUser,
  updateLastLogin,
  deleteUser,
  getUserSecurity
} = require('../controllers/usersController');
const { authenticateToken, rateLimiter } = require('../middleware/auth');

// Apply rate limiting to all user routes
router.use(rateLimiter(50, 15 * 60 * 1000)); // 50 requests per 15 minutes

// GET /api/users - Get all users (requires authentication)
router.get('/', authenticateToken, getAllUsers);

// GET /api/users/:id - Get user by ID (requires authentication)
router.get('/:id', authenticateToken, getUserById);

// GET /api/users/:id/security - Get user security info (requires authentication)
router.get('/:id/security', authenticateToken, getUserSecurity);

// POST /api/users - Create new user (public for registration)
router.post('/', createUser);

// PUT /api/users/:id - Update user (requires authentication)
router.put('/:id', authenticateToken, updateUser);

// PATCH /api/users/:id/login - Update last login timestamp (requires authentication)
router.patch('/:id/login', authenticateToken, updateLastLogin);

// DELETE /api/users/:id - Delete user (requires authentication)
router.delete('/:id', authenticateToken, deleteUser);

module.exports = router;
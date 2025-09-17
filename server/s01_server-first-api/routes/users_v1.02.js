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

// GET /api/users - Get all users
router.get('/', getAllUsers);

// GET /api/users/:id - Get user by ID
router.get('/:id', getUserById);

// GET /api/users/:id/security - Get user security info
router.get('/:id/security', getUserSecurity);

// POST /api/users - Create new user
router.post('/', createUser);

// PUT /api/users/:id - Update user
router.put('/:id', updateUser);

// PATCH /api/users/:id/login - Update last login timestamp
router.patch('/:id/login', updateLastLogin);

// DELETE /api/users/:id - Delete user
router.delete('/:id', deleteUser);

module.exports = router;
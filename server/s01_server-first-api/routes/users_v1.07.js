const express = require('express');
const router = express.Router();

// Test importing the users controller
try {
  const {
    getAllUsers,
    getUserById,
    createUser,
    updateUser,
    updateLastLogin,
    deleteUser,
    getUserSecurity
  } = require('../controllers/usersController');
  
  console.log('✅ Users controller imported successfully');
  
  // Basic routes without middleware first
  router.get('/test', (req, res) => {
    res.json({ message: 'Users routes working' });
  });
  
  // POST /api/users - Create new user (public for registration)
  router.post('/', createUser);
  
  // Add other routes later
  
} catch (error) {
  console.error('❌ Error importing users controller:', error.message);
  
  // Fallback test route
  router.get('/test', (req, res) => {
    res.json({ message: 'Users routes working (fallback)' });
  });
}

module.exports = router;
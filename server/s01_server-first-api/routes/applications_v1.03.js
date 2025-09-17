const express = require('express');
const router = express.Router();

// Test importing the controller
try {
  const {
    getApplicationById,
    getAllApplications,
    createApplication
  } = require('../controllers/applicationsController');
  
  console.log('✅ Applications controller imported successfully');
  
  // GET /api/applications - Get all applications
  router.get('/', getAllApplications);

  // GET /api/applications/:id - Get application by ID
  router.get('/:id', getApplicationById);

  // POST /api/applications - Create new application
  router.post('/', createApplication);
  
} catch (error) {
  console.error('❌ Error importing applications controller:', error.message);
  
  // Fallback test route
  router.get('/test', (req, res) => {
    res.json({ message: 'Applications routes working (fallback)' });
  });
}

module.exports = router;
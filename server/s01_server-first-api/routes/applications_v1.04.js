const express = require('express');
const router = express.Router();

try {
  const {
    getApplicationById,
    getAllApplications,
    createApplication
  } = require('../controllers/applicationsController');
  
  const { generalRateLimit } = require('../middleware/auth');
  
  console.log('✅ Applications controller and middleware imported successfully');
  
  // Apply rate limiting to application routes
  router.use(generalRateLimit);

  // GET /api/applications - Get all applications
  router.get('/', getAllApplications);

  // GET /api/applications/:id - Get application by ID
  router.get('/:id', getApplicationById);

  // POST /api/applications - Create new application
  router.post('/', createApplication);
  
  console.log('✅ All applications routes added successfully');
  
} catch (error) {
  console.error('❌ Error in applications routes:', error.message);
  
  // Fallback test route
  router.get('/test', (req, res) => {
    res.json({ message: 'Applications routes working (fallback)' });
  });
}

module.exports = router;
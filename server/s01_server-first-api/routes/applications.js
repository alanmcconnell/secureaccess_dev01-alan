const express = require('express');
const router = express.Router();
const {
  getApplicationById,
  getAllApplications,
  createApplication,
  getUserApplications
} = require('../controllers/applicationsController');
const { generalRateLimit, authenticateToken } = require('../middleware/auth');

// Apply rate limiting to application routes
router.use(generalRateLimit);

// GET /api/applications - Get all applications
router.get('/', getAllApplications);

// GET /api/applications/:id - Get application by ID
router.get('/:id', getApplicationById);

// POST /api/applications - Create new application
router.post('/', createApplication);

module.exports = router;
const { pool } = require('../database');
const Joi = require('joi');

// Validation schema
const applicationIdSchema = Joi.string().required();

// Get application by ID
const getApplicationById = async (req, res) => {
  try {
    const { error, value } = applicationIdSchema.validate(req.params.id);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Invalid application ID',
        details: error.details.map(d => d.message)
      });
    }

    const applicationId = value;
    
    const [rows] = await pool.execute(`
      SELECT 
        application_id, application_name, description, 
        created_at, updated_at, status
      FROM sa_applications 
      WHERE application_id = ?
    `, [applicationId]);
    
    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }
    
    res.json({
      success: true,
      data: rows[0]
    });
    
  } catch (error) {
    console.error('Error fetching application:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch application information',
      error: error.message
    });
  }
};

// Get all applications (optional - for admin purposes)
const getAllApplications = async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT 
        application_id, application_name, description, 
        created_at, updated_at, status
      FROM sa_applications 
      ORDER BY application_name ASC
    `);
    
    res.json({
      success: true,
      data: rows,
      count: rows.length
    });
    
  } catch (error) {
    console.error('Error fetching applications:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch applications',
      error: error.message
    });
  }
};

// Create new application
const createApplication = async (req, res) => {
  try {
    const schema = Joi.object({
      application_name: Joi.string().max(255).required(),
      description: Joi.string().optional(),
      status: Joi.string().valid('active', 'inactive').default('active')
    });

    const { error, value } = schema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details.map(d => d.message)
      });
    }

    const { application_name, description, status } = value;
    
    const [result] = await pool.execute(`
      INSERT INTO sa_applications (application_name, description, status) 
      VALUES (?, ?, ?)
    `, [application_name, description || null, status]);
    
    // Fetch the created application
    const [newApp] = await pool.execute(`
      SELECT 
        application_id, application_name, description, 
        created_at, updated_at, status
      FROM sa_applications 
      WHERE application_id = ?
    `, [result.insertId]);
    
    res.status(201).json({
      success: true,
      message: 'Application created successfully',
      data: newApp[0]
    });
    
  } catch (error) {
    console.error('Error creating application:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Application name already exists'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to create application',
      error: error.message
    });
  }
};

module.exports = {
  getApplicationById,
  getAllApplications,
  createApplication
};
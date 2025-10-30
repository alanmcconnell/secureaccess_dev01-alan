const express = require('express');
const path = require('path');
const cors = require('cors');
const mysql = require('mysql2/promise');

// Database configuration
const dbConfig = {
    host: 'localhost',
    port: 3306,
    user: 'nimdas',
    password: 'FormR!1234',
    database: 'dbtools'
};

/**
 * acm_NextID - Global ID generator function
 * Returns the next unique ID for a record in a table and updates the counter
 * 
 * @param {string} tableName - The name of the table to generate ID for
 * @returns {Promise<number>} - The next unique ID number
 * @throws {Error} - If database operation fails
 */
async function acm_NextID(tableName) {
    let connection;
    
    try {
        if (!tableName || typeof tableName !== 'string') {
            throw new Error('Table name must be a non-empty string');
        }
        
        connection = await mysql.createConnection(dbConfig);
        await connection.execute('SET autocommit = 0');
        await connection.beginTransaction();
        
        console.log(`Starting transaction for table: ${tableName}`);
        
        const [rows] = await connection.execute(
            'SELECT next_value FROM acm_nextid WHERE lower(table_name) = lower(?) FOR UPDATE',
            [tableName]
        );
        
        let nextId;
        
        if (rows.length > 0) {
            nextId = rows[0].next_value;
            
            await connection.execute(
                'UPDATE acm_nextid SET next_value = next_value + 1 WHERE lower(table_name) = lower(?)',
                [tableName]
            );
        } else {
            nextId = 1;
            
            await connection.execute(
                'INSERT INTO acm_nextid (table_name, next_value) VALUES (?, ?)',
                [tableName, 2]
            );
        }
        
        await connection.commit();
        console.log(`Transaction committed for table: ${tableName}, returned ID: ${nextId}`);
        
        return nextId;
        
    } catch (error) {
        if (connection) {
            try {
                await connection.rollback();
            } catch (rollbackError) {
                console.error('Rollback failed:', rollbackError.message);
            }
        }
        throw new Error(`acm_NextID function failed: ${error.message}`);
        
    } finally {
        if (connection) {
            try {
                await connection.end();
            } catch (closeError) {
                console.error('Connection close failed:', closeError.message);
            }
        }
    }
}

// Make acm_NextID globally available
global.acm_NextID = acm_NextID;

// Express server setup
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// API endpoint
app.post('/api/nextid', async (req, res) => {
    try {
        const { tableName } = req.body;
        
        if (!tableName) {
            return res.status(400).json({ error: 'Table name is required' });
        }
        
        if (typeof tableName !== 'string') {
            return res.status(400).json({ error: 'Table name must be a string' });
        }
        
        const nextId = await acm_NextID(tableName);
        
        res.json({ 
            nextId: nextId,
            tableName: tableName,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('acm_NextID API Error:', error.message);
        res.status(500).json({ 
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Serve HTML page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'nextid_testpage.html'));
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        service: 'acm_NextID API',
        timestamp: new Date().toISOString()
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`acm_NextID Server running on port ${PORT}`);
    console.log(`acm_NextID function available globally as acm_NextID(tableName)`);
    console.log(`API endpoint: http://localhost:${PORT}/api/nextid`);
});

// Export for use in other modules
module.exports = { acm_NextID };
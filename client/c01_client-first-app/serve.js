const express = require('express');
const path = require('path');

const app = express();
const PORT = 8080;

// Serve static files from current directory
app.use(express.static(__dirname));

// Default route to login page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login_client.html'));
});

app.listen(PORT, () => {
    console.log(`🌐 Client server running on http://localhost:${PORT}`);
    console.log(`🔐 Login page: http://localhost:${PORT}/login_client.html`);
    console.log(`👤 Profile page: http://localhost:${PORT}/profile-page.html`);
});
/**
 * Royal Photowaala - Express.js Backend Server
 * PostgreSQL Database Backend
 */

require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const cron = require('node-cron');
const ExcelJS = require('exceljs');
const fs = require('fs').promises;

const app = express(); // ✅ FIX 1: app created
const PORT = process.env.PORT || 5000;

/* ================= BASIC MIDDLEWARE ================= */
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : '*',
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ================= SESSION CONFIG ================= */
const sessionConfig = {
  secret: process.env.SECRET_KEY || 'fallback-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  name: 'royalphotowaala.sid',
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 2 * 60 * 60 * 1000 // 2 hours
  }
};

// ✅ FIX 2: trust proxy ONLY after app exists
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
  sessionConfig.cookie.secure = true;
  sessionConfig.cookie.sameSite = 'none';
}

app.use(session(sessionConfig));

/* ================= ENV VALIDATION ================= */
const requiredEnvVars = ['DATABASE_URL', 'SECRET_KEY'];
const missingEnvVars = requiredEnvVars.filter(v => !process.env[v]);

if (missingEnvVars.length > 0) {
  console.error('❌ Missing environment variables:');
  missingEnvVars.forEach(v => console.error(' -', v));
  process.exit(1);
}

/* ================= DATABASE ================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

pool.on('connect', () => {
  console.log('✅ Connected to PostgreSQL');
});

pool.on('error', (err) => {
  console.error('❌ PostgreSQL error:', err);
  process.exit(1);
});

async function query(text, params = []) {
  const start = Date.now();
  const res = await pool.query(text, params);
  console.log('DB query', { text, duration: Date.now() - start });
  return res;
}

/* ================= WHATSAPP HELPERS (FROM FLASK LOGIC) ================= */
const querystring = require('querystring');

function normalizePhone(number, country = '91') {
  if (!number) return null;
  const num = String(number).replace(/\D/g, '');

  if (num.length === 10) return country + num;
  if (num.length >= 11 && num.startsWith(country)) return num;

  return null;
}

function buildWhatsAppLink(number, message) {
  if (!number) {
    console.error('❌ No admin WhatsApp number');
    return null;
  }
  const encoded = querystring.escape(message);
  return `https://wa.me/${number}?text=${encoded}`;
}

/* ADMIN WHATSAPP NUMBER */
let ADMIN_WHATSAPP_NUMBER = normalizePhone(
  process.env.ADMIN_WHATSAPP_NUMBER || '8149003738'
);

console.log('✅ WhatsApp Admin:', ADMIN_WHATSAPP_NUMBER);

/* ================= AUTH MIDDLEWARE ================= */
function loginRequired(req, res, next) {
  if (req.session?.logged_in) return next();
  res.redirect('/admin_login');
}

function loginRequiredApi(req, res, next) {
  if (req.session?.logged_in) return next();
  res.status(401).json({ success: false, error: 'Auth required' });
}

// ========== ROUTES ==========
// Serve static files
app.use(express.static(path.join(__dirname, 'frontend')));
app.use('/static', express.static(path.join(__dirname, 'static')));
app.use('/templates', express.static(path.join(__dirname, 'templates')));
// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    await query('SELECT NOW()');
    res.json({ 
      status: 'ok', 
      message: 'Royal Photowaala API is running',
      database: 'connected',
      whatsapp: !!ADMIN_WHATSAPP_NUMBER
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error',
      message: 'Database connection failed',
      error: error.message 
    });
  }
});
// Admin login routes
app.get('/admin_login', (req, res) => {
  if (req.session.logged_in) {
    return res.redirect('/dashboard');
  }
  res.sendFile(path.join(__dirname, 'templates', 'admin_login.html'));
});
app.post('/admin_login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.send(`
      <script>
        alert('Username and password required');
        window.location.href = '/admin_login';
      </script>
    `);
  }
  
  try {
    const result = await query('SELECT * FROM admin_users WHERE username = $1', [username.trim()]);
    const user = result.rows[0];
    
    if (user && await bcrypt.compare(password, user.password_hash)) {
      req.session.logged_in = true;
      req.session.username = username;
      return res.redirect('/dashboard');
    } else {
      return res.send(`
        <script>
          alert('Invalid credentials');
          window.location.href = '/admin_login';
        </script>
      `);
    }
  } catch (error) {
    console.error('Login error:', error);
    return res.send(`
      <script>
        alert('Login error: ${error.message}');
        window.location.href = '/admin_login';
      </script>
    `);
  }
});
// Dashboard
app.get('/dashboard', loginRequired, (req, res) => {
  res.sendFile(path.join(__dirname, 'templates', 'dashboard_new.html'));
});
// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/admin_login');
});
// Booking API
app.post('/api/book', async (req, res) => {
  const { name, email, phone, package: pkg, date, details } = req.body || {};
  
  const trimmedName = (name || '').trim();
  const trimmedEmail = (email || '').trim();
  const trimmedPhone = (phone || '').trim();
  const trimmedPackage = (pkg || '').trim();
  const trimmedDate = (date || '').trim();
  const trimmedDetails = (details || '').trim();
  
  // Validation
  if (!trimmedName || !trimmedEmail || !trimmedPhone || !trimmedPackage || !trimmedDate) {
    return res.status(400).json({ success: false, error: 'All required fields must be filled' });
  }
  
  if (trimmedName.length < 2) {
    return res.status(400).json({ success: false, error: 'Name must be at least 2 characters' });
  }
  
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
    return res.status(400).json({ success: false, error: 'Invalid email format' });
  }
  
  if (!/^\d{10}$/.test(trimmedPhone)) {
    return res.status(400).json({ success: false, error: 'Phone must be 10 digits' });
  }
  
  // Validate date
  try {
    const bookingDate = new Date(trimmedDate);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    if (bookingDate < today) {
      return res.status(400).json({ success: false, error: 'Booking date must be in the future' });
    }
  } catch (error) {
    return res.status(400).json({ success: false, error: 'Invalid date format' });
  }
  
  try {
    const result = await query(
      `INSERT INTO bookings (name, email, phone, package, date, details, status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [trimmedName, trimmedEmail, trimmedPhone, trimmedPackage, trimmedDate, trimmedDetails, 'pending'],
      { queryName: 'create_booking' }
    );
    
    const bookingId = result.rows[0].id;
    
    // Format date for WhatsApp message
    const eventDate = new Date(trimmedDate).toLocaleDateString('en-GB', {
      day: 'numeric',
      month: 'long',
      year: 'numeric'
    });
    
    const packageDisplay = trimmedPackage.replace(' - ', ' - 📸 ');
    const cleanedDetails = trimmedDetails || 'No additional details provided';
    
    const msg = `🌟 *NEW BOOKING REQUEST* 🌟\n\n` +
      `👤 *Name*: ${trimmedName}\n` +
      `📧 *Email*: ${trimmedEmail}\n` +
      `📱 *Phone*: ${trimmedPhone}\n` +
      `📦 *Package*: ${packageDisplay}\n` +
      `📅 *Event Date*: ${eventDate}\n\n` +
      `📝 *Event Details*:\n${cleanedDetails}\n\n` +
      `⏰ *Please respond within 24 hours*\n` +
      `✅ To confirm: Reply 'Confirm ${bookingId}'\n` +
      `❌ To cancel: Reply 'Cancel ${bookingId}'`;
    
    const waLink = buildWhatsAppLink(ADMIN_WHATSAPP_NUMBER, msg);
    
    if (!waLink) {
      console.error(`❌ Failed to generate WhatsApp link for booking ID: ${bookingId}`);
      return res.status(500).json({ success: false, error: 'WhatsApp link generation failed' });
    }
    
    return res.json({
      success: true,
      message: 'Booking request submitted successfully',
      wa_link: waLink
    });
  } catch (error) {
    console.error('❌ DB Insert Error:', error);
    return res.status(500).json({ 
      success: false, 
      error: 'Database error occurred',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});
// Get all bookings (admin only)
app.get('/api/bookings', loginRequiredApi, async (req, res) => {
  try {
    const threeMonthsAgo = new Date();
    threeMonthsAgo.setMonth(threeMonthsAgo.getMonth() - 3);
    
    const result = await query(
      `SELECT * FROM bookings 
       WHERE created_at >= $1 
       ORDER BY created_at DESC`,
      [threeMonthsAgo],
      { queryName: 'get_recent_bookings' }
    );
    
    return res.json({ success: true, bookings: result.rows });
  } catch (error) {
    console.error('Error fetching bookings:', error);
    return res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch bookings',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});
// Update booking status
app.put('/api/bookings/:id/status', loginRequiredApi, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body || {};
  
  const validStatuses = ['pending', 'confirmed', 'cancelled', 'completed'];
  if (!status || !validStatuses.includes(status.trim())) {
    return res.status(400).json({ success: false, error: 'Invalid status' });
  }
  
  try {
    await query('UPDATE bookings SET status = $1 WHERE id = $2', [status.trim(), id]);
    const bookingResult = await query('SELECT * FROM bookings WHERE id = $1', [id]);
    
    if (bookingResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }
    
    const booking = bookingResult.rows[0];
    
    const msg = `BOOKING STATUS UPDATE\n` +
      `📅 Booking ID: ${booking.id}\n` +
      `👤 Name: ${booking.name}\n` +
      `📦 Package: ${booking.package}\n` +
      `📅 Date: ${booking.date}\n` +
      `🔄 New Status: ${status.toUpperCase()}\n` +
      `\nPlease contact the customer if needed.`;
    
    const waLink = buildWhatsAppLink(ADMIN_WHATSAPP_NUMBER, msg);
    
    return res.json({
      success: true,
      wa_link: waLink
    });
  } catch (error) {
    console.error('❌ Booking error:', error);
    return res.status(500).json({ 
      success: false, 
      error: 'Server error',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});
// Delete booking
app.delete('/api/bookings/:id', loginRequiredApi, async (req, res) => {
  const { id } = req.params;
  
  try {
    await query('DELETE FROM bookings WHERE id = $1', [id]);
    return res.json({ success: true, message: 'Booking deleted' });
  } catch (error) {
    console.error('Error deleting booking:', error);
    return res.status(500).json({ 
      success: false, 
      error: 'Failed to delete booking',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});
// Get approved reviews
app.get('/api/reviews', async (req, res) => {
  try {
    const result = await query(
      `SELECT name, rating, comment 
       FROM reviews 
       WHERE approved = 1 
       ORDER BY created_at DESC`,
      [],
      { queryName: 'get_approved_reviews' }
    );
    
    return res.json({ success: true, reviews: result.rows });
  } catch (error) {
    console.error('Error fetching reviews:', error);
    return res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch reviews',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});
// Submit review
app.post('/api/reviews', async (req, res) => {
  const { name, rating, comment } = req.body || {};
  
  const trimmedName = (name || '').trim();
  const trimmedComment = (comment || '').trim();
  const ratingNum = parseInt(rating, 10);
  
  if (!trimmedName || !trimmedComment || !ratingNum || ratingNum < 1 || ratingNum > 5) {
    return res.status(400).json({ 
      success: false, 
      error: 'Invalid input. Please provide valid name, comment, and rating (1-5).' 
    });
  }
  
  try {
    await query(
      'INSERT INTO reviews (name, rating, comment, approved) VALUES ($1, $2, $3, $4)',
      [trimmedName, ratingNum, trimmedComment, false],
      { queryName: 'create_review' }
    );
    
    return res.json({ 
      success: true, 
      message: 'Thank you for your review! It will be visible after approval.' 
    });
  } catch (error) {
    console.error('Error submitting review:', error);
    return res.status(500).json({ 
      success: false, 
      error: 'Failed to submit review',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});
// Approve review (admin only)
app.put('/api/reviews/:id/approve', loginRequiredApi, async (req, res) => {
  const { id } = req.params;
  
  try {
    await query('UPDATE reviews SET approved = 1 WHERE id = $1', [id]);
    return res.json({ success: true, message: 'Review approved' });
  } catch (error) {
    console.error('Error approving review:', error);
    return res.status(500).json({ 
      success: false, 
      error: 'Failed to approve review',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});
// Archive old bookings
async function archiveOldBookings() {
  try {
    const threeMonthsAgo = new Date();
    threeMonthsAgo.setMonth(threeMonthsAgo.getMonth() - 3);
    
    const result = await query(
      'SELECT * FROM bookings WHERE created_at < $1',
      [threeMonthsAgo],
      { queryName: 'get_old_bookings' }
    );
    
    const oldBookings = result.rows;
    
    if (oldBookings.length === 0) {
      console.log("ℹ️  No bookings to archive");
      return 0;
    }
    
    // Create archives directory if it doesn't exist
    const archivesDir = path.join(__dirname, 'archives');
    await fs.mkdir(archivesDir, { recursive: true });
    
    const excelFile = path.join(archivesDir, `bookings_archive_${Date.now()}.xlsx`);
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Archived Bookings');
    
    // Add headers
    worksheet.columns = [
      { header: 'ID', key: 'id', width: 10 },
      { header: 'Name', key: 'name', width: 20 },
      { header: 'Email', key: 'email', width: 30 },
      { header: 'Phone', key: 'phone', width: 15 },
      { header: 'Package', key: 'package', width: 30 },
      { header: 'Event Date', key: 'date', width: 15 },
      { header: 'Details', key: 'details', width: 40 },
      { header: 'Status', key: 'status', width: 15 },
      { header: 'Created At', key: 'created_at', width: 20 }
    ];
    
    // Style header row
    worksheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
    worksheet.getRow(1).fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FF4472C4' }
    };
    worksheet.getRow(1).alignment = { vertical: 'middle', horizontal: 'center' };
    
    // Add data
    oldBookings.forEach(booking => {
      worksheet.addRow({
        id: booking.id,
        name: booking.name,
        email: booking.email,
        phone: booking.phone,
        package: booking.package,
        date: booking.date,
        details: booking.details || '',
        status: booking.status,
        created_at: booking.created_at
      });
    });
    
    await workbook.xlsx.writeFile(excelFile);
    
    // Delete archived bookings
    await query('DELETE FROM bookings WHERE created_at < $1', [threeMonthsAgo]);
    
    console.log(`✅ Archived ${oldBookings.length} bookings to ${excelFile}`);
    return oldBookings.length;
  } catch (error) {
    console.error(`❌ Error archiving bookings: ${error.message}`);
    throw error;
  }
}
// Manual archive trigger
app.post('/api/archive-bookings', loginRequiredApi, async (req, res) => {
  try {
    const result = await archiveOldBookings();
    return res.json({ 
      success: true, 
      message: 'Old bookings archived successfully',
      archived_count: result || 0
    });
  } catch (error) {
    return res.status(500).json({ 
      success: false, 
      error: error.message,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});
// Schedule archiving (runs daily at midnight)
cron.schedule('0 0 * * *', () => {
  console.log('Running scheduled archiving of old bookings...');
  archiveOldBookings().catch(console.error);
});
// ========== ERROR HANDLERS ==========
// ✅ ROOT ROUTE — MUST BE FIRST
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Royal Photowaala Backend is running 🚀',
    status: 'OK'
  });
});

// ❌ 404 handler — MUST BE AFTER ALL ROUTES
app.use((req, res) => {
  res.status(404).json({ 
    success: false,
    error: 'Not Found',
    message: `The requested resource ${req.originalUrl} was not found`
  });
});

// ✅ Global error handler — ALWAYS LAST
app.use((err, req, res, next) => {
  console.error('Unhandled error:', {
    error: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString()
  });
  res.status(err.status || 500).json({
    success: false,
    error: process.env.NODE_ENV === 'development'
      ? err.message
      : 'Internal Server Error'
  });
});

// ========== START SERVER ==========
async function startServer() {
  try {
    // Initialize database
    await initDb();
    
    // Initialize WhatsApp number
    initWhatsAppNumber();
    
    // Start the server
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`
        ========================================
        🚀 Royal Photowaala API is running
        🌐 http://localhost:${PORT}
        🕒 ${new Date().toLocaleString()}
        ========================================
        Environment: ${process.env.NODE_ENV || 'development'}
        Node.js: ${process.version}
        Platform: ${process.platform} ${process.arch}
        ========================================
      `);
    });
    // Handle server errors
    server.on('error', (error) => {
      if (error.syscall !== 'listen') {
        throw error;
      }
      const bind = typeof PORT === 'string' ? 'Pipe ' + PORT : 'Port ' + PORT;
      // Handle specific listen errors with friendly messages
      switch (error.code) {
        case 'EACCES':
          console.error(bind + ' requires elevated privileges');
          process.exit(1);
          break;
        case 'EADDRINUSE':
          console.error(bind + ' is already in use');
          process.exit(1);
          break;
        default:
          throw error;
      }
    });
    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled Rejection at:', promise, 'reason:', reason);
      // Close server & exit process
      server.close(() => process.exit(1));
    });
    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      console.error('Uncaught Exception:', error);
      // Close server & exit process
      server.close(() => process.exit(1));
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}
// Initialize database schema
async function initDb() {
  try {
    // Create tables
    await query(`
      CREATE TABLE IF NOT EXISTS admin_users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS bookings (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        phone VARCHAR(20) NOT NULL,
        package VARCHAR(255) NOT NULL,
        date DATE NOT NULL,
        details TEXT,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS reviews (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
        comment TEXT NOT NULL,
        approved BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // ✅ DEFAULT ADMIN CREATION — NOW CORRECT
    const adminCheck = await query(
      'SELECT * FROM admin_users WHERE username = $1',
      ['admin']
    );

    if (adminCheck.rows.length === 0) {
      const passwordHash = await bcrypt.hash('admin123', 10);
      await query(
        'INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)',
        ['admin', passwordHash]
      );
      console.log('✅ Created default admin user (admin/admin123)');
    }

    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
    throw error;
  }
}

  
// Start the server
startServer();





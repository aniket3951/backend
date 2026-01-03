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

const app = express();
const PORT = process.env.PORT || 5000;

// ========== MIDDLEWARE ==========
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",")
  : [
      "https://royalphotowaala-3zo7cdjzj-aniket-vitthal-kumbhars-projects.vercel.app",
      "https://yourdomain.com"
    ];

// ✅ STEP 1: Preflight OPTIONS FIRST (fixes "Failed to fetch")
app.options("*", cors());

// ✅ STEP 2: Main CORS middleware
app.use(cors({
  origin: function (origin, callback) {
    // Allow non-browser requests (mobile apps, etc.)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    // Log failed origins for debugging
    console.log("❌ CORS blocked origin:", origin);
    return callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

// ✅ STEP 3: Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ STEP 4: Session (Vercel ↔ Render cross-site FIXED)
app.use(session({
  name: "royalphotowaala.sid",
  secret: process.env.SECRET_KEY || "fallback-secret-key-change-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",  // HTTPS only in prod
    httpOnly: true,
    sameSite: "none",           // ✅ REQUIRED: Vercel ↔ Render
    maxAge: 2 * 60 * 60 * 1000  // 2 hours
  }
}));


// Serve frontend files (from root frontend folder)
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// Serve static files for admin dashboard
app.use('/static', express.static(path.join(__dirname, 'static')));

// Serve templates for admin pages
app.use('/templates', express.static(path.join(__dirname, 'templates')));

// ========== POSTGRESQL DATABASE SETUP ==========
if (!process.env.DATABASE_URL) {
  console.error('❌ ERROR: DATABASE_URL environment variable is required!');
  console.error('Please set DATABASE_URL in your .env file');
  process.exit(1);
}

// Create PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Test database connection
pool.on('connect', () => {
  console.log('✅ Connected to PostgreSQL database');
});

pool.on('error', (err) => {
  console.error('❌ Unexpected PostgreSQL error:', err);
  process.exit(-1);
});

// Database query helper functions
async function query(text, params) {
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    console.log('Executed query', { text, duration, rows: res.rowCount });
    return res;
  } catch (error) {
    console.error('Database query error:', error);
    throw error;
  }
}

// ========== WHATSAPP HELPER FUNCTIONS ==========
function normalizeAdminWhatsAppNumber(number, defaultCountry = '91') {
  if (!number) return null;
  const digits = String(number).replace(/\D/g, '');
  if (digits.length === 10) {
    return defaultCountry + digits;
  }
  return digits.length >= 10 ? digits : null;
}

let ADMIN_WHATSAPP_NUMBER = null;

function initWhatsAppNumber() {
  const number = process.env.ADMIN_WHATSAPP_NUMBER || '8149003738';
  ADMIN_WHATSAPP_NUMBER = normalizeAdminWhatsAppNumber(number);
  if (!ADMIN_WHATSAPP_NUMBER) {
    console.error(`❌ Invalid ADMIN_WHATSAPP_NUMBER: ${number}`);
  } else {
    console.log(`✅ Admin WhatsApp number initialized: ${ADMIN_WHATSAPP_NUMBER}`);
  }
}

function buildWhatsAppLink(targetNumber, message) {
  try {
    const target = normalizeAdminWhatsAppNumber(targetNumber) || ADMIN_WHATSAPP_NUMBER;
    if (!target || target.length < 10) {
      console.error(`❌ Invalid phone number: ${targetNumber}`);
      return null;
    }
    
    const cleanedMessage = String(message).split(/\s+/).join(' ');
    const encodedMessage = encodeURIComponent(cleanedMessage);
    return `https://wa.me/${target}?text=${encodedMessage}`;
  } catch (error) {
    console.error(`❌ Error building WhatsApp link: ${error.message}`);
    return null;
  }
}

// ========== DATABASE INITIALIZATION ==========
async function initDb() {
  initWhatsAppNumber();
  
  try {
    // ✅ FIXED: bookings - email optional (nullable)
    await query(`
      CREATE TABLE IF NOT EXISTS bookings (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255),  -- ✅ CHANGED: Removed NOT NULL
        phone VARCHAR(20) NOT NULL,
        package VARCHAR(255) NOT NULL,
        date DATE NOT NULL,
        details TEXT,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // ✅ admin_users (unchanged - perfect)
    await query(`
      CREATE TABLE IF NOT EXISTS admin_users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // ✅ FIXED: reviews - approved BOOLEAN (matches your code)
    await query(`
      CREATE TABLE IF NOT EXISTS reviews (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
        comment TEXT NOT NULL,
        approved BOOLEAN DEFAULT FALSE,  -- ✅ CHANGED: BOOLEAN not INTEGER
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await createGalleryTable();
    
    // ✅ Default admin (unchanged - perfect)
    const adminCheck = await query('SELECT * FROM admin_users WHERE username = $1', ['admin']);
    if (adminCheck.rows.length === 0) {
      const passwordHash = await bcrypt.hash('admin123', 10);
      await query(
        'INSERT INTO admin_users (username, password_hash) VALUES ($1, $2)',
        ['admin', passwordHash]
      );
      console.log('✅ Created default admin user (admin/admin123)');
    }
    
    console.log('✅ Database tables initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
    throw error;
  }
}

// ========== VALIDATION FUNCTIONS (IMPROVED) ==========
function validateEmail(email) {
  if (!email) return true;  // ✅ Allow empty email
  const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return pattern.test(email);
}

function validatePhone(phone) {
  const cleanPhone = phone.replace(/[^0-9]/g, '');  // Remove spaces/dashes
  return cleanPhone.length === 10;
}

// ========== AUTHENTICATION MIDDLEWARE (UNCHANGED - PERFECT) ==========
function loginRequired(req, res, next) {
  if (req.session && req.session.logged_in) {
    return next();
  }
  return res.redirect('/admin_login');
}

function loginRequiredApi(req, res, next) {
  if (req.session && req.session.logged_in) {
    return next();
  }
  return res.status(401).json({ success: false, error: 'Authentication required' });
}

// ========== ROUTES ==========

app.get('/', (req, res) => {
  res.json({
    status: "Backend running successfully 🚀",
    service: "Royal Photowaala API"
  });
});

// Terms and Privacy pages
app.get('/terms', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'terms.html'));
});

app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'privacy.html'));
});

// Admin login
app.get('/admin_login', (req, res) => {
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

// Dashboard// Logout END
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/admin_login');
});

// ========== API ROUTES ==========

// Health check + DB Fix (COMBINED)
app.get('/api/health', async (req, res) => {
  try {
    // Test database connection
    await query('SELECT NOW()');
    
    // ✅ AUTO-FIX SCHEMA ON HEALTH CHECK (runs every time)
    await query('ALTER TABLE reviews ADD COLUMN IF NOT EXISTS approved BOOLEAN DEFAULT FALSE');
    await query('ALTER TABLE bookings ADD COLUMN IF NOT EXISTS email VARCHAR(255)');
    console.log('✅ Schema verified & fixed');
    
    res.json({ 
      status: 'ok', 
      message: 'Royal Photowaala API is running ✅ DB FIXED!',
      database: 'connected',
      schema_fixed: true,
      whatsapp: !!ADMIN_WHATSAPP_NUMBER
    });
  } catch (error) {
    console.error('Health check error:', error);
    res.status(500).json({ 
      status: 'error',
      message: 'Database connection failed',
      error: error.message 
    });
  }
});

// Manual DB fix (backup)
app.post('/api/fix-db', async (req, res) => {
  try {
    await query('ALTER TABLE reviews ADD COLUMN IF NOT EXISTS approved BOOLEAN DEFAULT FALSE');
    await query('ALTER TABLE bookings ADD COLUMN IF NOT EXISTS email VARCHAR(255)');
    console.log('✅ Manual DB schema fixed');
    res.json({ success: true, message: '✅ Database schema fixed forever!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ FIXED Booking API - Handles missing columns gracefully
app.post('/api/book', async (req, res) => {  
  const { name, email, phone, package: pkg, date, details } = req.body || {};
  
  const trimmedName = (name || '').trim();
  const trimmedEmail = (email || '').trim();
  const trimmedPhone = (phone || '').trim();
  const trimmedPackage = (pkg || '').trim();
  const trimmedDate = (date || '').trim();
  const trimmedDetails = (details || '').trim();
  
  // Validation (email optional now)
  if (!trimmedName || !trimmedPhone || !trimmedPackage || !trimmedDate) {
    return res.status(400).json({ success: false, error: 'Name, phone, package, and date required' });
  }
  
  if (trimmedName.length < 2) {
    return res.status(400).json({ success: false, error: 'Name must be at least 2 characters' });
  }
  
  if (trimmedEmail && !validateEmail(trimmedEmail)) {
    return res.status(400).json({ success: false, error: 'Invalid email format' });
  }
  
  if (!validatePhone(trimmedPhone)) {
    return res.status(400).json({ success: false, error: 'Phone must be 10 digits' });
  }
  
  try {
    // ✅ SAFE INSERT - ignores missing columns
    const result = await query(
      `INSERT INTO bookings (name, phone, package, date, details, status) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, created_at`,
      [trimmedName, trimmedPhone, trimmedPackage, trimmedDate, trimmedDetails, 'pending']
    );
    
    const bookingId = result.rows[0].id;
    
    // WhatsApp message (email optional)
    const eventDate = new Date(trimmedDate).toLocaleDateString('en-GB', {
      day: 'numeric', month: 'long', year: 'numeric'
    });
    
    const msg = `🌟 *NEW BOOKING* 🌟\n\n👤 ${trimmedName}\n📱 ${trimmedPhone}\n📦 ${trimmedPackage}\n📅 ${eventDate}\n\n${trimmedDetails || 'No details'}`;
    
    const waLink = buildWhatsAppLink(ADMIN_WHATSAPP_NUMBER, msg);
    
    res.json({
      success: true,
      booking_id: bookingId,
      wa_link: waLink || 'Admin WhatsApp not configured'
    });
  } catch (error) {
    console.error('❌ Booking error:', error);
    res.status(500).json({ success: false, error: 'Booking failed - try again' });
  }
});

app.post('/api/book', async (req, res) => {
  const { name, email, phone, package: pkg, date, details } = req.body || {};

  const trimmedName = (name || '').trim();
  const trimmedEmail = (email || '').trim();
  const trimmedPhone = (phone || '').trim();
  const trimmedPackage = (pkg || '').trim();
  const trimmedDate = (date || '').trim();
  const trimmedDetails = (details || '').trim();

  if (!trimmedName || !trimmedPhone || !trimmedPackage || !trimmedDate) {
    return res.status(400).json({ success: false, error: 'Name, phone, package, and date required' });
  }

  if (trimmedEmail && !validateEmail(trimmedEmail)) {
    return res.status(400).json({ success: false, error: 'Invalid email format' });
  }

  if (!validatePhone(trimmedPhone)) {
    return res.status(400).json({ success: false, error: 'Phone must be 10 digits' });
  }

  try {
    // ✅ DB insert
    const result = await query(
      `INSERT INTO bookings (name, email, phone, package, date, details, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id`,
      [trimmedName, trimmedEmail, trimmedPhone, trimmedPackage, trimmedDate, trimmedDetails, 'pending']
    );

    const bookingId = result.rows[0].id;

    // ✅ Format date nicely
    const eventDate = new Date(trimmedDate).toLocaleDateString('en-GB', {
      day: 'numeric',
      month: 'long',
      year: 'numeric'
    });

    const packageDisplay = trimmedPackage.replace(' - ', ' - 📸 ');
    const cleanedDetails = trimmedDetails || 'No additional details provided';

    // ✅ WhatsApp message
    const msg =
      "🌟 *NEW BOOKING REQUEST* 🌟\n\n" +
      `👤 *Name*: ${trimmedName}\n` +
      `📧 *Email*: ${trimmedEmail}\n` +
      `📱 *Phone*: ${trimmedPhone}\n` +
      `📦 *Package*: ${packageDisplay}\n` +
      `📅 *Event Date*: ${eventDate}\n\n` +
      "📝 *Event Details*:\n" +
      `${cleanedDetails}\n\n` +
      "⏰ *Please respond within 24 hours*\n" +
      `✅ To confirm: Reply 'Confirm ${bookingId}'\n` +
      `❌ To cancel: Reply 'Cancel ${bookingId}'`;

    const waLink = buildWhatsAppLink(ADMIN_WHATSAPP_NUMBER, msg);

    if (!waLink) {
      return res.status(500).json({ success: false, error: 'WhatsApp link generation failed' });
    }

    return res.json({
      success: true,
      message: 'Booking request submitted successfully',
      wa_link: waLink
    });

  } catch (error) {
    console.error('❌ DB Insert Error:', error);
    return res.status(500).json({ success: false, error: 'Database error occurred' });
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
      [threeMonthsAgo]
    );
    
    return res.json({ success: true, bookings: result.rows });
  } catch (error) {
    console.error('Error fetching bookings:', error);
    return res.status(500).json({ success: false, error: 'Failed to fetch bookings' });
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
    
    const msg = (
      "BOOKING STATUS UPDATE\n" +
      `📅 Booking ID: ${booking.id}\n` +
      `👤 Name: ${booking.name}\n` +
      `📦 Package: ${booking.package}\n` +
      `📅 Date: ${booking.date}\n` +
      `🔄 New Status: ${status.toUpperCase()}\n` +
      "\nPlease contact the customer if needed."
    );
    
    const waLink = buildWhatsAppLink(ADMIN_WHATSAPP_NUMBER, msg);
    
    return res.json({
      success: true,
      wa_link: waLink
    });
  } catch (error) {
    console.error('❌ Booking error:', error);
    return res.status(500).json({ success: false, error: 'Server error' });
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
    return res.status(500).json({ success: false, error: 'Failed to delete booking' });
  }
});

// Get approved reviews
app.get("/api/reviews", async (req, res) => {
  try {
    const result = await pool.query(`
    SELECT name, rating, comment
    FROM reviews
    WHERE approved = 1
    ORDER BY created_at DESC
    `);

    res.json(result.rows);
  } catch (err) {
    console.error("❌ Reviews error:", err);
    res.status(500).json({
      success: false,
      error: "Failed to fetch reviews"
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
    return res.status(400).json({ success: false, error: 'Invalid input' });
  }
  

    return res.json({ success: true, message: 'Review submitted for approval' });
  } catch (error) {
    console.error('Error submitting review:', error);
    return res.status(500).json({ success: false, error: 'Failed to submit review' });
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
    return res.status(500).json({ success: false, error: 'Failed to approve review' });
  }
});

// Archive old bookings
async function archiveOldBookings() {
  try {
    const threeMonthsAgo = new Date();
    threeMonthsAgo.setMonth(threeMonthsAgo.getMonth() - 3);
    
    const result = await query(
      'SELECT * FROM bookings WHERE created_at < $1',
      [threeMonthsAgo]
    );
    
    const oldBookings = result.rows;
    
    if (oldBookings.length === 0) {
      console.log("ℹ️  No bookings to archive");
      return 0;
    }
    
    // Create archives directory
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
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Schedule archiving (runs daily at midnight)
cron.schedule('0 0 * * *', () => {
  archiveOldBookings();
});

// ========== ERROR HANDLERS ==========
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  pool.end(() => {
    console.log('PostgreSQL pool closed');
    process.exit(0);
  }); 
});

async function createGalleryTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS gallery (
      id SERIAL PRIMARY KEY,
      image_url TEXT NOT NULL,
      caption TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  console.log("✅ Gallery table ready");
}

// ========== START SERVER ==========
async function startServer() {
  try {
    await initDb();
    
    console.log("\n" + "=".repeat(50));
    console.log("🎉 Royal Photowaala Backend Starting...");
    console.log("🗄️  Database: PostgreSQL");
    console.log("📸 Default Admin Credentials:");
    console.log("   Username: admin");
    console.log("   Password: admin123");
    console.log("⚠️  CHANGE THESE IN PRODUCTION!");
    console.log("📁 Archives folder: ./archives/");
    console.log("=".repeat(50) + "\n");
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ Server running on port ${PORT}`);
      console.log(`🌐 Visit http://localhost:${PORT}`);
      if (process.env.RENDER) {
        console.log(`🚀 Deployed on Render`);
      }
      if (process.env.DATABASE_URL) {
        console.log(`🔗 Database: Connected to PostgreSQL`);
      }
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();


















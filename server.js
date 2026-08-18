const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for secure cookies on Render
app.set('trust proxy', 1);

// Middleware
app.use(helmet({
    contentSecurityPolicy: false,
}));
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'web4u-super-secret-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// SQLite Database Setup
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to SQLite database.');
        initDb();
    }
});

function initDb() {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_id TEXT UNIQUE,
            email TEXT UNIQUE,
            name TEXT,
            role TEXT DEFAULT 'CUSTOMER',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            website_name TEXT,
            requirements TEXT,
            status TEXT DEFAULT 'IN DEVELOPMENT',
            payment_status TEXT DEFAULT 'Pending',
            preview_url TEXT,
            live_url TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);
    });
}

// Passport Google Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL || 'https://web4u-platform.onrender.com/api/auth/google/callback'
    }, (accessToken, refreshToken, profile, done) => {
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        const name = profile.displayName || 'Google User';
        const googleId = profile.id;

        db.get(`SELECT * FROM users WHERE google_id = ? OR email = ?`, [googleId, email], (err, user) => {
            if (err) return done(err);

            if (user) {
                if (!user.google_id) {
                    db.run(`UPDATE users SET google_id = ? WHERE id = ?`, [googleId, user.id]);
                }
                return done(null, user);
            } else {
                db.run(`INSERT INTO users (google_id, email, name, role) VALUES (?, ?, ?, 'CUSTOMER')`, 
                    [googleId, email, name], function(err) {
                        if (err) return done(err);
                        db.get(`SELECT * FROM users WHERE id = ?`, [this.lastID], (err, newUser) => {
                            if (err) return done(err);
                            return done(null, newUser);
                        });
                    });
            }
        });
    }));
}

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    db.get(`SELECT * FROM users WHERE id = ?`, [id], (err, user) => {
        done(err, user);
    });
});

// Rate limiting for auth routes
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
});

// --- API ROUTES ---

// Auth Routes
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/api/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/');
    }
);

app.get('/api/auth/me', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    res.json(req.user);
});

app.post('/api/auth/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        req.session.destroy(() => {
            res.clearCookie('connect.sid');
            res.json({ success: true });
        });
    });
});

// Admin Login Route with Diagnostic Logging
app.post('/api/auth/admin-login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        console.log({
            adminEmailConfigured: Boolean(process.env.ADMIN_EMAIL),
            adminPasswordHashConfigured: Boolean(process.env.ADMIN_PASSWORD_HASH),
            hashLength: process.env.ADMIN_PASSWORD_HASH ? process.env.ADMIN_PASSWORD_HASH.length : 0,
            bcryptPrefixValid: /^\$2[aby]\$/.test(process.env.ADMIN_PASSWORD_HASH || ''),
            submittedEmailMatches: Boolean(email) && Boolean(process.env.ADMIN_EMAIL) && email.trim().toLowerCase() === process.env.ADMIN_EMAIL.trim().toLowerCase()
        });

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const adminEmail = process.env.ADMIN_EMAIL;
        const adminHash = process.env.ADMIN_PASSWORD_HASH;

        if (!adminEmail || !adminHash) {
            return res.status(500).json({ error: 'Admin credentials not configured on server' });
        }

        const emailMatch = email.trim().toLowerCase() === adminEmail.trim().toLowerCase();
        const passwordMatch = await bcrypt.compare(password, adminHash);

        console.log({
            passwordHashMatch: passwordMatch
        });

        if (!emailMatch || !passwordMatch) {
            return res.status(401).json({ error: 'Invalid admin credentials' });
        }

        // Check SQLite for SUPER_ADMIN user
        db.get(`SELECT * FROM users WHERE email = ? AND role = 'SUPER_ADMIN'`, [adminEmail], (err, adminUser) => {
            if (err) {
                console.error('Database error during admin lookup:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (adminUser) {
                req.login(adminUser, (err) => {
                    if (err) return res.status(500).json({ error: 'Login session error' });
                    return res.json({ success: true, user: adminUser });
                });
            } else {
                db.run(`INSERT INTO users (email, name, role) VALUES (?, 'Super Admin', 'SUPER_ADMIN')`, 
                    [adminEmail], function(err) {
                        if (err) {
                            console.error('Database error during admin creation:', err);
                            return res.status(500).json({ error: 'Internal server error' });
                        }
                        db.get(`SELECT * FROM users WHERE id = ?`, [this.lastID], (err, newAdminUser) => {
                            if (err || !newAdminUser) {
                                return res.status(500).json({ error: 'Internal server error' });
                            }
                            req.login(newAdminUser, (err) => {
                                if (err) return res.status(500).json({ error: 'Login session error' });
                                return res.json({ success: true, user: newAdminUser });
                            });
                        });
                    });
            }
        });

    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Project Routes (Customer)
app.post('/api/projects', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { requirements } = req.body;
    if (!requirements) {
        return res.status(400).json({ error: 'Requirements are required' });
    }

    const userId = req.user.id;
    const websiteName = requirements.split('\n')[0].substring(0, 50) || 'Custom Website';

    db.run(`INSERT INTO projects (user_id, website_name, requirements, status, payment_status) VALUES (?, ?, ?, 'IN DEVELOPMENT', 'Pending')`,
        [userId, websiteName, requirements], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to create project' });
            }
            res.json({ success: true, projectId: this.lastID });
        });
});

app.get('/api/customer/projects', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const userId = req.user.id;
    db.all(`SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC`, [userId], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch projects' });
        }
        res.json(rows);
    });
});

// Admin Projects Route
app.get('/api/admin/projects', (req, res) => {
    if (!req.isAuthenticated() || req.user.role !== 'SUPER_ADMIN') {
        return res.status(403).json({ error: 'Unauthorized access' });
    }

    const query = `
        SELECT p.*, u.name as customer_name, u.email as customer_email 
        FROM projects p 
        LEFT JOIN users u ON p.user_id = u.id 
        ORDER BY p.created_at DESC
    `;

    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch admin projects' });
        }
        res.json(rows);
    });
});

// Portfolio Endpoint fallback
app.get('/api/portfolio', (req, res) => {
    res.json([
        { title: 'Tech Startup Dashboard', category: 'Web App', description: 'Advanced responsive dashboard built for an AI analytics company.', image_url: 'https://placehold.co/800x600/18181b/6366f1?text=Dashboard+UI' },
        { title: 'Local Coffee Roaster', category: 'E-Commerce', description: 'Clean, modern storefront with integrated local delivery zones.', image_url: 'https://placehold.co/800x600/18181b/6366f1?text=E-Commerce+Store' }
    ]);
});

// Serve frontend index.html for all other routes
app.get('*', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

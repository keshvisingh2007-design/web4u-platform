 const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Render deployment reverse proxy trust configuration for secure cookies
app.set('trust proxy', 1);

// Security check for session secret in production
if (!process.env.SESSION_SECRET) {
    console.error('CRITICAL ERROR: SESSION_SECRET environment variable is missing.');
    process.exit(1);
}

// Helmet security headers configured safely for single-file frontend integration
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 1 week
    }
});

app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

// Rate limiter specifically for admin login to prevent brute force attacks (5 requests per 15 minutes)
const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const dbPath = path.resolve(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to SQLite database.');
    }
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        google_id TEXT UNIQUE,
        email TEXT,
        name TEXT,
        role TEXT DEFAULT 'CUSTOMER'
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        request_id TEXT UNIQUE,
        website_name TEXT,
        original_requirements TEXT,
        status TEXT DEFAULT 'REQUESTED',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
});

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL || '/api/auth/google/callback'
    }, (accessToken, refreshToken, profile, done) => {
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : '';
        const name = profile.displayName || 'Customer';
        const googleId = profile.id;

        db.get('SELECT * FROM users WHERE google_id = ?', [googleId], (err, user) => {
            if (err) return done(err);
            if (user) {
                return done(null, user);
            } else {
                db.run('INSERT INTO users (google_id, email, name, role) VALUES (?, ?, ?, ?)',
                    [googleId, email, name, 'CUSTOMER'], function(err) {
                        if (err) return done(err);
                        db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (err, newUser) => {
                            return done(err, newUser);
                        });
                    });
            }
        });
    }));
}

passport.serializeUser((user, done) => {
    done(null, { id: user.id, role: user.role });
});

passport.deserializeUser((obj, done) => {
    db.get('SELECT * FROM users WHERE id = ?', [obj.id], (err, user) => {
        if (err || !user) return done(err, null);
        done(null, user);
    });
});

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.status(401).json({ error: 'Authentication required' });
}

function isSuperAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user && req.user.role === 'SUPER_ADMIN') {
        return next();
    }
    res.status(403).json({ error: 'Admin authorization required' });
}

app.get('/api/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/api/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/');
    }
);

app.get('/api/auth/me', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({
            id: req.user.id,
            email: req.user.email,
            name: req.user.name,
            role: req.user.role
        });
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
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

app.post('/api/auth/admin-login', adminLoginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const adminEmail = process.env.ADMIN_EMAIL;
        const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;

        if (!adminEmail || !adminPasswordHash) {
            console.error('CRITICAL ERROR: Admin environment variables are not configured.');
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const emailMatch = (email.trim().toLowerCase() === adminEmail.trim().toLowerCase());
        const passwordMatch = await bcrypt.compare(password, adminPasswordHash);

        if (emailMatch && passwordMatch) {
            db.get('SELECT * FROM users WHERE email = ? AND role = ?', [adminEmail, 'SUPER_ADMIN'], async (err, adminUser) => {
                if (err) return res.status(500).json({ error: 'Internal server error' });

                const completeLogin = (userObj) => {
                    req.session.regenerate((err) => {
                        if (err) return res.status(500).json({ error: 'Internal server error' });
                        req.login(userObj, (err) => {
                            if (err) return res.status(500).json({ error: 'Internal server error' });
                            return res.json({
                                success: true,
                                user: {
                                    id: userObj.id,
                                    email: userObj.email,
                                    name: userObj.name,
                                    role: userObj.role
                                }
                            });
                        });
                    });
                };

                if (!adminUser) {
                    db.run('INSERT INTO users (email, name, role) VALUES (?, ?, ?)',
                        [adminEmail, 'Super Admin', 'SUPER_ADMIN'], function(err) {
                            if (err) return res.status(500).json({ error: 'Internal server error' });
                            db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (err, newUser) => {
                                if (err || !newUser) return res.status(500).json({ error: 'Internal server error' });
                                completeLogin(newUser);
                            });
                        });
                } else {
                    completeLogin(adminUser);
                }
            });
        } else {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (e) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/projects', isAuthenticated, (req, res) => {
    const { requirements } = req.body;
    if (!requirements || !requirements.trim()) {
        return res.status(400).json({ error: 'Requirements are required' });
    }

    const userId = req.user.id;
    const requestId = 'W4-' + Math.floor(100000 + Math.random() * 900000);
    const websiteName = 'Custom Website ' + requestId;

    db.run('INSERT INTO projects (user_id, request_id, website_name, original_requirements, status) VALUES (?, ?, ?, ?, ?)',
        [userId, requestId, websiteName, requirements, 'REQUESTED'], function(err) {
            if (err) return res.status(500).json({ error: 'Failed to create project' });
            res.json({ success: true, projectId: this.lastID, request_id: requestId });
        });
});

app.get('/api/customer/projects', isAuthenticated, (req, res) => {
    const userId = req.user.id;
    db.all('SELECT * FROM projects WHERE user_id = ? ORDER BY id DESC', [userId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Failed to retrieve projects' });
        res.json(rows);
    });
});

app.get('/api/customer/projects/:id', isAuthenticated, (req, res) => {
    const userId = req.user.id;
    const projectId = req.params.id;

    db.get('SELECT * FROM projects WHERE id = ? AND user_id = ?', [projectId, userId], (err, project) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!project) return res.status(404).json({ error: 'Project not found or unauthorized' });
        res.json(project);
    });
});

app.get('/api/admin/projects', isSuperAdmin, (req, res) => {
    const query = `
        SELECT p.*, u.name as customer_name, u.email as customer_email 
        FROM projects p 
        LEFT JOIN users u ON p.user_id = u.id 
        ORDER BY p.id DESC
    `;
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch admin projects' });
        res.json(rows);
    });
});

app.use((err, req, res, next) => {
    console.error('Unhandled Server Error:', err.message);
    res.status(500).json({ error: 'An unexpected internal error occurred.' });
});

app.listen(PORT, () => {
    console.log(`WEB4U Secure Server running on port ${PORT}`);
});

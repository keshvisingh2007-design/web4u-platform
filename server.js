const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for secure cookies on Render / proxies
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
            user_id INTEGER NOT NULL,
            website_name TEXT NOT NULL,
            requirements TEXT NOT NULL,
            status TEXT DEFAULT 'REQUESTED',
            payment_status TEXT DEFAULT 'Pending',
            preview_url TEXT,
            live_url TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            sender_user_id INTEGER NOT NULL,
            sender_role TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            read_at DATETIME NULL,
            FOREIGN KEY(project_id) REFERENCES projects(id),
            FOREIGN KEY(sender_user_id) REFERENCES users(id)
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

// Middleware Helpers
function requireAuth(req, res, next) {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.isAuthenticated() || req.user.role !== 'SUPER_ADMIN') {
        return res.status(403).json({ error: 'Unauthorized access' });
    }
    next();
}

// URL Safety Validator
function isValidSafeUrl(string) {
    if (!string || string.trim() === '') return true;
    try {
        const parsed = new URL(string);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

// Rate limiting for auth routes
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 25,
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

// Project Routes (Customer Creation)
app.post('/api/projects', requireAuth, (req, res) => {
    const { requirements } = req.body;
    if (!requirements || requirements.trim() === '') {
        return res.status(400).json({ error: 'Requirements are required' });
    }

    const userId = req.user.id;
    const websiteName = requirements.split('\n')[0].substring(0, 50) || 'Custom Website';

    db.run(`INSERT INTO projects (user_id, website_name, requirements, status, payment_status) VALUES (?, ?, ?, 'REQUESTED', 'Pending')`,
        [userId, websiteName, requirements.trim()], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to create project' });
            }
            res.json({ success: true, projectId: this.lastID });
        });
});

app.get('/api/customer/projects', requireAuth, (req, res) => {
    const userId = req.user.id;
    const query = `
        SELECT p.*,
            (SELECT COUNT(*) FROM messages m WHERE m.project_id = p.id AND m.sender_role = 'SUPER_ADMIN' AND m.read_at IS NULL) as unread_messages
        FROM projects p 
        WHERE p.user_id = ? 
        ORDER BY p.created_at DESC
    `;
    db.all(query, [userId], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch projects' });
        }
        res.json(rows || []);
    });
});

// Customer Single Project API
app.get('/api/customer/projects/:projectId', requireAuth, (req, res) => {
    const projectId = parseInt(req.params.projectId, 10);
    if (isNaN(projectId)) {
        return res.status(400).json({ error: 'Invalid project ID' });
    }

    const query = `
        SELECT p.*,
            (SELECT COUNT(*) FROM messages m WHERE m.project_id = p.id AND m.sender_role = 'SUPER_ADMIN' AND m.read_at IS NULL) as unread_messages
        FROM projects p 
        WHERE p.id = ? AND p.user_id = ?
    `;
    db.get(query, [projectId, req.user.id], (err, project) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!project) return res.status(404).json({ error: 'Project not found or unauthorized' });
        res.json(project);
    });
});

// Customer Chat APIs
app.get('/api/customer/projects/:projectId/messages', requireAuth, (req, res) => {
    const projectId = parseInt(req.params.projectId, 10);
    if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

    db.get(`SELECT id FROM projects WHERE id = ? AND user_id = ?`, [projectId, req.user.id], (err, project) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!project) return res.status(404).json({ error: 'Project not found' });

        db.all(`SELECT * FROM messages WHERE project_id = ? ORDER BY created_at ASC`, [projectId], (err, messages) => {
            if (err) return res.status(500).json({ error: 'Failed to fetch messages' });
            res.json(messages || []);
        });
    });
});

app.post('/api/customer/projects/:projectId/messages', requireAuth, (req, res) => {
    const projectId = parseInt(req.params.projectId, 10);
    const { message } = req.body;

    if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });
    if (!message || message.trim() === '') return res.status(400).json({ error: 'Message cannot be empty' });
    if (message.length > 3000) return res.status(400).json({ error: 'Message length exceeds 3000 characters' });

    db.get(`SELECT id FROM projects WHERE id = ? AND user_id = ?`, [projectId, req.user.id], (err, project) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!project) return res.status(404).json({ error: 'Project not found' });

        db.run(`INSERT INTO messages (project_id, sender_user_id, sender_role, message) VALUES (?, ?, 'CUSTOMER', ?)`,
            [projectId, req.user.id, message.trim()], function(err) {
                if (err) return res.status(500).json({ error: 'Failed to send message' });
                db.get(`SELECT * FROM messages WHERE id = ?`, [this.lastID], (err, newMsg) => {
                    if (err) return res.status(500).json({ error: 'Failed to retrieve message' });
                    res.json(newMsg);
                });
            });
    });
});

app.post('/api/customer/projects/:projectId/messages/read', requireAuth, (req, res) => {
    const projectId = parseInt(req.params.projectId, 10);
    if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

    db.get(`SELECT id FROM projects WHERE id = ? AND user_id = ?`, [projectId, req.user.id], (err, project) => {
        if (err || !project) return res.status(404).json({ error: 'Project not found' });

        db.run(`UPDATE messages SET read_at = CURRENT_TIMESTAMP WHERE project_id = ? AND sender_role = 'SUPER_ADMIN' AND read_at IS NULL`,
            [projectId], (err) => {
                if (err) return res.status(500).json({ error: 'Failed to update read status' });
                res.json({ success: true });
            });
    });
});

// --- Admin Projects & Chat Routes ---

app.get('/api/admin/projects', requireAdmin, (req, res) => {
    const query = `
        SELECT p.*, u.name as customer_name, u.email as customer_email,
            (SELECT COUNT(*) FROM messages m WHERE m.project_id = p.id AND m.sender_role = 'CUSTOMER' AND m.read_at IS NULL) as unread_messages
        FROM projects p 
        LEFT JOIN users u ON p.user_id = u.id 
        ORDER BY p.created_at DESC
    `;

    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch admin projects' });
        }
        res.json(rows || []);
    });
});

app.get('/api/admin/projects/:projectId', requireAdmin, (req, res) => {
    const projectId = parseInt(req.params.projectId, 10);
    if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

    const query = `
        SELECT p.*, u.name as customer_name, u.email as customer_email,
            (SELECT COUNT(*) FROM messages m WHERE m.project_id = p.id AND m.sender_role = 'CUSTOMER' AND m.read_at IS NULL) as unread_messages
        FROM projects p 
        LEFT JOIN users u ON p.user_id = u.id 
        WHERE p.id = ?
    `;

    db.get(query, [projectId], (err, project) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!project) return res.status(404).json({ error: 'Project not found' });
        res.json(project);
    });
});

app.patch('/api/admin/projects/:projectId', requireAdmin, (req, res) => {
    const projectId = parseInt(req.params.projectId, 10);
    if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

    const { status, preview_url, live_url } = req.body;

    const allowedStatuses = [
        'REQUESTED',
        'APPROVED',
        'IN DEVELOPMENT',
        'PREVIEW READY',
        'CHANGES REQUESTED',
        'COMPLETED',
        'PAYMENT REQUIRED',
        'PAID',
        'LAUNCHED',
        'REJECTED',
        'Completed'
    ];

    const updates = [];
    const params = [];

    if (status !== undefined) {
        if (!allowedStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status value' });
        }
        updates.push('status = ?');
        params.push(status);
    }

    if (preview_url !== undefined) {
        if (preview_url && !isValidSafeUrl(preview_url)) {
            return res.status(400).json({ error: 'Invalid Preview URL' });
        }
        updates.push('preview_url = ?');
        params.push(preview_url ? preview_url.trim() : null);
    }

    if (live_url !== undefined) {
        if (live_url && !isValidSafeUrl(live_url)) {
            return res.status(400).json({ error: 'Invalid Live URL' });
        }
        updates.push('live_url = ?');
        params.push(live_url ? live_url.trim() : null);
    }

    if (updates.length === 0) {
        return res.status(400).json({ error: 'No valid fields provided for update' });
    }

    db.get(`SELECT id FROM projects WHERE id = ?`, [projectId], (err, project) => {
        if (err || !project) return res.status(404).json({ error: 'Project not found' });

        params.push(projectId);
        const sql = `UPDATE projects SET ${updates.join(', ')} WHERE id = ?`;

        db.run(sql, params, function(err) {
            if (err) return res.status(500).json({ error: 'Failed to update project' });

            db.get(`SELECT p.*, u.name as customer_name, u.email as customer_email FROM projects p LEFT JOIN users u ON p.user_id = u.id WHERE p.id = ?`, [projectId], (err, updated) => {
                if (err) return res.status(500).json({ error: 'Failed to retrieve updated project' });
                res.json({ success: true, project: updated });
            });
        });
    });
});

app.get('/api/admin/projects/:projectId/messages', requireAdmin, (req, res) => {
    const projectId = parseInt(req.params.projectId, 10);
    if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

    db.get(`SELECT id FROM projects WHERE id = ?`, [projectId], (err, project) => {
        if (err || !project) return res.status(404).json({ error: 'Project not found' });

        db.all(`SELECT m.*, u.name as sender_name, u.email as sender_email FROM messages m LEFT JOIN users u ON m.sender_user_id = u.id WHERE m.project_id = ? ORDER BY m.created_at ASC`,
            [projectId], (err, messages) => {
                if (err) return res.status(500).json({ error: 'Failed to fetch messages' });
                res.json(messages || []);
            });
    });
});

app.post('/api/admin/projects/:projectId/messages', requireAdmin, (req, res) => {
    const projectId = parseInt(req.params.projectId, 10);
    const { message } = req.body;

    if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });
    if (!message || message.trim() === '') return res.status(400).json({ error: 'Message cannot be empty' });
    if (message.length > 3000) return res.status(400).json({ error: 'Message length exceeds 3000 characters' });

    db.get(`SELECT id FROM projects WHERE id = ?`, [projectId], (err, project) => {
        if (err || !project) return res.status(404).json({ error: 'Project not found' });

        db.run(`INSERT INTO messages (project_id, sender_user_id, sender_role, message) VALUES (?, ?, 'SUPER_ADMIN', ?)`,
            [projectId, req.user.id, message.trim()], function(err) {
                if (err) return res.status(500).json({ error: 'Failed to send message' });
                db.get(`SELECT * FROM messages WHERE id = ?`, [this.lastID], (err, newMsg) => {
                    if (err) return res.status(500).json({ error: 'Failed to retrieve message' });
                    res.json(newMsg);
                });
            });
    });
});

app.post('/api/admin/projects/:projectId/messages/read', requireAdmin, (req, res) => {
    const projectId = parseInt(req.params.projectId, 10);
    if (isNaN(projectId)) return res.status(400).json({ error: 'Invalid project ID' });

    db.get(`SELECT id FROM projects WHERE id = ?`, [projectId], (err, project) => {
        if (err || !project) return res.status(404).json({ error: 'Project not found' });

        db.run(`UPDATE messages SET read_at = CURRENT_TIMESTAMP WHERE project_id = ? AND sender_role = 'CUSTOMER' AND read_at IS NULL`,
            [projectId], (err) => {
                if (err) return res.status(500).json({ error: 'Failed to update read status' });
                res.json({ success: true });
            });
    });
});

// Portfolio Endpoint fallback
app.get('/api/portfolio', (req, res) => {
    res.json([
        { title: 'Tech Startup Dashboard', category: 'Web App', description: 'Advanced responsive dashboard built for an AI analytics company.', image_url: 'https://placehold.co/800x600/18181b/6366f1?text=Dashboard+UI' },
        { title: 'Local Coffee Roaster', category: 'E-Commerce', description: 'Clean, modern storefront with integrated local delivery zones.', image_url: 'https://placehold.co/800x600/18181b/6366f1?text=E-Commerce+Store' }
    ]);
});

// Fallback to serve index.html for frontend routing (Express 5 compatible)
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

const express = require('express');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;
const usersFile = path.join(__dirname, 'users.json');
const impersonationLogFile = path.join(__dirname, 'impersonation-log.json');
const sessions = {};

app.use(express.json());
app.use(express.static(__dirname));
app.get("/", (req, res) => {
	res.sendFile(path.join(__dirname, "LinuxQuest.html"));
});

function ensureUsersFile() {
  if (!fs.existsSync(usersFile)) {
    fs.writeFileSync(usersFile, '[]', 'utf8');
  }
}

function ensureImpersonationLogFile() {
  if (!fs.existsSync(impersonationLogFile)) {
    fs.writeFileSync(impersonationLogFile, '[]', 'utf8');
  }
}

function loadUsers() {
  ensureUsersFile();
  const raw = fs.readFileSync(usersFile, 'utf8');
  try {
    return JSON.parse(raw);
  } catch (err) {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2), 'utf8');
}

function logImpersonationEvent(event) {
  ensureImpersonationLogFile();
  const raw = fs.readFileSync(impersonationLogFile, 'utf8');
  const logs = raw ? JSON.parse(raw) : [];
  logs.push(event);
  fs.writeFileSync(impersonationLogFile, JSON.stringify(logs, null, 2), 'utf8');
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = header.split(';').reduce((cookiesObj, cookie) => {
    const [name, ...rest] = cookie.split('=');
    if (!name) return cookiesObj;
    cookiesObj[name.trim()] = rest.join('=').trim();
    return cookiesObj;
  }, {});

  if (req.headers.authorization) {
    const auth = String(req.headers.authorization).trim();
    if (auth.toLowerCase().startsWith('bearer ')) {
      cookies.sessionId = auth.slice(7).trim();
    }
  }

  if (!cookies.sessionId && req.headers['x-session-id']) {
    cookies.sessionId = String(req.headers['x-session-id']).trim();
  }

  return cookies;
}

function getSession(req) {
  const cookies = parseCookies(req);
  if (!cookies.sessionId) return null;
  return sessions[cookies.sessionId] || null;
}

function getUserById(userId) {
  const users = loadUsers();
  return users.find((user) => user.id === userId) || null;
}

function safeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    created_at: user.created_at,
    progress: user.progress || {
      coursesEnrolled: 0,
      completionRate: '0%',
      activeChallenges: 0,
    },
  };
}

function createSession(userId, originalAdminId = null, impersonatedUserId = null) {
  const sessionId = crypto.randomBytes(16).toString('hex');
  sessions[sessionId] = {
    userId,
    originalAdminId,
    impersonatedUserId,
    createdAt: new Date().toISOString(),
  };
  return { sessionId, ...sessions[sessionId] };
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getEffectiveUser(session) {
  if (!session) return null;
  const effectiveId = session.impersonatedUserId || session.userId;
  return getUserById(effectiveId);
}

function getRealUser(session) {
  if (!session) return null;
  return getUserById(session.userId);
}

function requireLogin(req, res, next) {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ success: false, message: 'Authentication required.' });
  }

  req.session = session;
  req.realUser = getRealUser(session);
  req.effectiveUser = getEffectiveUser(session);

  if (!req.realUser) {
    return res.status(401).json({ success: false, message: 'Authentication required.' });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (!req.realUser || req.realUser.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin privileges required.' });
  }

  next();
}

function ensureAdminUser() {
  const users = loadUsers();
  const adminExists = users.some((user) => user.role === 'admin');

  if (!adminExists) {
    const passwordHash = bcrypt.hashSync('AdminPass123', 10);
    users.push({
      id: Date.now().toString(),
      name: 'Lab Admin',
      email: 'admin@linuxquest.lab',
      password_hash: passwordHash,
      role: 'admin',
      created_at: new Date().toISOString(),
      progress: {
        coursesEnrolled: 0,
        completionRate: '0%',
        activeChallenges: 0,
      },
    });
    saveUsers(users);
  }
}

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: 'Name, email, and password are required.' });
  }

  const trimmedName = String(name).trim();
  const normalizedEmail = String(email).trim().toLowerCase();
  const trimmedPassword = String(password);

  if (!trimmedName) {
    return res.status(400).json({ success: false, message: 'Student name cannot be empty.' });
  }

  if (!isValidEmail(normalizedEmail)) {
    return res.status(400).json({ success: false, message: 'Please provide a valid email address.' });
  }

  if (trimmedPassword.length < 8) {
    return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long.' });
  }

  const users = loadUsers();
  const existingUser = users.find((u) => u.email.toLowerCase() === normalizedEmail);
  if (existingUser) {
    return res.status(409).json({ success: false, message: 'That email is already registered.' });
  }

  try {
    const passwordHash = await bcrypt.hash(trimmedPassword, 10);
    const newUser = {
      id: Date.now().toString(),
      name: trimmedName,
      email: normalizedEmail,
      password_hash: passwordHash,
      role: 'student',
      created_at: new Date().toISOString(),
      progress: {
        coursesEnrolled: 1,
        completionRate: '0%',
        activeChallenges: 0,
      },
    };

    users.push(newUser);
    saveUsers(users);

    console.log('Register saved user:', { email: newUser.email, role: newUser.role });
    return res.status(201).json({ success: true, message: 'Student account created successfully.' });
  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({ success: false, message: 'Server error. Please try again later.' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('Login received email:', email);

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required.' });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const users = loadUsers();
  const user = users.find((u) => u.email.toLowerCase() === normalizedEmail);

  if (!user) {
    console.log('Login user not found for email:', normalizedEmail);
    return res.status(404).json({ success: false, message: 'User not found.' });
  }

  if (user.locked) {
    console.log('Login blocked for locked user:', normalizedEmail);
    return res.status(423).json({ success: false, message: 'Account locked.' });
  }

  const isMatch = await bcrypt.compare(String(password), user.password_hash);
  console.log('Password match for', normalizedEmail, ':', isMatch);
  if (!isMatch) {
    return res.status(401).json({ success: false, message: 'Incorrect password.' });
  }

  const session = createSession(user.id);
  res.cookie('sessionId', session.sessionId, { httpOnly: true, sameSite: 'Lax', path: '/' });
  console.log('Login successful for', normalizedEmail, 'role:', user.role);
  return res.json({ success: true, sessionId: session.sessionId, user: safeUser(user), isAdmin: user.role === 'admin' });
});

app.post('/logout', (req, res) => {
  const session = getSession(req);
  if (session) {
    const cookies = parseCookies(req);
    delete sessions[cookies.sessionId];
  }
  res.clearCookie('sessionId');
  return res.json({ success: true });
});

app.get('/session', (req, res) => {
  const session = getSession(req);
  if (!session) {
    return res.json({ success: false, message: 'Not authenticated.' });
  }

  const realUser = getRealUser(session);
  const effectiveUser = getEffectiveUser(session);
  if (!realUser) {
    return res.json({ success: false, message: 'Session invalid.' });
  }

  return res.json({
    success: true,
    user: safeUser(effectiveUser),
    currentUser: safeUser(realUser),
    impersonation: {
      active: Boolean(session.impersonatedUserId),
      originalAdmin: session.impersonatedUserId ? safeUser(realUser) : null,
      student: session.impersonatedUserId ? safeUser(effectiveUser) : null,
    },
    canImpersonate: realUser.role === 'admin',
    isAdmin: realUser.role === 'admin',
  });
});

app.get('/users', requireLogin, requireAdmin, (req, res) => {
  const users = loadUsers();
  const students = users.filter((user) => user.role === 'student').map(safeUser);
  return res.json({ success: true, students });
});

app.post('/impersonate', requireLogin, requireAdmin, (req, res) => {
  const { studentId } = req.body;
  if (!studentId) {
    return res.status(400).json({ success: false, message: 'Student ID is required.' });
  }

  const students = loadUsers().filter((user) => user.role === 'student');
  const student = students.find((user) => user.id === studentId);
  if (!student) {
    return res.status(404).json({ success: false, message: 'Student not found.' });
  }

  if (req.realUser.id === student.id) {
    return res.status(400).json({ success: false, message: 'Cannot impersonate your own account.' });
  }

  req.session.impersonatedUserId = student.id;
  req.session.originalAdminId = req.realUser.id;
  logImpersonationEvent({
    admin_user_id: req.realUser.id,
    student_user_id: student.id,
    timestamp: new Date().toISOString(),
    action: 'impersonation_started',
  });

  return res.json({ success: true, message: 'Impersonation started.' });
});

app.post('/impersonation/stop', requireLogin, (req, res) => {
  if (!req.session.impersonatedUserId) {
    return res.status(400).json({ success: false, message: 'No active impersonation session.' });
  }

  const studentId = req.session.impersonatedUserId;
  req.session.impersonatedUserId = null;
  req.session.originalAdminId = null;
  logImpersonationEvent({
    admin_user_id: req.realUser.id,
    student_user_id: studentId,
    timestamp: new Date().toISOString(),
    action: 'impersonation_ended',
  });

  return res.json({ success: true, message: 'Impersonation ended.' });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'LinuxQuest.html'));
});

ensureAdminUser();
ensureImpersonationLogFile();

app.listen(port, () => {
  console.log(`LinuxQuest server running at http://localhost:${port}`);
});

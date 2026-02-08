// server.js - FULL UPDATED VERSION with permanent Access ID login requirement

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');

const { LowSync } = require('lowdb');
const { JSONFileSync } = require('lowdb/node');

const app = express();
const PORT = process.env.PORT || 5000;

// === CHANGE THESE FOR SECURITY! ===
const ADMIN_PASSWORD = 'nursa2026';     // ← CHANGE THIS TO SOMETHING STRONG
const VOTE_SALT = 'nursa2026-salt';     // ← CHANGE THIS TOO

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Databases
const voteFile = path.join(__dirname, 'votes.json');
const voteAdapter = new JSONFileSync(voteFile);
const voteDb = new LowSync(voteAdapter, { votes: [], votedHashes: [] });
voteDb.read();
voteDb.data ||= { votes: [], votedHashes: [] };
voteDb.write();

const studentsFile = path.join(__dirname, 'students.json');
const studentsAdapter = new JSONFileSync(studentsFile);
const studentsDb = new LowSync(studentsAdapter, []);
studentsDb.read();
studentsDb.data ||= [];
studentsDb.write();

const configFile = path.join(__dirname, 'config.json');
const configAdapter = new JSONFileSync(configFile);
const configDb = new LowSync(configAdapter, {
    votingStart: new Date('2026-01-06T08:00:00').getTime(),
    votingEnd:   new Date('2026-01-10T23:59:59').getTime()
});
configDb.read();

let votingStart = configDb.data.votingStart;
let votingEnd = configDb.data.votingEnd;

// In-memory admin token
let currentAdminToken = null;

// === HASHING UTILITIES ===
function createHash(value) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(value, salt, 10000, 64, 'sha512').toString('hex');
    return { salt, hash };
}

function verifyHash(value, salt, storedHash) {
    const hash = crypto.pbkdf2Sync(value, salt, 10000, 64, 'sha512').toString('hex');
    return hash === storedHash;
}

function getVoteHash(studentId) {
    return crypto.createHash('sha256').update(studentId + VOTE_SALT).digest('hex');
}

// === ADMIN AUTH MIDDLEWARE ===
function requireAdmin(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token === currentAdminToken) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized' });
    }
}

// === STUDENT AUTH ENDPOINTS ===
// Register - now generates permanent Access ID
app.post('/api/register', (req, res) => {
    const { studentId, password, confirmPassword, question, answer } = req.body;

    if (!studentId || !password || password !== confirmPassword || !question || !answer) {
        return res.json({ success: false, message: "All fields required and passwords must match" });
    }

    const upperId = studentId.toUpperCase();
    const student = studentsDb.data.find(s => s.id === upperId);
    if (!student) return res.json({ success: false, message: "Invalid Student ID - not eligible" });
    if (student.hashedPassword) return res.json({ success: false, message: "Account already registered" });

    // Generate permanent Access ID (shown only once)
    const accessId = 'AID-' + Math.random().toString(36).substr(2, 9).toUpperCase();

    // Generate one-time recovery code
    const recoveryCode = Math.floor(10000000 + Math.random() * 90000000).toString();

    const pwd = createHash(password);
    const ans = createHash(answer.trim().toLowerCase());
    const rec = createHash(recoveryCode);
    const acc = createHash(accessId);

    student.hashedPassword   = pwd.hash;
    student.passwordSalt     = pwd.salt;
    student.question         = question;
    student.hashedAnswer     = ans.hash;
    student.answerSalt       = ans.salt;
    student.hashedRecovery   = rec.hash;
    student.recoverySalt     = rec.salt;
    student.hashedAccessId   = acc.hash;
    student.accessIdSalt     = acc.salt;

    studentsDb.write();

    res.json({
        success: true,
        accessId,       // permanent login credential
        recoveryCode    // one-time password reset code
    });
});

// Login - now requires Access ID every time
app.post('/api/login', (req, res) => {
    const { studentId, password, accessId } = req.body;

    if (!studentId || !password || !accessId) {
        return res.json({ success: false, message: "Student ID, password and Access ID are all required" });
    }

    const upperId = studentId.toUpperCase();
    const student = studentsDb.data.find(s => s.id === upperId);

    if (!student || !student.hashedPassword || !student.hashedAccessId) {
        return res.json({ success: false, message: "Account not found or not fully registered" });
    }

    const pwdValid   = verifyHash(password, student.passwordSalt, student.hashedPassword);
    const accessValid = verifyHash(accessId.toUpperCase(), student.accessIdSalt, student.hashedAccessId);

    if (!pwdValid || !accessValid) {
        return res.json({ success: false, message: "Invalid credentials" });
    }

    const voteHash = getVoteHash(studentId);
    if (voteDb.data.votedHashes.includes(voteHash)) {
        return res.json({ success: false, message: "You have already voted!" });
    }

    res.json({
        success: true,
        student: { id: student.id, name: student.name || "Student" }
    });
});

// Get security question for forgot password
app.post('/api/forgot-question', (req, res) => {
    const { studentId } = req.body;
    const student = studentsDb.data.find(s => s.id === studentId.toUpperCase());

    if (!student || !student.question) {
        return res.json({ success: false, message: "Student not found or not registered" });
    }

    res.json({ success: true, question: student.question });
});

// Reset password (using answer OR recovery code)
app.post('/api/reset-password', (req, res) => {
    const { studentId, answer, recoveryCode, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
        return res.json({ success: false, message: "Passwords do not match" });
    }

    const student = studentsDb.data.find(s => s.id === studentId.toUpperCase());
    if (!student) return res.json({ success: false, message: "Invalid Student ID" });

    let valid = false;

    if (answer) {
        valid = verifyHash(answer.trim().toLowerCase(), student.answerSalt, student.hashedAnswer);
    } else if (recoveryCode) {
        valid = verifyHash(recoveryCode, student.recoverySalt, student.hashedRecovery);
    }

    if (!valid) {
        return res.json({ success: false, message: "Incorrect security answer or recovery code" });
    }

    const pwd = createHash(newPassword);
    student.hashedPassword = pwd.hash;
    student.passwordSalt = pwd.salt;
    studentsDb.write();

    res.json({ success: true, message: "Password reset successful" });
});

// === VOTING ENDPOINTS ===
app.post('/api/vote', (req, res) => {
    const { studentId, president, vicepresident, secretary } = req.body;
    const now = Date.now();

    if (now < votingStart || now > votingEnd) {
        return res.json({ success: false, message: "Voting period is not open!" });
    }

    const hash = getVoteHash(studentId);
    if (voteDb.data.votedHashes.includes(hash)) {
        return res.json({ success: false, message: "You have already voted!" });
    }

    const refCode = 'NM-2026-' + Math.floor(1000 + Math.random() * 9000);

    voteDb.data.votes.push({
        president,
        vicepresident,
        secretary,
        timestamp: new Date().toISOString(),
        refCode
    });
    voteDb.data.votedHashes.push(hash);
    voteDb.write();

    res.json({ success: true, refCode });
});

app.get('/api/results', (req, res) => {
    const votes = voteDb.data.votes || [];
    const counts = {
        president: { "Sarah Johnson": 0, "John Davis": 0 },
        vicepresident: { "Michael Chen": 0, "Lisa Williams": 0 },
        secretary: { "Emily Brown": 0, "Robert Garcia": 0 }
    };

    votes.forEach(v => {
        if (v.president) counts.president[v.president]++;
        if (v.vicepresident) counts.vicepresident[v.vicepresident]++;
        if (v.secretary) counts.secretary[v.secretary]++;
    });

    res.json({ counts, total: votes.length });
});

app.get('/api/voting-status', (req, res) => {
    const now = Date.now();
    const isOpen = now >= votingStart && now <= votingEnd;
    res.json({ isOpen, start: votingStart, end: votingEnd });
});

// === ADMIN ENDPOINTS ===
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        currentAdminToken = crypto.randomBytes(32).toString('hex');
        res.json({ success: true, token: currentAdminToken });
    } else {
        res.json({ success: false, message: "Incorrect password" });
    }
});

app.post('/api/admin/set-period', requireAdmin, (req, res) => {
    const { start, end } = req.body;
    if (!start || !end) return res.status(400).json({ success: false, message: "Missing dates" });
    configDb.data.votingStart = new Date(start).getTime();
    configDb.data.votingEnd = new Date(end).getTime();
    configDb.write();
    votingStart = configDb.data.votingStart;
    votingEnd = configDb.data.votingEnd;
    res.json({ success: true });
});

app.post('/api/open-voting', requireAdmin, (req, res) => {
    configDb.data.votingStart = Date.now() - 1000;
    configDb.data.votingEnd = new Date('2030-12-31').getTime();
    configDb.write();
    votingStart = configDb.data.votingStart;
    votingEnd = configDb.data.votingEnd;
    res.json({ success: true });
});

app.post('/api/close-voting', requireAdmin, (req, res) => {
    configDb.data.votingEnd = Date.now() - 1000;
    configDb.write();
    votingEnd = configDb.data.votingEnd;
    res.json({ success: true });
});

app.post('/api/reset', requireAdmin, (req, res) => {
    voteDb.data.votes = [];
    voteDb.data.votedHashes = [];
    voteDb.write();
    res.json({ success: true });
});

app.get('/api/export-votes', requireAdmin, (req, res) => {
    const votes = voteDb.data.votes || [];
    if (votes.length === 0) return res.status(200).send('No votes recorded.\n');

    let csv = 'President,VicePresident,Secretary,Timestamp,ReferenceCode\n';
    votes.forEach(v => {
        csv += `"${(v.president || '')}","${(v.vicepresident || '')}","${(v.secretary || '')}","${v.timestamp}","${v.refCode}"\n`;
    });

    res.header('Content-Type', 'text/csv');
    res.attachment(`nursa-votes-${new Date().toISOString().slice(0,10)}.csv`);
    res.send(csv);
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
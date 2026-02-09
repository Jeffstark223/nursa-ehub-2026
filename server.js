// server.js - FIXED & COMPLETE VERSION
// Database init moved to top + safer defaults + better logging

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const { LowSync } = require('lowdb');
const { JSONFileSync } = require('lowdb/node');

const app = express();
const PORT = process.env.PORT || 5000;

// ────────────────────────────────────────────────
//   SECURITY CONSTANTS – CHANGE THESE IN PRODUCTION!
// ────────────────────────────────────────────────
const ADMIN_PASSWORD = 'nursa2026';       // ← CHANGE TO STRONG PASSWORD
const VOTE_SALT      = 'nursa2026-salt';  // ← CHANGE TO UNIQUE LONG STRING

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ────────────────────────────────────────────────
//   DATABASE SETUP – MUST COME BEFORE ANY .read() or .data access
// ────────────────────────────────────────────────

const voteFile = path.join(__dirname, 'votes.json');
const voteAdapter = new JSONFileSync(voteFile);
const voteDb = new LowSync(voteAdapter, { votes: [], votedHashes: [] });
voteDb.data ||= { votes: [], votedHashes: [] };   // safe default
voteDb.read();                                    // now safe
voteDb.write();                                   // ensure file exists

const studentsFile = path.join(__dirname, 'students.json');
const studentsAdapter = new JSONFileSync(studentsFile);
const studentsDb = new LowSync(studentsAdapter, []);
studentsDb.data ||= [];
studentsDb.read();
studentsDb.write();

const configFile = path.join(__dirname, 'config.json');
const configAdapter = new JSONFileSync(configFile);
const configDb = new LowSync(configAdapter, {
    votingStart: new Date('2026-01-06T08:00:00').getTime(),
    votingEnd:   new Date('2026-01-10T23:59:59').getTime()
});
configDb.read();
configDb.data ||= {
    votingStart: new Date('2026-01-06T08:00:00').getTime(),
    votingEnd:   new Date('2026-01-10T23:59:59').getTime()
};
configDb.write();

let votingStart = configDb.data.votingStart;
let votingEnd   = configDb.data.votingEnd;

// Debug output (will appear in Render logs)
console.log('───────────────────────────────────────────────');
console.log('Database files initialized:');
console.log('Votes count:      ', voteDb.data.votes?.length ?? 0);
console.log('Voted hashes:     ', voteDb.data.votedHashes?.length ?? 0);
console.log('Students loaded:  ', studentsDb.data.length);
console.log('Voting period:    ', new Date(votingStart).toISOString(), '→', new Date(votingEnd).toISOString());
console.log('───────────────────────────────────────────────');

// In-memory admin token (resets on restart)
let currentAdminToken = null;

// ────────────────────────────────────────────────
//   HASHING HELPERS
// ────────────────────────────────────────────────

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

// ────────────────────────────────────────────────
//   ADMIN AUTH MIDDLEWARE
// ────────────────────────────────────────────────

function requireAdmin(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token === currentAdminToken) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized' });
    }
}

// ────────────────────────────────────────────────
//   STUDENT ENDPOINTS
// ────────────────────────────────────────────────

// Register student (creates permanent Access ID)
app.post('/api/register', (req, res) => {
    const { studentId, password, confirmPassword, question, answer } = req.body;

    if (!studentId || !password || password !== confirmPassword || !question || !answer) {
        return res.json({ success: false, message: "All fields required and passwords must match" });
    }

    const upperId = studentId.toUpperCase().trim();
    const existing = studentsDb.data.find(s => s.id === upperId);

    if (existing) {
        return res.json({ success: false, message: "Student ID already registered" });
    }

    const accessId = 'ACCESS-' + crypto.randomBytes(8).toString('hex').toUpperCase();
    const recoveryCode = crypto.randomBytes(10).toString('hex').toUpperCase();

    const newStudent = {
        id: upperId,
        name: "Student " + upperId, // ← you can improve this later
        accessId,
        recoveryCode,
        passwordSalt: null,
        passwordHash: null,
        securityQuestion: question,
        securityAnswerHash: null
    };

    const { salt, hash } = createHash(password);
    newStudent.passwordSalt = salt;
    newStudent.passwordHash = hash;

    const { salt: ansSalt, hash: ansHash } = createHash(answer.toLowerCase().trim());
    newStudent.securityAnswerSalt = ansSalt;
    newStudent.securityAnswerHash = ansHash;

    studentsDb.data.push(newStudent);
    studentsDb.write();

    res.json({
        success: true,
        accessId,
        recoveryCode,
        message: "Registration successful! Save your Access ID and Recovery Code."
    });
});

// Login with Access ID
app.post('/api/login', (req, res) => {
    const { accessId, password } = req.body;

    if (!accessId || !password) {
        return res.json({ success: false, message: "Access ID and password required" });
    }

    const student = studentsDb.data.find(s => s.accessId === accessId.trim().toUpperCase());

    if (!student || !student.passwordHash || !student.passwordSalt) {
        return res.json({ success: false, message: "Invalid Access ID or not registered" });
    }

    if (verifyHash(password, student.passwordSalt, student.passwordHash)) {
        res.json({
            success: true,
            student: {
                id: student.id,
                name: student.name || "Student",
                accessId: student.accessId
            }
        });
    } else {
        res.json({ success: false, message: "Incorrect password" });
    }
});

// ────────────────────────────────────────────────
//   VOTING ENDPOINT
// ────────────────────────────────────────────────

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

// ────────────────────────────────────────────────
//   PUBLIC ENDPOINTS
// ────────────────────────────────────────────────

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

// ────────────────────────────────────────────────
//   ADMIN ENDPOINTS
// ────────────────────────────────────────────────

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
    configDb.data.votingEnd   = new Date(end).getTime();
    configDb.write();

    votingStart = configDb.data.votingStart;
    votingEnd   = configDb.data.votingEnd;

    res.json({ success: true });
});

app.post('/api/open-voting', requireAdmin, (req, res) => {
    configDb.data.votingStart = Date.now() - 1000;
    configDb.data.votingEnd   = new Date('2030-12-31').getTime();
    configDb.write();
    votingStart = configDb.data.votingStart;
    votingEnd   = configDb.data.votingEnd;
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

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
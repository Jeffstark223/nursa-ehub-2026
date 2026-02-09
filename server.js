// server.js – FULL VERSION with Supabase (February 2026)

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 5000;

// ────────────────────────────────────────────────
//   SECURITY – CHANGE THESE!
// ────────────────────────────────────────────────
const ADMIN_PASSWORD = 'nursa2026';       // ← CHANGE THIS
const VOTE_SALT      = 'nursa2026-salt';  // ← CHANGE THIS

// Supabase – PASTE YOUR OWN VALUES HERE
const supabaseUrl = 'https://auabscyallcyrupqitqw.supabase.co';          // ← your project URL
const supabaseAnonKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImF1YWJzY3lhbGxjeXJ1cHFpdHF3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzA1OTIyMjQsImV4cCI6MjA4NjE2ODIyNH0.7Red0vdmQIF85xFUYiJLTxDFXgDbQ6oXEn8DlXM8nt0'; // ← anon key
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ────────────────────────────────────────────────
//   VOTING PERIOD (loaded from config table)
// ────────────────────────────────────────────────
let votingStart = 0;
let votingEnd = 0;

async function loadVotingPeriod() {
  try {
    const { data, error } = await supabase
      .from('config')
      .select('key, value')
      .in('key', ['votingStart', 'votingEnd']);

    if (error) throw error;

    const startRow = data.find(row => row.key === 'votingStart');
    const endRow   = data.find(row => row.key === 'votingEnd');

    votingStart = startRow ? Number(startRow.value) : Date.now();
    votingEnd   = endRow   ? Number(endRow.value)   : Date.now() + 7 * 86400000;

    console.log(`Voting period: ${new Date(votingStart).toISOString()} → ${new Date(votingEnd).toISOString()}`);
  } catch (err) {
    console.error('Failed to load voting period:', err);
  }
}

loadVotingPeriod(); // run once at startup

// ────────────────────────────────────────────────
//   HASH HELPERS (unchanged)
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
//   ADMIN AUTH MIDDLEWARE (unchanged)
// ────────────────────────────────────────────────

let currentAdminToken = null;

function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (token === currentAdminToken) {
    next();
  } else {
    res.status(401).json({ success: false, message: 'Unauthorized' });
  }
}

// ────────────────────────────────────────────────
//   STUDENT ENDPOINTS
// ────────────────────────────────────────────────

app.post('/api/register', async (req, res) => {
  const { studentId, password, confirmPassword, question, answer } = req.body;

  if (!studentId || !password || password !== confirmPassword || !question || !answer) {
    return res.json({ success: false, message: "All fields required and passwords must match" });
  }

  const cleanId = studentId.trim().toUpperCase();

  try {
    // Check if in official list (for now: allow any ID during testing)
    let allowed = null;
    const { data: allowedData, error: allowErr } = await supabase
      .from('allowed_students')
      .select('student_id, full_name')
      .eq('student_id', cleanId)
      .single();

    if (!allowErr && allowedData) {
      allowed = allowedData;
    } else {
      // Temporary: allow registration even if not in allowed_students (testing phase)
      allowed = { student_id: cleanId, full_name: `Test Student (${cleanId})` };
      // When you have the real list → uncomment this line instead:
      // return res.json({ success: false, message: "Invalid Student ID – not found in department records" });
    }

    // Check if already registered
    const { data: existing } = await supabase
      .from('registered_students')
      .select('student_id')
      .eq('student_id', cleanId)
      .maybeSingle();

    if (existing) {
      return res.json({ success: false, message: "This Student ID is already registered" });
    }

    const accessId = 'ACCESS-' + crypto.randomBytes(8).toString('hex').toUpperCase();
    const recoveryCode = crypto.randomBytes(10).toString('hex').toUpperCase();

    const { salt: pwdSalt, hash: pwdHash } = createHash(password);
    const { salt: ansSalt, hash: ansHash } = createHash(answer.toLowerCase().trim());

    const { error: insertErr } = await supabase
      .from('registered_students')
      .insert({
        student_id: cleanId,
        access_id: accessId,
        recovery_code: recoveryCode,
        password_hash: pwdHash,
        password_salt: pwdSalt,
        security_question: question,
        security_answer_hash: ansHash,
        security_answer_salt: ansSalt
      });

    if (insertErr) throw insertErr;

    res.json({
      success: true,
      accessId,
      recoveryCode,
      name: allowed.full_name || "Student",
      message: "Registration successful! Save your Access ID and Recovery Code."
    });

  } catch (err) {
    console.error('Register error:', err.message);
    res.json({ success: false, message: "Server error – please try again" });
  }
});

app.post('/api/login', async (req, res) => {
  const { accessId, password } = req.body;

  if (!accessId || !password) {
    return res.json({ success: false, message: "Access ID and password required" });
  }

  const cleanAccess = accessId.trim().toUpperCase();

  try {
    const { data: student, error } = await supabase
      .from('registered_students')
      .select(`
        student_id,
        password_hash,
        password_salt,
        allowed_students!inner (full_name)
      `)
      .eq('access_id', cleanAccess)
      .single();

    if (error || !student) {
      return res.json({ success: false, message: "Invalid Access ID or not registered" });
    }

    if (verifyHash(password, student.password_salt, student.password_hash)) {
      res.json({
        success: true,
        student: {
          id: student.student_id,
          name: student.allowed_students?.full_name || "Student",
          accessId: cleanAccess
        }
      });
    } else {
      res.json({ success: false, message: "Incorrect password" });
    }
  } catch (err) {
    console.error('Login error:', err.message);
    res.json({ success: false, message: "Server error" });
  }
});
// In login fetch success handler
localStorage.setItem('currentStudent', JSON.stringify({
    id: data.student.id,
    name: data.student.name,
    accessId: data.student.accessId
  }));

app.post('/api/vote', async (req, res) => {
  const { studentId, president, vicepresident, secretary } = req.body;
  const now = Date.now();

  if (now < votingStart || now > votingEnd) {
    return res.json({ success: false, message: "Voting period is not open!" });
  }

  const voterHash = getVoteHash(studentId);

  try {
    const { data: existing } = await supabase
      .from('votes')
      .select('id')
      .eq('voter_hash', voterHash)
      .maybeSingle();

    if (existing) {
      return res.json({ success: false, message: "You have already voted!" });
    }

    const refCode = 'NM-2026-' + Math.floor(1000 + Math.random() * 9000);

    const { error } = await supabase
      .from('votes')
      .insert({
        voter_hash: voterHash,
        president,
        vicepresident,
        secretary,
        ref_code: refCode
      });

    if (error) throw error;

    res.json({ success: true, refCode });
  } catch (err) {
    console.error('Vote error:', err.message);
    res.json({ success: false, message: "Server error" });
  }
});

// ────────────────────────────────────────────────
//   PUBLIC ENDPOINTS
// ────────────────────────────────────────────────

app.get('/api/results', async (req, res) => {
  try {
    const { data: votes, error } = await supabase
      .from('votes')
      .select('president, vicepresident, secretary');

    if (error) throw error;

    const counts = {
      president: { "Sarah Johnson": 0, "John Davis": 0 },
      vicepresident: { "Michael Chen": 0, "Lisa Williams": 0 },
      secretary: { "Emily Brown": 0, "Robert Garcia": 0 }
    };

    votes.forEach(v => {
      if (v.president) counts.president[v.president] = (counts.president[v.president] || 0) + 1;
      if (v.vicepresident) counts.vicepresident[v.vicepresident] = (counts.vicepresident[v.vicepresident] || 0) + 1;
      if (v.secretary) counts.secretary[v.secretary] = (counts.secretary[v.secretary] || 0) + 1;
    });

    res.json({ counts, total: votes.length });
  } catch (err) {
    console.error('Results error:', err.message);
    res.status(500).json({ success: false, message: "Error fetching results" });
  }
});

app.get('/api/voting-status', (req, res) => {
  const now = Date.now();
  const isOpen = now >= votingStart && now <= votingEnd;
  res.json({ isOpen, start: votingStart, end: votingEnd });
});

// ────────────────────────────────────────────────
//   ADMIN ENDPOINTS (example – keep / adapt as needed)
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

// Add your other admin routes here (set-period, open-voting, close-voting, reset, export-votes)
// You can adapt them to use supabase instead of lowdb

// ────────────────────────────────────────────────
//   START SERVER
// ────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Supabase URL: ${supabaseUrl}`);
});
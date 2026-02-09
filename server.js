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

    console.log(`Voting period loaded: ${new Date(votingStart).toISOString()} → ${new Date(votingEnd).toISOString()}`);
  } catch (err) {
    console.error('Failed to load voting period:', err);
  }
}

// Call it once at startup
loadVotingPeriod();

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
      const { data: studentRecord, error } = await supabase
        .from('registered_students')
        .select(`
          student_id,
          password_hash,
          password_salt,
          allowed_students!inner (full_name)
        `)
        .eq('access_id', cleanAccess)
        .single();
  
      if (error || !studentRecord) {
        return res.json({ success: false, message: "Invalid Access ID or not registered" });
      }
  
      if (verifyHash(password, studentRecord.password_salt, studentRecord.password_hash)) {
        res.json({
          success: true,
          student: {
            id: studentRecord.student_id,
            name: studentRecord.allowed_students?.full_name || "Student",
            accessId: cleanAccess
          }
        });
      } else {
        res.json({ success: false, message: "Incorrect password" });
      }
    } catch (err) {
      console.error('Login error:', err.message);
      res.json({ success: false, message: "Server error – please try again" });
    }
  });

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
//   ADMIN LOGIN (unchanged)
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
  
  // ────────────────────────────────────────────────
  //   ADMIN: Set custom voting period
  // ────────────────────────────────────────────────
  app.post('/api/admin/set-period', requireAdmin, async (req, res) => {
    const { start, end } = req.body;
  
    if (!start || !end || isNaN(new Date(start).getTime()) || isNaN(new Date(end).getTime())) {
      return res.status(400).json({ success: false, message: "Invalid or missing start/end dates" });
    }
  
    const startTime = new Date(start).getTime();
    const endTime   = new Date(end).getTime();
  
    try {
      // Update config table (upsert)
      await supabase
        .from('config')
        .upsert([
          { key: 'votingStart', value: startTime },
          { key: 'votingEnd',   value: endTime }
        ], { onConflict: 'key' });
  
      // Reload in-memory variables
      await loadVotingPeriod();
  
      res.json({ success: true, message: "Voting period updated successfully" });
    } catch (err) {
      console.error('Set period error:', err.message);
      res.status(500).json({ success: false, message: "Failed to update voting period" });
    }
  });
  
  // ────────────────────────────────────────────────
  //   ADMIN: Open voting now
  // ────────────────────────────────────────────────
  app.post('/api/open-voting', requireAdmin, async (req, res) => {
    try {
      const now = Date.now();
  
      await supabase
        .from('config')
        .upsert([
          { key: 'votingStart', value: now - 1000 }, // slightly in the past
          { key: 'votingEnd',   value: new Date('2030-12-31').getTime() }
        ], { onConflict: 'key' });
  
      await loadVotingPeriod();
  
      res.json({ success: true, message: "Voting opened successfully" });
    } catch (err) {
      console.error('Open voting error:', err.message);
      res.status(500).json({ success: false, message: "Failed to open voting" });
    }
  });
  
  // ────────────────────────────────────────────────
  //   ADMIN: Close voting now
  // ────────────────────────────────────────────────
  app.post('/api/close-voting', requireAdmin, async (req, res) => {
    try {
      const now = Date.now();
  
      await supabase
        .from('config')
        .upsert([
          { key: 'votingEnd', value: now - 1000 }
        ], { onConflict: 'key' });
  
      await loadVotingPeriod();
  
      res.json({ success: true, message: "Voting closed successfully" });
    } catch (err) {
      console.error('Close voting error:', err.message);
      res.status(500).json({ success: false, message: "Failed to close voting" });
    }
  });
  
  // ────────────────────────────────────────────────
  //   ADMIN: Reset all votes (deletes everything from votes table)
  // ────────────────────────────────────────────────
  app.post('/api/reset', requireAdmin, async (req, res) => {
    try {
      const { error } = await supabase
        .from('votes')
        .delete()
        .neq('id', 0);  // delete all rows
  
      if (error) throw error;
  
      res.json({ success: true, message: "All votes have been reset" });
    } catch (err) {
      console.error('Reset votes error:', err.message);
      res.status(500).json({ success: false, message: "Failed to reset votes" });
    }
  });
  
  // ────────────────────────────────────────────────
  //   ADMIN: Export votes as CSV
  // ────────────────────────────────────────────────
  app.get('/api/export-votes', requireAdmin, async (req, res) => {
    try {
      const { data: votes, error } = await supabase
        .from('votes')
        .select('president, vicepresident, secretary, timestamp, ref_code');
  
      if (error) throw error;
  
      if (!votes || votes.length === 0) {
        return res.status(200).send('No votes recorded yet.\n');
      }
  
      let csv = 'President,VicePresident,Secretary,Timestamp,ReferenceCode\n';
  
      votes.forEach(v => {
        csv += `"${(v.president || '')}","${(v.vicepresident || '')}","${(v.secretary || '')}","${v.timestamp}","${v.ref_code}"\n`;
      });
  
      res.header('Content-Type', 'text/csv');
      res.attachment(`nursa-votes-${new Date().toISOString().slice(0,10)}.csv`);
      res.send(csv);
    } catch (err) {
      console.error('Export error:', err.message);
      res.status(500).send('Error exporting votes');
    }
  });

// ────────────────────────────────────────────────
//   START SERVER
// ────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Supabase URL: ${supabaseUrl}`);
});
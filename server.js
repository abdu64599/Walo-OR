const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET =
  process.env.JWT_SECRET || "walo-or-secret-2026";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
  family: 4
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

/* =========================
   DATABASE
========================= */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      email VARCHAR(200) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(30) DEFAULT 'teacher',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS classes (
      id SERIAL PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      grade VARCHAR(100),
      teacher_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS students (
      id SERIAL PRIMARY KEY,
      full_name VARCHAR(200) NOT NULL,
      student_code VARCHAR(100) UNIQUE NOT NULL,
      phone VARCHAR(50),
      class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS attendance (
      id SERIAL PRIMARY KEY,
      student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
      class_id INTEGER REFERENCES classes(id) ON DELETE CASCADE,
      attendance_date DATE NOT NULL,
      status VARCHAR(30) NOT NULL
        CHECK (status IN ('present','absent','late')),
      note TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(student_id, attendance_date)
    );

    CREATE TABLE IF NOT EXISTS exam_results (
      id SERIAL PRIMARY KEY,
      student_id INTEGER NOT NULL
        REFERENCES students(id) ON DELETE CASCADE,
      exam_name VARCHAR(200) NOT NULL,
      subject VARCHAR(150),
      score NUMERIC(10,2) NOT NULL DEFAULT 0,
      total NUMERIC(10,2) NOT NULL DEFAULT 100,
      exam_date DATE DEFAULT CURRENT_DATE,
      note TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("Database initialization completed.");
}

/* =========================
   AUTH HELPERS
========================= */

function makeToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: "30d"
  });
}

function teacherAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || "";

    if (!auth.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Teacher login godhi."
      });
    }

    const token = auth.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role !== "teacher") {
      return res.status(403).json({
        error: "Teacher qofaaf."
      });
    }

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      error: "Token sirrii miti."
    });
  }
}

function studentAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || "";

    if (!auth.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Barataan koodii isaa galchuu qaba."
      });
    }

    const token = auth.substring(7);
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role !== "student") {
      return res.status(403).json({
        error: "Barataa qofaaf."
      });
    }

    req.student = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      error: "Token sirrii miti."
    });
  }
}

/* =========================
   HEALTH
========================= */

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    app: "Walo-OR Attendance",
    time: new Date().toISOString()
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    app: "Walo-OR Attendance"
  });
});

/* =========================
   TEACHER REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Maqaa, email fi password guuti."
      });
    }

    const exists = await pool.query(
      `SELECT id FROM users WHERE email=$1`,
      [email]
    );

    if (exists.rows.length) {
      return res.status(400).json({
        error: "Email kun duraan jira."
      });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users
      (name,email,password_hash,role)
      VALUES ($1,$2,$3,'teacher')
      RETURNING id,name,email,role
      `,
      [name, email, hash]
    );

    const user = result.rows[0];

    const token = makeToken({
      id: user.id,
      role: "teacher",
      name: user.name,
      email: user.email
    });

    res.json({
      message: "Teacher account uumame.",
      token,
      user
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Register irratti rakkoon uumame."
    });
  }
});

/* =========================
   TEACHER LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    const result = await pool.query(
      `SELECT * FROM users WHERE email=$1`,
      [email]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Email ykn password dogoggora."
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Email ykn password dogoggora."
      });
    }

    const token = makeToken({
      id: user.id,
      role: "teacher",
      name: user.name,
      email: user.email
    });

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Login irratti rakkoon uumame."
    });
  }
});

/* =========================
   STUDENT LOGIN BY CODE
========================= */

app.post("/api/student/login", async (req, res) => {
  try {
    const { studentCode } = req.body;

    if (!studentCode) {
      return res.status(400).json({
        error: "Koodii barataa galchi."
      });
    }

    const result = await pool.query(
      `
      SELECT
        s.id,
        s.full_name,
        s.student_code,
        s.phone,
        s.class_id,
        c.name AS class_name,
        c.grade
      FROM students s
      LEFT JOIN classes c
        ON c.id = s.class_id
      WHERE LOWER(s.student_code)=LOWER($1)
      `,
      [studentCode.trim()]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Koodiin barataa hin argamne."
      });
    }

    const student = result.rows[0];

    const token = makeToken({
      id: student.id,
      role: "student",
      studentCode: student.student_code,
      classId: student.class_id
    });

    res.json({
      token,
      student
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Student login irratti rakkoon uumame."
    });
  }
});

/* =========================
   ME
========================= */

app.get("/api/me", teacherAuth, async (req, res) => {
  const result = await pool.query(
    `
    SELECT id,name,email,role
    FROM users
    WHERE id=$1
    `,
    [req.user.id]
  );

  res.json(result.rows[0]);
});

app.get("/api/student/me", studentAuth, async (req, res) => {
  const result = await pool.query(
    `
    SELECT
      s.id,
      s.full_name,
      s.student_code,
      s.phone,
      s.class_id,
      c.name AS class_name,
      c.grade
    FROM students s
    LEFT JOIN classes c
      ON c.id=s.class_id
    WHERE s.id=$1
    `,
    [req.student.id]
  );

  if (!result.rows.length) {
    return res.status(404).json({
      error: "Barataan hin argamne."
    });
  }

  res.json(result.rows[0]);
});

/* =========================
   CLASSES
========================= */

app.get("/api/classes", teacherAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        c.*,
        COUNT(s.id)::int AS student_count
      FROM classes c
      LEFT JOIN students s
        ON s.class_id=c.id
      WHERE c.teacher_id=$1
      GROUP BY c.id
      ORDER BY c.id DESC
      `,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Kutaa argachuu hin dandeenye."
    });
  }
});

app.post("/api/classes", teacherAuth, async (req, res) => {
  try {
    const {
      name,
      grade
    } = req.body;

    if (!name) {
      return res.status(400).json({
        error: "Maqaa kutaa galchi."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO classes
      (name,grade,teacher_id)
      VALUES ($1,$2,$3)
      RETURNING *
      `,
      [name, grade || "", req.user.id]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Kutaa uumuu hin dandeenye."
    });
  }
});

app.delete("/api/classes/:id", teacherAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      DELETE FROM classes
      WHERE id=$1 AND teacher_id=$2
      RETURNING id
      `,
      [req.params.id, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Kutaan hin argamne."
      });
    }

    res.json({
      message: "Kutaan haqame."
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Kutaa haquu hin dandeenye."
    });
  }
});

/* =========================
   STUDENTS
========================= */

app.get("/api/students", teacherAuth, async (req, res) => {
  try {
    const params = [req.user.id];

    let query = `
      SELECT
        s.*,
        c.name AS class_name,
        c.grade
      FROM students s
      LEFT JOIN classes c
        ON c.id=s.class_id
      WHERE c.teacher_id=$1
    `;

    if (req.query.classId) {
      params.push(req.query.classId);
      query += ` AND s.class_id=$2`;
    }

    query += ` ORDER BY s.id DESC`;

    const result = await pool.query(query, params);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Barattoota argachuu hin dandeenye."
    });
  }
});

app.post("/api/students", teacherAuth, async (req, res) => {
  try {
    const {
      fullName,
      studentCode,
      phone,
      classId
    } = req.body;

    if (!fullName || !studentCode || !classId) {
      return res.status(400).json({
        error: "Maqaa, koodii fi kutaa guuti."
      });
    }

    const classCheck = await pool.query(
      `
      SELECT id
      FROM classes
      WHERE id=$1 AND teacher_id=$2
      `,
      [classId, req.user.id]
    );

    if (!classCheck.rows.length) {
      return res.status(403).json({
        error: "Kutaa kana irratti hayyama hin qabdu."
      });
    }

    const exists = await pool.query(
      `
      SELECT id
      FROM students
      WHERE LOWER(student_code)=LOWER($1)
      `,
      [studentCode.trim()]
    );

    if (exists.rows.length) {
      return res.status(400).json({
        error: "Koodiin barataa kun duraan jira."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO students
      (full_name,student_code,phone,class_id)
      VALUES ($1,$2,$3,$4)
      RETURNING *
      `,
      [
        fullName,
        studentCode.trim(),
        phone || "",
        classId
      ]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Barataa galchuu hin dandeenye."
    });
  }
});

app.delete("/api/students/:id", teacherAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      DELETE FROM students s
      USING classes c
      WHERE s.id=$1
        AND s.class_id=c.id
        AND c.teacher_id=$2
      RETURNING s.id
      `,
      [req.params.id, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Barataan hin argamne."
      });
    }

    res.json({
      message: "Barataan haqame."
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Barataa haquu hin dandeenye."
    });
  }
});

/* =========================
   ATTENDANCE
========================= */

app.get("/api/attendance", teacherAuth, async (req, res) => {
  try {
    const {
      date,
      classId
    } = req.query;

    const params = [req.user.id];
    let n = 2;

    let query = `
      SELECT
        a.*,
        s.full_name,
        s.student_code,
        c.name AS class_name
      FROM attendance a
      JOIN students s
        ON s.id=a.student_id
      JOIN classes c
        ON c.id=a.class_id
      WHERE c.teacher_id=$1
    `;

    if (date) {
      params.push(date);
      query += ` AND a.attendance_date=$${n++}`;
    }

    if (classId) {
      params.push(classId);
      query += ` AND a.class_id=$${n++}`;
    }

    query += `
      ORDER BY a.attendance_date DESC,
      s.full_name
    `;

    const result = await pool.query(query, params);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Attendance argachuu hin dandeenye."
    });
  }
});

app.post("/api/attendance", teacherAuth, async (req, res) => {
  try {
    const {
      studentId,
      classId,
      attendanceDate,
      status,
      note
    } = req.body;

    if (
      !studentId ||
      !classId ||
      !attendanceDate ||
      !status
    ) {
      return res.status(400).json({
        error: "Attendance odeeffannoo guuti."
      });
    }

    const check = await pool.query(
      `
      SELECT s.id
      FROM students s
      JOIN classes c
        ON c.id=s.class_id
      WHERE s.id=$1
        AND c.id=$2
        AND c.teacher_id=$3
      `,
      [
        studentId,
        classId,
        req.user.id
      ]
    );

    if (!check.rows.length) {
      return res.status(403).json({
        error: "Barataa kana irratti hayyama hin qabdu."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO attendance
      (student_id,class_id,attendance_date,status,note)
      VALUES ($1,$2,$3,$4,$5)
      ON CONFLICT(student_id,attendance_date)
      DO UPDATE SET
        class_id=EXCLUDED.class_id,
        status=EXCLUDED.status,
        note=EXCLUDED.note
      RETURNING *
      `,
      [
        studentId,
        classId,
        attendanceDate,
        status,
        note || ""
      ]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Attendance galchuu hin dandeenye."
    });
  }
});

/* =========================
   TEACHER REPORT
========================= */

app.get("/api/report", teacherAuth, async (req, res) => {
  try {
    const {
      from,
      to
    } = req.query;

    const params = [req.user.id];

    let query = `
      SELECT
        s.full_name,
        s.student_code,
        c.name AS class_name,
        COUNT(a.id)::int AS total_days,
        COUNT(*) FILTER
          (WHERE a.status='present')::int AS present,
        COUNT(*) FILTER
          (WHERE a.status='absent')::int AS absent,
        COUNT(*) FILTER
          (WHERE a.status='late')::int AS late
      FROM students s
      JOIN classes c
        ON c.id=s.class_id
      LEFT JOIN attendance a
        ON a.student_id=s.id
      WHERE c.teacher_id=$1
    `;

    let n = 2;

    if (from) {
      params.push(from);
      query += ` AND (a.attendance_date >= $${n} OR a.attendance_date IS NULL)`;
      n++;
    }

    if (to) {
      params.push(to);
      query += ` AND (a.attendance_date <= $${n} OR a.attendance_date IS NULL)`;
      n++;
    }

    query += `
      GROUP BY
        s.id,
        s.full_name,
        s.student_code,
        c.name
      ORDER BY s.full_name
    `;

    const result = await pool.query(query, params);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Report argachuu hin dandeenye."
    });
  }
});

/* =========================
   DASHBOARD
========================= */

app.get("/api/dashboard", teacherAuth, async (req, res) => {
  try {
    const classes = await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM classes
      WHERE teacher_id=$1
      `,
      [req.user.id]
    );

    const students = await pool.query(
      `
      SELECT COUNT(s.id)::int AS count
      FROM students s
      JOIN classes c
        ON c.id=s.class_id
      WHERE c.teacher_id=$1
      `,
      [req.user.id]
    );

    const attendance = await pool.query(
      `
      SELECT
        COUNT(*) FILTER
          (WHERE a.status='present')::int AS present,
        COUNT(*) FILTER
          (WHERE a.status='absent')::int AS absent,
        COUNT(*) FILTER
          (WHERE a.status='late')::int AS late
      FROM attendance a
      JOIN classes c
        ON c.id=a.class_id
      WHERE c.teacher_id=$1
      `,
      [req.user.id]
    );

    const results = await pool.query(
      `
      SELECT COUNT(er.id)::int AS count
      FROM exam_results er
      JOIN students s
        ON s.id=er.student_id
      JOIN classes c
        ON c.id=s.class_id
      WHERE c.teacher_id=$1
      `,
      [req.user.id]
    );

    res.json({
      classes: classes.rows[0].count,
      students: students.rows[0].count,
      present: attendance.rows[0].present || 0,
      absent: attendance.rows[0].absent || 0,
      late: attendance.rows[0].late || 0,
      results: results.rows[0].count
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Dashboard rakkoo qaba."
    });
  }
});

/* ==================================================
   BU'AA QORMAATAA - TEACHER
================================================== */

/*
  Teacher koodii barataa fayyadamuun
  bu'aa galcha.
*/

app.get("/api/results", teacherAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        er.id,
        er.student_id,
        s.full_name,
        s.student_code,
        c.name AS class_name,
        er.exam_name,
        er.subject,
        er.score,
        er.total,
        ROUND(
          CASE
            WHEN er.total > 0
            THEN (er.score / er.total) * 100
            ELSE 0
          END,
          2
        ) AS percentage,
        er.exam_date,
        er.note,
        er.created_at
      FROM exam_results er
      JOIN students s
        ON s.id=er.student_id
      JOIN classes c
        ON c.id=s.class_id
      WHERE c.teacher_id=$1
      ORDER BY er.exam_date DESC, er.id DESC
      `,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Bu'aa qormaataa argachuu hin dandeenye."
    });
  }
});

app.post("/api/results", teacherAuth, async (req, res) => {
  try {
    const {
      studentCode,
      examName,
      subject,
      score,
      total,
      examDate,
      note
    } = req.body;

    if (
      !studentCode ||
      !examName ||
      score === undefined ||
      score === null
    ) {
      return res.status(400).json({
        error: "Koodii, maqaa qormaataa fi qabxii guuti."
      });
    }

    const scoreNumber = Number(score);
    const totalNumber =
      total === undefined ||
      total === null ||
      total === ""
        ? 100
        : Number(total);

    if (
      !Number.isFinite(scoreNumber) ||
      !Number.isFinite(totalNumber) ||
      totalNumber <= 0 ||
      scoreNumber < 0 ||
      scoreNumber > totalNumber
    ) {
      return res.status(400).json({
        error: "Qabxiin sirrii miti."
      });
    }

    const student = await pool.query(
      `
      SELECT s.id
      FROM students s
      JOIN classes c
        ON c.id=s.class_id
      WHERE LOWER(s.student_code)=LOWER($1)
        AND c.teacher_id=$2
      `,
      [
        studentCode.trim(),
        req.user.id
      ]
    );

    if (!student.rows.length) {
      return res.status(404).json({
        error: "Barataan koodii kana qabu kutaa kee keessa hin jiru."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO exam_results
      (
        student_id,
        exam_name,
        subject,
        score,
        total,
        exam_date,
        note
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      RETURNING *
      `,
      [
        student.rows[0].id,
        examName.trim(),
        subject || "",
        scoreNumber,
        totalNumber,
        examDate || new Date().toISOString().slice(0, 10),
        note || ""
      ]
    );

    res.json({
      message: "Bu'aan qormaataa galmaa'e.",
      result: result.rows[0]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Bu'aa qormaataa galchuu hin dandeenye."
    });
  }
});

app.put("/api/results/:id", teacherAuth, async (req, res) => {
  try {
    const {
      examName,
      subject,
      score,
      total,
      examDate,
      note
    } = req.body;

    const scoreNumber = Number(score);
    const totalNumber = Number(total);

    if (
      !examName ||
      !Number.isFinite(scoreNumber) ||
      !Number.isFinite(totalNumber) ||
      totalNumber <= 0 ||
      scoreNumber < 0 ||
      scoreNumber > totalNumber
    ) {
      return res.status(400).json({
        error: "Odeeffannoon bu'aa sirrii miti."
      });
    }

    const result = await pool.query(
      `
      UPDATE exam_results er
      SET
        exam_name=$1,
        subject=$2,
        score=$3,
        total=$4,
        exam_date=$5,
        note=$6
      FROM students s
      JOIN classes c
        ON c.id=s.class_id
      WHERE er.id=$7
        AND er.student_id=s.id
        AND c.teacher_id=$8
      RETURNING er.*
      `,
      [
        examName.trim(),
        subject || "",
        scoreNumber,
        totalNumber,
        examDate || new Date().toISOString().slice(0, 10),
        note || "",
        req.params.id,
        req.user.id
      ]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Bu'aan qormaataa hin argamne."
      });
    }

    res.json({
      message: "Bu'aan qormaataa sirreeffame.",
      result: result.rows[0]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Bu'aa sirreessuu hin dandeenye."
    });
  }
});

app.delete("/api/results/:id", teacherAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      DELETE FROM exam_results er
      USING students s, classes c
      WHERE er.id=$1
        AND er.student_id=s.id
        AND s.class_id=c.id
        AND c.teacher_id=$2
      RETURNING er.id
      `,
      [
        req.params.id,
        req.user.id
      ]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Bu'aan qormaataa hin argamne."
      });
    }

    res.json({
      message: "Bu'aan qormaataa haqame."
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Bu'aa haquu hin dandeenye."
    });
  }
});

/* ==================================================
   BU'AA QORMAATAA - STUDENT
================================================== */

/*
  BARATAAN BU'AA KAN OFII QOFA ARGATA.
  student_id token keessaa fudhatama.
  Kanaaf koodii nama biraa beekullee
  bu'aa nama biraa argachuu hin danda'u.
*/

app.get("/api/student/results", studentAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        er.id,
        er.exam_name,
        er.subject,
        er.score,
        er.total,
        ROUND(
          CASE
            WHEN er.total > 0
            THEN (er.score / er.total) * 100
            ELSE 0
          END,
          2
        ) AS percentage,
        er.exam_date,
        er.note
      FROM exam_results er
      WHERE er.student_id=$1
      ORDER BY er.exam_date DESC, er.id DESC
      `,
      [req.student.id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Bu'aa qormaataa argachuu hin dandeenye."
    });
  }
});

/* =========================
   SPA
========================= */

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

/* =========================
   START
========================= */

async function start() {
  try {
    await initDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `Walo-OR running on port ${PORT}`
      );
    });
  } catch (err) {
    console.error(
      "Database initialization failed:",
      err
    );

    process.exit(1);
  }
}

start();

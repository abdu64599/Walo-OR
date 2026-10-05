const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET =
  process.env.JWT_SECRET || "walo-or-secret-2026";

if (!process.env.DATABASE_URL) {
  console.error("❌ DATABASE_URL hin argamne.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
  connectionTimeoutMillis: 15000,
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
      email VARCHAR(180) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(30) NOT NULL DEFAULT 'teacher',
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
      full_name VARCHAR(180) NOT NULL,
      student_code VARCHAR(80) UNIQUE,
      phone VARCHAR(50),
      class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS attendance (
      id SERIAL PRIMARY KEY,
      student_id INTEGER NOT NULL
        REFERENCES students(id) ON DELETE CASCADE,
      class_id INTEGER
        REFERENCES classes(id) ON DELETE SET NULL,
      attendance_date DATE NOT NULL,
      status VARCHAR(20) NOT NULL
        CHECK (status IN ('present','absent','late')),
      note TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(student_id, attendance_date)
    );
  `);

  console.log("✅ Database initialized.");
}

/* =========================
   HELPERS
========================= */

function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: "7d"
  });
}

function getToken(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.substring(7);
}

/* =========================
   TEACHER AUTH
========================= */

function teacherAuth(req, res, next) {
  try {
    const token = getToken(req);

    if (!token) {
      return res.status(401).json({
        error: "Login barbaachisa."
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role !== "teacher") {
      return res.status(403).json({
        error: "Hayyama barsiisaa hin qabdu."
      });
    }

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      error: "Token sirrii miti ykn yeroo isaa darbe."
    });
  }
}

/* =========================
   STUDENT AUTH
========================= */

function studentAuth(req, res, next) {
  try {
    const token = getToken(req);

    if (!token) {
      return res.status(401).json({
        error: "Student Code keessan galchaa."
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role !== "student") {
      return res.status(403).json({
        error: "Hayyama barataa hin qabdu."
      });
    }

    req.student = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      error: "Session keessan xumurameera."
    });
  }
}

/* =========================
   HEALTH
========================= */

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      app: "Walo-OR",
      database: "connected"
    });
  } catch (err) {
    res.status(500).json({
      status: "error",
      database: "disconnected",
      error: err.message
    });
  }
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
        error: "Maqaa, email fi password guutaa."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password yoo xiqqaate 6 ta'uu qaba."
      });
    }

    const exists = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email.toLowerCase().trim()]
    );

    if (exists.rows.length > 0) {
      return res.status(400).json({
        error: "Email kun duraan galmaa'eera."
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users
      (name, email, password_hash, role)
      VALUES ($1, $2, $3, 'teacher')
      RETURNING id, name, email, role
      `,
      [
        name.trim(),
        email.toLowerCase().trim(),
        passwordHash
      ]
    );

    const user = result.rows[0];

    const token = createToken({
      id: user.id,
      role: "teacher"
    });

    res.json({
      message: "Galmeen milkaa'e.",
      token,
      user
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Galmee uumuu irratti rakkoo uumame."
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

    if (!email || !password) {
      return res.status(400).json({
        error: "Email fi password galchaa."
      });
    }

    const result = await pool.query(
      `
      SELECT *
      FROM users
      WHERE email = $1
      `,
      [email.toLowerCase().trim()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Email ykn password sirrii miti."
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Email ykn password sirrii miti."
      });
    }

    const token = createToken({
      id: user.id,
      role: "teacher"
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
      error: "Login irratti rakkoo uumame."
    });
  }
});

/* =========================
   TEACHER ME
========================= */

app.get("/api/me", teacherAuth, async (req, res) => {
  const result = await pool.query(
    `
    SELECT id, name, email, role
    FROM users
    WHERE id = $1
    `,
    [req.user.id]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({
      error: "User hin argamne."
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
        ON s.class_id = c.id
      WHERE c.teacher_id = $1
      GROUP BY c.id
      ORDER BY c.id DESC
      `,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({
      error: err.message
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
        error: "Maqaa kutaa galchaa."
      });
    }

    const result = await pool.query(
      `
      INSERT INTO classes
      (name, grade, teacher_id)
      VALUES ($1, $2, $3)
      RETURNING *
      `,
      [
        name.trim(),
        grade || "",
        req.user.id
      ]
    );

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

app.delete("/api/classes/:id", teacherAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      DELETE FROM classes
      WHERE id = $1
      AND teacher_id = $2
      RETURNING id
      `,
      [
        req.params.id,
        req.user.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Kutaan hin argamne."
      });
    }

    res.json({
      message: "Kutaan haqame."
    });
  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

/* =========================
   STUDENTS
========================= */

app.get("/api/students", teacherAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        s.*,
        c.name AS class_name,
        c.grade
      FROM students s
      LEFT JOIN classes c
        ON c.id = s.class_id
      WHERE c.teacher_id = $1
         OR s.class_id IS NULL
      ORDER BY s.id DESC
      `,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({
      error: err.message
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

    if (!fullName || !studentCode) {
      return res.status(400).json({
        error: "Maqaa barataa fi Student Code dirqama."
      });
    }

    const code = studentCode.trim();

    const codeExists = await pool.query(
      `
      SELECT id
      FROM students
      WHERE LOWER(student_code) = LOWER($1)
      `,
      [code]
    );

    if (codeExists.rows.length > 0) {
      return res.status(400).json({
        error: "Student Code kun duraan fayyadameera."
      });
    }

    if (classId) {
      const classCheck = await pool.query(
        `
        SELECT id
        FROM classes
        WHERE id = $1
        AND teacher_id = $2
        `,
        [classId, req.user.id]
      );

      if (classCheck.rows.length === 0) {
        return res.status(403).json({
          error: "Kutaa kanaaf hayyama hin qabdu."
        });
      }
    }

    const result = await pool.query(
      `
      INSERT INTO students
      (full_name, student_code, phone, class_id)
      VALUES ($1, $2, $3, $4)
      RETURNING *
      `,
      [
        fullName.trim(),
        code,
        phone || "",
        classId || null
      ]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Barataa galchuu irratti rakkoo uumame."
    });
  }
});

app.delete("/api/students/:id", teacherAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      DELETE FROM students
      WHERE id = $1
      AND (
        class_id IN (
          SELECT id
          FROM classes
          WHERE teacher_id = $2
        )
        OR class_id IS NULL
      )
      RETURNING id
      `,
      [
        req.params.id,
        req.user.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "Barataan hin argamne."
      });
    }

    res.json({
      message: "Barataan haqame."
    });
  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

/* =========================
   ATTENDANCE GET
========================= */

app.get("/api/attendance", teacherAuth, async (req, res) => {
  try {
    const {
      date,
      classId
    } = req.query;

    if (!date) {
      return res.status(400).json({
        error: "Guyyaa barbaachisa."
      });
    }

    const result = await pool.query(
      `
      SELECT
        s.id,
        s.full_name,
        s.student_code,
        a.status,
        a.note
      FROM students s
      LEFT JOIN attendance a
        ON a.student_id = s.id
       AND a.attendance_date = $1
      LEFT JOIN classes c
        ON c.id = s.class_id
      WHERE c.teacher_id = $2
      ${classId ? "AND s.class_id = $3" : ""}
      ORDER BY s.full_name
      `,
      classId
        ? [date, req.user.id, classId]
        : [date, req.user.id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: err.message
    });
  }
});

/* =========================
   ATTENDANCE SAVE
========================= */

app.post("/api/attendance", teacherAuth, async (req, res) => {
  const client = await pool.connect();

  try {
    const {
      date,
      records
    } = req.body;

    if (!date || !Array.isArray(records)) {
      return res.status(400).json({
        error: "Date fi attendance records barbaachisa."
      });
    }

    await client.query("BEGIN");

    for (const record of records) {
      if (!record.studentId || !record.status) {
        continue;
      }

      if (
        !["present", "absent", "late"].includes(
          record.status
        )
      ) {
        continue;
      }

      const studentCheck = await client.query(
        `
        SELECT s.id, s.class_id
        FROM students s
        JOIN classes c
          ON c.id = s.class_id
        WHERE s.id = $1
        AND c.teacher_id = $2
        `,
        [
          record.studentId,
          req.user.id
        ]
      );

      if (studentCheck.rows.length === 0) {
        continue;
      }

      const classId =
        studentCheck.rows[0].class_id;

      await client.query(
        `
        INSERT INTO attendance
        (
          student_id,
          class_id,
          attendance_date,
          status,
          note
        )
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (student_id, attendance_date)
        DO UPDATE SET
          status = EXCLUDED.status,
          class_id = EXCLUDED.class_id,
          note = EXCLUDED.note
        `,
        [
          record.studentId,
          classId,
          date,
          record.status,
          record.note || ""
        ]
      );
    }

    await client.query("COMMIT");

    res.json({
      message: "Attendance milkaa'inaan olkaa'e."
    });
  } catch (err) {
    await client.query("ROLLBACK");

    console.error(err);

    res.status(500).json({
      error: "Attendance olkaa'uu irratti rakkoo uumame."
    });
  } finally {
    client.release();
  }
});
/* =====================================================
   EXAM CODE - TEACHER
===================================================== */

function generateExamCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  let code = "OR-";

  for (let i = 0; i < 6; i++) {
    code += chars.charAt(
      Math.floor(Math.random() * chars.length)
    );
  }

  return code;
}


/* =========================
   CREATE EXAM CODE
========================= */

app.post("/api/exams", teacherAuth, async (req, res) => {
  try {
    const {
      title,
      subject
    } = req.body;

    if (!title) {
      return res.status(400).json({
        error: "Maqaa qormaataa galchaa."
      });
    }

    let examCode;
    let exists = true;

    while (exists) {
      examCode = generateExamCode();

      const check = await pool.query(
        `
        SELECT id
        FROM exams
        WHERE exam_code = $1
        `,
        [examCode]
      );

      exists = check.rows.length > 0;
    }

    const result = await pool.query(
      `
      INSERT INTO exams
      (
        exam_code,
        title,
        subject,
        teacher_id
      )
      VALUES ($1, $2, $3, $4)
      RETURNING *
      `,
      [
        examCode,
        title.trim(),
        subject || "",
        req.user.id
      ]
    );

    res.json({
      message: "Qormaanni uumame.",
      exam: result.rows[0]
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Exam Code uumuu irratti rakkoo uumame."
    });
  }
});


/* =========================
   TEACHER EXAMS
========================= */

app.get("/api/exams", teacherAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        e.id,
        e.exam_code,
        e.title,
        e.subject,
        e.created_at,
        COUNT(er.id)::int AS result_count
      FROM exams e
      LEFT JOIN exam_results er
        ON er.exam_id = e.id
      WHERE e.teacher_id = $1
      GROUP BY e.id
      ORDER BY e.id DESC
      `,
      [req.user.id]
    );

    res.json(result.rows);

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: err.message
    });
  }
});


/* =====================================================
   TEACHER - BU'AA BARAATAA GALCHUU
===================================================== */

app.post(
  "/api/exam-results",
  teacherAuth,
  async (req, res) => {
    try {
      const {
        examCode,
        studentCode,
        score,
        total
      } = req.body;

      if (
        !examCode ||
        !studentCode ||
        score === undefined ||
        total === undefined
      ) {
        return res.status(400).json({
          error:
            "Exam Code, Student Code, Score fi Total guutaa."
        });
      }

      const examResult = await pool.query(
        `
        SELECT id
        FROM exams
        WHERE UPPER(exam_code) = UPPER($1)
        AND teacher_id = $2
        `,
        [
          examCode.trim(),
          req.user.id
        ]
      );

      if (examResult.rows.length === 0) {
        return res.status(404).json({
          error: "Exam Code hin argamne."
        });
      }

      const studentResult = await pool.query(
        `
        SELECT id
        FROM students
        WHERE LOWER(student_code) = LOWER($1)
        `,
        [studentCode.trim()]
      );

      if (studentResult.rows.length === 0) {
        return res.status(404).json({
          error: "Student Code hin argamne."
        });
      }

      const examId = examResult.rows[0].id;
      const studentId = studentResult.rows[0].id;

      const scoreNumber = Number(score);
      const totalNumber = Number(total);

      if (
        !Number.isFinite(scoreNumber) ||
        !Number.isFinite(totalNumber) ||
        totalNumber <= 0 ||
        scoreNumber < 0 ||
        scoreNumber > totalNumber
      ) {
        return res.status(400).json({
          error: "Score fi Total sirrii galchaa."
        });
      }

      const percentage =
        Math.round(
          (scoreNumber / totalNumber) * 10000
        ) / 100;

      const result = await pool.query(
        `
        INSERT INTO exam_results
        (
          exam_id,
          student_id,
          score,
          total,
          percentage
        )
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (exam_id, student_id)
        DO UPDATE SET
          score = EXCLUDED.score,
          total = EXCLUDED.total,
          percentage = EXCLUDED.percentage
        RETURNING *
        `,
        [
          examId,
          studentId,
          scoreNumber,
          totalNumber,
          percentage
        ]
      );

      res.json({
        message: "Bu'aan qormaataa galmaa'e.",
        result: result.rows[0]
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Bu'aa qormaataa galchuu irratti rakkoo uumame."
      });
    }
  }
);


/* =====================================================
   STUDENT - EXAM RESULT
   STUDENT CODE ISAATII QOFA
===================================================== */

app.post(
  "/api/student/exam-result",
  studentAuth,
  async (req, res) => {
    try {
      const {
        examCode
      } = req.body;

      if (!examCode) {
        return res.status(400).json({
          error: "Exam Code galchaa."
        });
      }

      const result = await pool.query(
        `
        SELECT
          e.exam_code,
          e.title,
          e.subject,
          er.score,
          er.total,
          er.percentage,
          er.created_at
        FROM exam_results er
        JOIN exams e
          ON e.id = er.exam_id
        WHERE er.student_id = $1
        AND UPPER(e.exam_code) = UPPER($2)
        `,
        [
          req.student.id,
          examCode.trim()
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error:
            "Qormaata kanaaf bu'aan kee hin argamne."
        });
      }

      res.json({
        message: "Bu'aan qormaataa argame.",
        result: result.rows[0]
      });

    } catch (err) {
      console.error(err);

      res.status(500).json({
        error:
          "Bu'aa qormaataa ilaalu irratti rakkoo uumame."
      });
    }
  }
);
/* =========================
   REPORT
========================= */

app.get("/api/report", teacherAuth, async (req, res) => {
  try {
    const {
      studentId,
      from,
      to
    } = req.query;

    if (!studentId || !from || !to) {
      return res.status(400).json({
        error: "Student, from fi to barbaachisa."
      });
    }

    const studentResult = await pool.query(
      `
      SELECT
        s.id,
        s.full_name,
        s.student_code,
        c.name AS class_name,
        c.grade
      FROM students s
      LEFT JOIN classes c
        ON c.id = s.class_id
      WHERE s.id = $1
      AND c.teacher_id = $2
      `,
      [
        studentId,
        req.user.id
      ]
    );

    if (studentResult.rows.length === 0) {
      return res.status(404).json({
        error: "Barataan hin argamne."
      });
    }

    const attendanceResult = await pool.query(
      `
      SELECT
        attendance_date,
        status,
        note
      FROM attendance
      WHERE student_id = $1
      AND attendance_date BETWEEN $2 AND $3
      ORDER BY attendance_date DESC
      `,
      [
        studentId,
        from,
        to
      ]
    );

    const rows = attendanceResult.rows;

    const total = rows.length;

    const present = rows.filter(
      x => x.status === "present"
    ).length;

    const absent = rows.filter(
      x => x.status === "absent"
    ).length;

    const late = rows.filter(
      x => x.status === "late"
    ).length;

    const percentage =
      total === 0
        ? 0
        : Math.round(
            ((present + late) / total) * 100
          );

    res.json({
      student: studentResult.rows[0],
      summary: {
        total,
        present,
        absent,
        late,
        percentage
      },
      attendance: rows
    });
  } catch (err) {
    res.status(500).json({
      error: err.message
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
      WHERE teacher_id = $1
      `,
      [req.user.id]
    );

    const students = await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM students s
      JOIN classes c
        ON c.id = s.class_id
      WHERE c.teacher_id = $1
      `,
      [req.user.id]
    );

    const attendance = await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM attendance a
      JOIN students s
        ON s.id = a.student_id
      JOIN classes c
        ON c.id = s.class_id
      WHERE c.teacher_id = $1
      `,
      [req.user.id]
    );

    res.json({
      classes: classes.rows[0].count,
      students: students.rows[0].count,
      attendance: attendance.rows[0].count
    });
  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

/* =====================================================
   STUDENT LOGIN — STUDENT CODE QOFA
===================================================== */

app.post("/api/student/login", async (req, res) => {
  try {
    const {
      studentCode
    } = req.body;

    if (!studentCode) {
      return res.status(400).json({
        error: "Student Code galchaa."
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
      WHERE LOWER(s.student_code) = LOWER($1)
      `,
      [studentCode.trim()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Student Code sirrii miti."
      });
    }

    const student = result.rows[0];

    const token = createToken({
      id: student.id,
      role: "student",
      classId: student.class_id
    });

    res.json({
      message: "Baga nagaan dhuftan.",
      token,
      student
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Login barataa irratti rakkoo uumame."
    });
  }
});

/* =========================
   STUDENT PROFILE
========================= */

app.get(
  "/api/student/me",
  studentAuth,
  async (req, res) => {
    try {
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
        WHERE s.id = $1
        `,
        [req.student.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Barataan hin argamne."
        });
      }

      res.json(result.rows[0]);
    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

/* =====================================================
   STUDENT ATTENDANCE — ISA QOFA
===================================================== */

app.get(
  "/api/student/attendance",
  studentAuth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          attendance_date,
          status,
          note
        FROM attendance
        WHERE student_id = $1
        ORDER BY attendance_date DESC
        `,
        [req.student.id]
      );

      const rows = result.rows;

      const total = rows.length;

      const present = rows.filter(
        x => x.status === "present"
      ).length;

      const absent = rows.filter(
        x => x.status === "absent"
      ).length;

      const late = rows.filter(
        x => x.status === "late"
      ).length;

      const percentage =
        total === 0
          ? 0
          : Math.round(
              ((present + late) / total) * 100
            );

      res.json({
        summary: {
          total,
          present,
          absent,
          late,
          percentage
        },
        attendance: rows
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: err.message
      });
    }
  }
);

/* =========================
   FRONTEND
========================= */

app.get("*", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

/* =========================
   START
========================= */

async function start() {
  try {
    await initDatabase();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `🚀 Walo-OR running on port ${PORT}`
        );
      }
    );
  } catch (err) {
    console.error(
      "❌ Database initialization failed:",
      err
    );

    process.exit(1);
  }
}

start();

const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;

const JWT_SECRET =
  process.env.JWT_SECRET || "walo-or-change-this-secret";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
  connectionTimeoutMillis: 10000,
  family: 4
});

app.set("trust proxy", 1);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

/* =========================
   HELPERS
========================= */

function generatePrivateToken() {
  return crypto.randomBytes(24).toString("hex");
}

function signTeacherToken(user) {
  return jwt.sign(
    {
      id: user.id,
      role: "teacher",
      name: user.name,
      email: user.email
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function signStudentToken(student) {
  return jwt.sign(
    {
      id: student.id,
      role: "student",
      student_code: student.student_code
    },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Login godhi."
      });
    }

    const token = header.substring(7);

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
      error: "Token sirrii miti ykn yeroo isaa darbe."
    });
  }
}

function studentAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Student login godhi."
      });
    }

    const token = header.substring(7);

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
      error: "Student token sirrii miti ykn yeroo isaa darbe."
    });
  }
}

function getBaseUrl(req) {
  if (process.env.RENDER_EXTERNAL_URL) {
    return process.env.RENDER_EXTERNAL_URL;
  }

  const protocol =
    req.headers["x-forwarded-proto"] ||
    req.protocol ||
    "http";

  return `${protocol}://${req.get("host")}`;
}

/* =========================
   DATABASE
========================= */

async function initDatabase() {
  if (!process.env.DATABASE_URL) {
    throw new Error(
      "DATABASE_URL hin argamne. Render Environment keessatti DATABASE_URL galchi."
    );
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'teacher',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS classes (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      grade TEXT,
      teacher_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS students (
      id SERIAL PRIMARY KEY,
      full_name TEXT NOT NULL,
      student_code TEXT UNIQUE NOT NULL,
      phone TEXT,
      class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
      private_token TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS attendance (
      id SERIAL PRIMARY KEY,
      student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
      class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
      attendance_date DATE NOT NULL,
      status TEXT NOT NULL CHECK (
        status IN ('present', 'absent', 'late')
      ),
      note TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(student_id, attendance_date)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS exam_results (
      id SERIAL PRIMARY KEY,
      student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
      exam_name TEXT NOT NULL,
      subject TEXT NOT NULL,
      score NUMERIC NOT NULL,
      total NUMERIC NOT NULL,
      exam_date DATE NOT NULL,
      note TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  /* Existing database migration */
  await pool.query(`
    ALTER TABLE students
    ADD COLUMN IF NOT EXISTS private_token TEXT
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    students_private_token_unique
    ON students(private_token)
    WHERE private_token IS NOT NULL
  `);

  const oldStudents = await pool.query(`
    SELECT id
    FROM students
    WHERE private_token IS NULL
  `);

  for (const student of oldStudents.rows) {
    let token = generatePrivateToken();

    let exists = await pool.query(
      `SELECT id FROM students WHERE private_token = $1`,
      [token]
    );

    while (exists.rows.length) {
      token = generatePrivateToken();

      exists = await pool.query(
        `SELECT id FROM students WHERE private_token = $1`,
        [token]
      );
    }

    await pool.query(
      `
      UPDATE students
      SET private_token = $1
      WHERE id = $2
      `,
      [token, student.id]
    );
  }

  console.log("✅ Database migrations completed.");
}

/* =========================
   HEALTH
========================= */

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    app: "Walo-OR"
  });
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: true,
      app: "Walo-OR"
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      database: false,
      error: err.message
    });
  }
});

/* =========================
   TEACHER AUTH
========================= */

app.post("/api/auth/register", async (req, res) => {
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

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password yoo xiqqaate qubee 6 qabaachuu qaba."
      });
    }

    const normalizedEmail =
      String(email).trim().toLowerCase();

    const exists = await pool.query(
      `SELECT id FROM users WHERE email = $1`,
      [normalizedEmail]
    );

    if (exists.rows.length) {
      return res.status(409).json({
        error: "Email kun duraan galmaa'eera."
      });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users
      (name, email, password_hash, role)
      VALUES ($1, $2, $3, 'teacher')
      RETURNING id, name, email, role
      `,
      [
        String(name).trim(),
        normalizedEmail,
        hash
      ]
    );

    const user = result.rows[0];

    res.status(201).json({
      message: "Account milkaa'inaan uumame.",
      token: signTeacherToken(user),
      user
    });
  } catch (err) {
    console.error("REGISTER:", err);

    res.status(500).json({
      error: "Account uumuu irratti rakkoon uumame."
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email fi password guuti."
      });
    }

    const normalizedEmail =
      String(email).trim().toLowerCase();

    const result = await pool.query(
      `
      SELECT id, name, email, password_hash, role
      FROM users
      WHERE email = $1
      `,
      [normalizedEmail]
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

    delete user.password_hash;

    res.json({
      token: signTeacherToken(user),
      user
    });
  } catch (err) {
    console.error("LOGIN:", err);

    res.status(500).json({
      error: "Login irratti rakkoon uumame."
    });
  }
});

app.get("/api/auth/me", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, name, email, role, created_at
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Teacher hin argamne."
      });
    }

    res.json({
      user: result.rows[0]
    });
  } catch (err) {
    res.status(500).json({
      error: "Odeeffannoo teacher fiduu hin dandeenye."
    });
  }
});

/* =========================
   DASHBOARD
========================= */

app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const teacherId = req.user.id;

    const classes = await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM classes
      WHERE teacher_id = $1
      `,
      [teacherId]
    );

    const students = await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM students s
      JOIN classes c ON c.id = s.class_id
      WHERE c.teacher_id = $1
      `,
      [teacherId]
    );

    const attendance = await pool.query(
      `
      SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER (
          WHERE a.status = 'present'
        )::int AS present,
        COUNT(*) FILTER (
          WHERE a.status = 'absent'
        )::int AS absent,
        COUNT(*) FILTER (
          WHERE a.status = 'late'
        )::int AS late
      FROM attendance a
      JOIN classes c ON c.id = a.class_id
      WHERE c.teacher_id = $1
      `,
      [teacherId]
    );

    const results = await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM exam_results r
      JOIN students s ON s.id = r.student_id
      JOIN classes c ON c.id = s.class_id
      WHERE c.teacher_id = $1
      `,
      [teacherId]
    );

    res.json({
      classes: classes.rows[0].count,
      students: students.rows[0].count,
      attendance: attendance.rows[0].total,
      present: attendance.rows[0].present,
      absent: attendance.rows[0].absent,
      late: attendance.rows[0].late,
      results: results.rows[0].count
    });
  } catch (err) {
    console.error("DASHBOARD:", err);

    res.status(500).json({
      error: "Dashboard fiduu hin dandeenye."
    });
  }
});

/* =========================
   CLASSES
========================= */

app.get("/api/classes", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        c.id,
        c.name,
        c.grade,
        c.created_at,
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

    res.json({
      classes: result.rows
    });
  } catch (err) {
    console.error("GET CLASSES:", err);

    res.status(500).json({
      error: "Kutaa fiduu hin dandeenye."
    });
  }
});

app.post("/api/classes", auth, async (req, res) => {
  try {
    const {
      name,
      grade
    } = req.body;

    if (!name) {
      return res.status(400).json({
        error: "Maqaa kutaa guuti."
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
        String(name).trim(),
        grade ? String(grade).trim() : null,
        req.user.id
      ]
    );

    res.status(201).json({
      message: "Kutaan uumame.",
      class: result.rows[0]
    });
  } catch (err) {
    console.error("CREATE CLASS:", err);

    res.status(500).json({
      error: "Kutaa uumuu hin dandeenye."
    });
  }
});

app.delete("/api/classes/:id", auth, async (req, res) => {
  try {
    const classId = Number(req.params.id);

    const result = await pool.query(
      `
      DELETE FROM classes
      WHERE id = $1
      AND teacher_id = $2
      RETURNING id
      `,
      [
        classId,
        req.user.id
      ]
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
    console.error("DELETE CLASS:", err);

    res.status(500).json({
      error: "Kutaa haquu hin dandeenye."
    });
  }
});

/* =========================
   STUDENTS
========================= */

app.get("/api/students", auth, async (req, res) => {
  try {
    const classId =
      req.query.class_id ||
      req.query.classId ||
      null;

    let query = `
      SELECT
        s.id,
        s.full_name,
        s.student_code,
        s.phone,
        s.class_id,
        s.private_token,
        s.created_at,
        c.name AS class_name,
        c.grade
      FROM students s
      JOIN classes c
        ON c.id = s.class_id
      WHERE c.teacher_id = $1
    `;

    const params = [req.user.id];

    if (classId) {
      query += ` AND s.class_id = $2`;
      params.push(Number(classId));
    }

    query += `
      ORDER BY s.id DESC
    `;

    const result = await pool.query(
      query,
      params
    );

    const baseUrl = getBaseUrl(req);

    const students = result.rows.map((s) => ({
      ...s,
      private_link:
        `${baseUrl}/s/${s.private_token}`
    }));

    res.json({
      students
    });
  } catch (err) {
    console.error("GET STUDENTS:", err);

    res.status(500).json({
      error: "Barattoota fiduu hin dandeenye."
    });
  }
});

app.post("/api/students", auth, async (req, res) => {
  try {
    const {
      full_name,
      student_code,
      phone,
      class_id
    } = req.body;

    if (
      !full_name ||
      !student_code ||
      !class_id
    ) {
      return res.status(400).json({
        error:
          "Maqaa barataa, student code fi kutaa guuti."
      });
    }

    const classCheck = await pool.query(
      `
      SELECT id
      FROM classes
      WHERE id = $1
      AND teacher_id = $2
      `,
      [
        Number(class_id),
        req.user.id
      ]
    );

    if (!classCheck.rows.length) {
      return res.status(403).json({
        error: "Kutaan kun kan kee miti."
      });
    }

    const code = String(student_code)
      .trim()
      .toUpperCase();

    const duplicate = await pool.query(
      `
      SELECT id
      FROM students
      WHERE student_code = $1
      `,
      [code]
    );

    if (duplicate.rows.length) {
      return res.status(409).json({
        error: "Student code kun duraan jira."
      });
    }

    const privateToken =
      generatePrivateToken();

    const result = await pool.query(
      `
      INSERT INTO students
      (
        full_name,
        student_code,
        phone,
        class_id,
        private_token
      )
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
      `,
      [
        String(full_name).trim(),
        code,
        phone
          ? String(phone).trim()
          : null,
        Number(class_id),
        privateToken
      ]
    );

    const student = result.rows[0];

    res.status(201).json({
      message: "Barataan galmaa'e.",
      student,
      private_link:
        `${getBaseUrl(req)}/s/${privateToken}`
    });
  } catch (err) {
    console.error("CREATE STUDENT:", err);

    if (err.code === "23505") {
      return res.status(409).json({
        error: "Student code kun duraan jira."
      });
    }

    res.status(500).json({
      error: "Barataa galmeessuu hin dandeenye."
    });
  }
});

app.delete("/api/students/:id", auth, async (req, res) => {
  try {
    const studentId =
      Number(req.params.id);

    const result = await pool.query(
      `
      DELETE FROM students s
      USING classes c
      WHERE s.id = $1
      AND s.class_id = c.id
      AND c.teacher_id = $2
      RETURNING s.id
      `,
      [
        studentId,
        req.user.id
      ]
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
    console.error("DELETE STUDENT:", err);

    res.status(500).json({
      error: "Barataa haquu hin dandeenye."
    });
  }
});

app.post(
  "/api/students/:id/regenerate-link",
  auth,
  async (req, res) => {
    try {
      const studentId =
        Number(req.params.id);

      const token =
        generatePrivateToken();

      const result = await pool.query(
        `
        UPDATE students s
        SET private_token = $1
        FROM classes c
        WHERE s.id = $2
        AND s.class_id = c.id
        AND c.teacher_id = $3
        RETURNING s.*
        `,
        [
          token,
          studentId,
          req.user.id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Barataan hin argamne."
        });
      }

      res.json({
        message: "Link haaromfame.",
        private_link:
          `${getBaseUrl(req)}/s/${token}`
      });
    } catch (err) {
      console.error("REGENERATE LINK:", err);

      res.status(500).json({
        error: "Link haaromsuu hin dandeenye."
      });
    }
  }
);

app.post(
  "/api/students/:id/revoke-link",
  auth,
  async (req, res) => {
    try {
      const studentId =
        Number(req.params.id);

      const result = await pool.query(
        `
        UPDATE students s
        SET private_token = NULL
        FROM classes c
        WHERE s.id = $1
        AND s.class_id = c.id
        AND c.teacher_id = $2
        RETURNING s.id
        `,
        [
          studentId,
          req.user.id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Barataan hin argamne."
        });
      }

      res.json({
        message: "Link haqame."
      });
    } catch (err) {
      console.error("REVOKE LINK:", err);

      res.status(500).json({
        error: "Link haquu hin dandeenye."
      });
    }
  }
);

/* =========================
   ATTENDANCE
========================= */

app.get("/api/attendance", auth, async (req, res) => {
  try {
    const classId =
      Number(
        req.query.class_id ||
        req.query.classId
      );

    const date =
      req.query.date;

    if (!classId || !date) {
      return res.status(400).json({
        error: "class_id fi date barbaachisa."
      });
    }

    const result = await pool.query(
      `
      SELECT
        a.id,
        a.student_id,
        a.class_id,
        a.attendance_date,
        a.status,
        a.note,
        s.full_name,
        s.student_code
      FROM attendance a
      JOIN students s
        ON s.id = a.student_id
      JOIN classes c
        ON c.id = a.class_id
      WHERE a.class_id = $1
      AND a.attendance_date = $2
      AND c.teacher_id = $3
      ORDER BY s.full_name
      `,
      [
        classId,
        date,
        req.user.id
      ]
    );

    res.json({
      attendance: result.rows
    });
  } catch (err) {
    console.error("GET ATTENDANCE:", err);

    res.status(500).json({
      error: "Attendance fiduu hin dandeenye."
    });
  }
});

app.post("/api/attendance", auth, async (req, res) => {
  const client = await pool.connect();

  try {
    const {
      student_id,
      class_id,
      attendance_date,
      status,
      note
    } = req.body;

    if (
      !student_id ||
      !class_id ||
      !attendance_date ||
      !status
    ) {
      return res.status(400).json({
        error: "Attendance odeeffannoo guutuu barbaada."
      });
    }

    if (
      ![
        "present",
        "absent",
        "late"
      ].includes(status)
    ) {
      return res.status(400).json({
        error: "Status sirrii miti."
      });
    }

    await client.query("BEGIN");

    const studentCheck = await client.query(
      `
      SELECT
        s.id,
        s.full_name,
        s.student_code
      FROM students s
      JOIN classes c
        ON c.id = s.class_id
      WHERE s.id = $1
      AND s.class_id = $2
      AND c.teacher_id = $3
      `,
      [
        Number(student_id),
        Number(class_id),
        req.user.id
      ]
    );

    if (!studentCheck.rows.length) {
      await client.query("ROLLBACK");

      return res.status(403).json({
        error:
          "Barataan ykn kutaan kun sirrii miti."
      });
    }

    const result = await client.query(
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
      ON CONFLICT
      (student_id, attendance_date)
      DO UPDATE SET
        class_id = EXCLUDED.class_id,
        status = EXCLUDED.status,
        note = EXCLUDED.note
      RETURNING *
      `,
      [
        Number(student_id),
        Number(class_id),
        attendance_date,
        status,
        note || null
      ]
    );

    await client.query("COMMIT");

    res.json({
      message:
        "Attendance milkaa'inaan galmaa'e.",
      attendance: result.rows[0]
    });
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {}

    console.error("SAVE ATTENDANCE:", err);

    res.status(500).json({
      error:
        "Attendance galmeessuu hin dandeenye."
    });
  } finally {
    client.release();
  }
});

app.get(
  "/api/attendance/report",
  auth,
  async (req, res) => {
    try {
      const classId =
        req.query.class_id ||
        req.query.classId ||
        null;

      const from =
        req.query.from || null;

      const to =
        req.query.to || null;

      const params = [
        req.user.id
      ];

      let where = `
        WHERE c.teacher_id = $1
      `;

      if (classId) {
        params.push(Number(classId));
        where += `
          AND s.class_id = $${params.length}
        `;
      }

      if (from) {
        params.push(from);
        where += `
          AND a.attendance_date >= $${params.length}
        `;
      }

      if (to) {
        params.push(to);
        where += `
          AND a.attendance_date <= $${params.length}
        `;
      }

      const result = await pool.query(
        `
        SELECT
          s.id AS student_id,
          s.full_name,
          s.student_code,
          c.id AS class_id,
          c.name AS class_name,
          COUNT(a.id)::int AS total,
          COUNT(a.id) FILTER (
            WHERE a.status = 'present'
          )::int AS present,
          COUNT(a.id) FILTER (
            WHERE a.status = 'absent'
          )::int AS absent,
          COUNT(a.id) FILTER (
            WHERE a.status = 'late'
          )::int AS late
        FROM students s
        JOIN classes c
          ON c.id = s.class_id
        LEFT JOIN attendance a
          ON a.student_id = s.id
          ${from || to ? "" : ""}
        ${where}
        GROUP BY
          s.id,
          s.full_name,
          s.student_code,
          c.id,
          c.name
        ORDER BY
          c.name,
          s.full_name
        `,
        params
      );

      res.json({
        report: result.rows
      });
    } catch (err) {
      console.error("ATTENDANCE REPORT:", err);

      res.status(500).json({
        error:
          "Attendance report fiduu hin dandeenye."
      });
    }
  }
);

/* =========================
   EXAM RESULTS - TEACHER
========================= */

app.get("/api/results", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        r.id,
        r.student_id,
        r.exam_name,
        r.subject,
        r.score,
        r.total,
        r.exam_date,
        r.note,
        s.full_name,
        s.student_code,
        c.name AS class_name
      FROM exam_results r
      JOIN students s
        ON s.id = r.student_id
      JOIN classes c
        ON c.id = s.class_id
      WHERE c.teacher_id = $1
      ORDER BY r.exam_date DESC, r.id DESC
      `,
      [req.user.id]
    );

    res.json({
      results: result.rows
    });
  } catch (err) {
    console.error("GET RESULTS:", err);

    res.status(500).json({
      error: "Bu'aa qormaataa fiduu hin dandeenye."
    });
  }
});

app.post("/api/results", auth, async (req, res) => {
  try {
    const {
      student_code,
      exam_name,
      subject,
      score,
      total,
      exam_date,
      note
    } = req.body;

    if (
      !student_code ||
      !exam_name ||
      !subject ||
      score === undefined ||
      total === undefined ||
      !exam_date
    ) {
      return res.status(400).json({
        error:
          "Student code, maqaa qormaataa, subject, score, total fi guyyaa guuti."
      });
    }

    const scoreNumber =
      Number(score);

    const totalNumber =
      Number(total);

    if (
      !Number.isFinite(scoreNumber) ||
      !Number.isFinite(totalNumber) ||
      totalNumber <= 0 ||
      scoreNumber < 0 ||
      scoreNumber > totalNumber
    ) {
      return res.status(400).json({
        error:
          "Score fi total sirrii galchi."
      });
    }

    const student = await pool.query(
      `
      SELECT
        s.id,
        s.full_name,
        s.student_code
      FROM students s
      JOIN classes c
        ON c.id = s.class_id
      WHERE s.student_code = $1
      AND c.teacher_id = $2
      `,
      [
        String(student_code)
          .trim()
          .toUpperCase(),
        req.user.id
      ]
    );

    if (!student.rows.length) {
      return res.status(404).json({
        error:
          "Student code kanaan barataan hin argamne."
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
      VALUES
      ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
      `,
      [
        student.rows[0].id,
        String(exam_name).trim(),
        String(subject).trim(),
        scoreNumber,
        totalNumber,
        exam_date,
        note || null
      ]
    );

    res.status(201).json({
      message:
        "Bu'aan qormaataa galmaa'e.",
      result: result.rows[0]
    });
  } catch (err) {
    console.error("CREATE RESULT:", err);

    res.status(500).json({
      error:
        "Bu'aa qormaataa galmeessuu hin dandeenye."
    });
  }
});

app.delete(
  "/api/results/:id",
  auth,
  async (req, res) => {
    try {
      const resultId =
        Number(req.params.id);

      const result = await pool.query(
        `
        DELETE FROM exam_results r
        USING students s, classes c
        WHERE r.id = $1
        AND r.student_id = s.id
        AND s.class_id = c.id
        AND c.teacher_id = $2
        RETURNING r.id
        `,
        [
          resultId,
          req.user.id
        ]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Bu'aan hin argamne."
        });
      }

      res.json({
        message: "Bu'aan haqame."
      });
    } catch (err) {
      console.error("DELETE RESULT:", err);

      res.status(500).json({
        error:
          "Bu'aa haquu hin dandeenye."
      });
    }
  }
);

/* =========================
   STUDENT LOGIN
========================= */

app.post("/api/student/login", async (req, res) => {
  try {
    const studentCode =
      req.body.studentCode ||
      req.body.student_code;

    if (!studentCode) {
      return res.status(400).json({
        error: "Student code galchi."
      });
    }

    const code =
      String(studentCode)
        .trim()
        .toUpperCase();

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
      JOIN classes c
        ON c.id = s.class_id
      WHERE s.student_code = $1
      `,
      [code]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error:
          "Student code sirrii miti."
      });
    }

    const student = result.rows[0];

    res.json({
      message: "Baga nagaan dhuftan.",
      token: signStudentToken(student),
      student
    });
  } catch (err) {
    console.error("STUDENT LOGIN:", err);

    res.status(500).json({
      error:
        "Student login irratti rakkoon uumame."
    });
  }
});

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
        JOIN classes c
          ON c.id = s.class_id
        WHERE s.id = $1
        `,
        [req.student.id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Barataan hin argamne."
        });
      }

      res.json({
        student: result.rows[0]
      });
    } catch (err) {
      res.status(500).json({
        error:
          "Odeeffannoo barataa fiduu hin dandeenye."
      });
    }
  }
);

app.get(
  "/api/student/attendance",
  studentAuth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          a.id,
          a.attendance_date,
          a.status,
          a.note,
          c.name AS class_name
        FROM attendance a
        JOIN classes c
          ON c.id = a.class_id
        WHERE a.student_id = $1
        ORDER BY
          a.attendance_date DESC,
          a.id DESC
        `,
        [req.student.id]
      );

      res.json({
        attendance: result.rows
      });
    } catch (err) {
      console.error(
        "STUDENT ATTENDANCE:",
        err
      );

      res.status(500).json({
        error:
          "Attendance fiduu hin dandeenye."
      });
    }
  }
);

app.get(
  "/api/student/results",
  studentAuth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          exam_name,
          subject,
          score,
          total,
          exam_date,
          note
        FROM exam_results
        WHERE student_id = $1
        ORDER BY
          exam_date DESC,
          id DESC
        `,
        [req.student.id]
      );

      res.json({
        results: result.rows
      });
    } catch (err) {
      console.error(
        "STUDENT RESULTS:",
        err
      );

      res.status(500).json({
        error:
          "Bu'aa fiduu hin dandeenye."
      });
    }
  }
);

/* =========================
   PRIVATE STUDENT LINK
========================= */

app.get(
  "/api/public/student/:token",
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          s.id,
          s.full_name,
          s.student_code,
          c.name AS class_name,
          c.grade
        FROM students s
        JOIN classes c
          ON c.id = s.class_id
        WHERE s.private_token = $1
        `,
        [req.params.token]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Student link sirrii miti."
        });
      }

      const student = result.rows[0];

      const attendance =
        await pool.query(
          `
          SELECT
            attendance_date,
            status,
            note
          FROM attendance
          WHERE student_id = $1
          ORDER BY attendance_date DESC
          `,
          [student.id]
        );

      const results =
        await pool.query(
          `
          SELECT
            exam_name,
            subject,
            score,
            total,
            exam_date,
            note
          FROM exam_results
          WHERE student_id = $1
          ORDER BY exam_date DESC
          `,
          [student.id]
        );

      res.json({
        student,
        attendance:
          attendance.rows,
        results:
          results.rows
      });
    } catch (err) {
      console.error(
        "PUBLIC STUDENT:",
        err
      );

      res.status(500).json({
        error:
          "Student data fiduu hin dandeenye."
      });
    }
  }
);

app.get("/s/:token", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "student.html"
    )
  );
});

/* =========================
   API 404
========================= */

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API route hin argamne."
  });
});

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

async function startServer() {
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

startServer();

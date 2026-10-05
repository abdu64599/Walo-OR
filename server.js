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

// ===============================
// DATABASE
// ===============================

if (!process.env.DATABASE_URL) {
  console.warn("⚠️ DATABASE_URL hin argamne.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
  family: 4,
});

// ===============================
// APP SETTINGS
// ===============================

app.set("trust proxy", true);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "public")));

// ===============================
// HELPERS
// ===============================

function generatePrivateToken() {
  return crypto.randomBytes(24).toString("hex");
}

function getBaseUrl(req) {
  const host = req.get("host");

  if (!host) {
    return "";
  }

  const forwardedProto = String(
    req.headers["x-forwarded-proto"] || ""
  )
    .split(",")[0]
    .trim();

  const protocol =
    forwardedProto ||
    req.protocol ||
    "https";

  return `${protocol}://${host}`;
}

function makePrivatePath(token) {
  if (!token) return null;

  return `/s/${encodeURIComponent(token)}`;
}

function makePrivateLink(req, token) {
  const privatePath = makePrivatePath(token);

  if (!privatePath) return null;

  return `${getBaseUrl(req)}${privatePath}`;
}

function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
    JWT_SECRET,
    {
      expiresIn: "30d",
    }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication barbaachisa.",
      });
    }

    const token = header.substring(7);

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Token sirrii miti ykn yeroo isaa darbeera.",
    });
  }
}

function isValidPrivateToken(token) {
  if (!token) return false;

  return (
    typeof token === "string" &&
    token.length >= 20 &&
    token.length <= 200
  );
}

// ===============================
// DATABASE INITIALIZATION
// ===============================

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'teacher',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS classes (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      grade TEXT,
      teacher_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS students (
      id SERIAL PRIMARY KEY,
      full_name TEXT NOT NULL,
      student_code TEXT UNIQUE NOT NULL,
      phone TEXT,
      class_id INTEGER NOT NULL
        REFERENCES classes(id)
        ON DELETE CASCADE,
      private_token TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS attendance (
      id SERIAL PRIMARY KEY,
      student_id INTEGER NOT NULL
        REFERENCES students(id)
        ON DELETE CASCADE,
      class_id INTEGER NOT NULL
        REFERENCES classes(id)
        ON DELETE CASCADE,
      attendance_date DATE NOT NULL,
      status TEXT NOT NULL
        CHECK (status IN ('present','absent','late')),
      note TEXT,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(student_id, attendance_date)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS exam_results (
      id SERIAL PRIMARY KEY,
      student_id INTEGER NOT NULL
        REFERENCES students(id)
        ON DELETE CASCADE,
      exam_name TEXT NOT NULL,
      subject TEXT,
      score NUMERIC NOT NULL,
      total NUMERIC NOT NULL,
      exam_date DATE,
      note TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // Existing database yoo duraan students qabaate
  // private_token hin qabaatin taanaan itti dabala.
  await pool.query(`
    ALTER TABLE students
    ADD COLUMN IF NOT EXISTS private_token TEXT;
  `);

  // Student duraan jiru token hin qabneef token uuma.
  const oldStudents = await pool.query(`
    SELECT id
    FROM students
    WHERE private_token IS NULL
  `);

  for (const student of oldStudents.rows) {
    let token = generatePrivateToken();

    let exists = true;

    while (exists) {
      const check = await pool.query(
        `
        SELECT id
        FROM students
        WHERE private_token = $1
        LIMIT 1
        `,
        [token]
      );

      exists = check.rows.length > 0;

      if (exists) {
        token = generatePrivateToken();
      }
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

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    students_private_token_unique
    ON students(private_token)
    WHERE private_token IS NOT NULL;
  `);

  console.log("✅ Database migrations completed.");
}

// ===============================
// HEALTH
// ===============================

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    app: "Walo-OR Attendance",
    status: "running",
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    app: "Walo-OR Attendance",
    status: "running",
  });
});

// ===============================
// REGISTER
// ===============================

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password,
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error:
          "Maqaa, email fi password guuti.",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error:
          "Password yoo xiqqaate qubee 6 qabaachuu qaba.",
      });
    }

    const normalizedEmail =
      String(email).trim().toLowerCase();

    const existing = await pool.query(
      `
      SELECT id
      FROM users
      WHERE email = $1
      `,
      [normalizedEmail]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error:
          "Email kun duraan fayyadamaa jira.",
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 10);

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
        passwordHash,
      ]
    );

    const user = result.rows[0];

    const token = signToken(user);

    res.status(201).json({
      message: "Galmeen milkaa'eera.",
      token,
      user,
    });
  } catch (error) {
    console.error(
      "REGISTER ERROR:",
      error
    );

    res.status(500).json({
      error:
        "Galmee keessatti rakkoon uumame.",
    });
  }
});

// ===============================
// LOGIN
// ===============================

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      email,
      password,
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error:
          "Email fi password guuti.",
      });
    }

    const normalizedEmail =
      String(email).trim().toLowerCase();

    const result = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        password_hash,
        role
      FROM users
      WHERE email = $1
      `,
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error:
          "Email ykn password sirrii miti.",
      });
    }

    const user = result.rows[0];

    const valid =
      await bcrypt.compare(
        password,
        user.password_hash
      );

    if (!valid) {
      return res.status(401).json({
        error:
          "Email ykn password sirrii miti.",
      });
    }

    const token = signToken(user);

    res.json({
      message: "Seensa milkaa'eera.",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(
      "LOGIN ERROR:",
      error
    );

    res.status(500).json({
      error:
        "Login keessatti rakkoon uumame.",
    });
  }
});

// ===============================
// ME
// ===============================

app.get("/api/auth/me", auth, async (req, res) => {
  try {
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
        error: "Fayyadamaan hin argamne.",
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(
      "ME ERROR:",
      error
    );

    res.status(500).json({
      error: "Rakkoo server.",
    });
  }
});

// ===============================
// DASHBOARD
// ===============================

app.get("/api/dashboard", auth, async (req, res) => {
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
      JOIN classes c
        ON c.id = a.class_id
      WHERE c.teacher_id = $1
      `,
      [req.user.id]
    );

    const results = await pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM exam_results r
      JOIN students s
        ON s.id = r.student_id
      JOIN classes c
        ON c.id = s.class_id
      WHERE c.teacher_id = $1
      `,
      [req.user.id]
    );

    res.json({
      classes: classes.rows[0].count,
      students: students.rows[0].count,
      attendance: attendance.rows[0].count,
      results: results.rows[0].count,
    });
  } catch (error) {
    console.error(
      "DASHBOARD ERROR:",
      error
    );

    res.status(500).json({
      error: "Dashboard error.",
    });
  }
});

// ===============================
// CLASSES - GET
// ===============================

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
      GROUP BY
        c.id,
        c.name,
        c.grade,
        c.created_at
      ORDER BY c.id DESC
      `,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(
      "GET CLASSES ERROR:",
      error
    );

    res.status(500).json({
      error: "Class argachuu hin dandeenye.",
    });
  }
});

// ===============================
// CREATE CLASS
// ===============================

app.post("/api/classes", auth, async (req, res) => {
  try {
    const {
      name,
      grade,
    } = req.body;

    if (!name) {
      return res.status(400).json({
        error: "Maqaa kutaa galchi.",
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
        grade
          ? String(grade).trim()
          : null,
        req.user.id,
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error(
      "CREATE CLASS ERROR:",
      error
    );

    res.status(500).json({
      error: "Class uumuu hin dandeenye.",
    });
  }
});

// ===============================
// DELETE CLASS
// ===============================

app.delete(
  "/api/classes/:id",
  auth,
  async (req, res) => {
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
          req.user.id,
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error:
            "Class hin argamne.",
        });
      }

      res.json({
        message: "Class haqameera.",
      });
    } catch (error) {
      console.error(
        "DELETE CLASS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Class haqaa'u hin dandeenye.",
      });
    }
  }
);

// ===============================
// STUDENTS - GET
// ===============================

app.get("/api/students", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
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
      ORDER BY s.id DESC
      `,
      [req.user.id]
    );

    const students = result.rows.map(
      (student) => {
        const privatePath =
          makePrivatePath(
            student.private_token
          );

        const privateLink =
          makePrivateLink(
            req,
            student.private_token
          );

        return {
          id: student.id,
          full_name: student.full_name,
          student_code:
            student.student_code,
          phone: student.phone,
          class_id:
            student.class_id,
          class_name:
            student.class_name,
          grade: student.grade,
          created_at:
            student.created_at,

          // IMPORTANT
          private_path:
            privatePath,

          private_link:
            privateLink,
        };
      }
    );

    res.json(students);
  } catch (error) {
    console.error(
      "GET STUDENTS ERROR:",
      error
    );

    res.status(500).json({
      error:
        "Barattoota argachuu hin dandeenye.",
    });
  }
});

// ===============================
// CREATE STUDENT
// ===============================

app.post(
  "/api/students",
  auth,
  async (req, res) => {
    try {
      const {
        full_name,
        student_code,
        phone,
        class_id,
      } = req.body;

      if (
        !full_name ||
        !student_code ||
        !class_id
      ) {
        return res.status(400).json({
          error:
            "Maqaa, student code fi class guuti.",
        });
      }

      // Class teacher kanaaf akka ta'e mirkaneessi
      const classCheck =
        await pool.query(
          `
          SELECT id
          FROM classes
          WHERE id = $1
          AND teacher_id = $2
          `,
          [
            class_id,
            req.user.id,
          ]
        );

      if (
        classCheck.rows.length === 0
      ) {
        return res.status(403).json({
          error:
            "Class kana irratti hayyama hin qabdu.",
        });
      }

      // Student code duplicate
      const codeCheck =
        await pool.query(
          `
          SELECT id
          FROM students
          WHERE student_code = $1
          `,
          [
            String(
              student_code
            ).trim(),
          ]
        );

      if (
        codeCheck.rows.length > 0
      ) {
        return res.status(409).json({
          error:
            "Student code kun duraan jira.",
        });
      }

      const privateToken =
        generatePrivateToken();

      const result =
        await pool.query(
          `
          INSERT INTO students
          (
            full_name,
            student_code,
            phone,
            class_id,
            private_token
          )
          VALUES
          ($1, $2, $3, $4, $5)
          RETURNING *
          `,
          [
            String(
              full_name
            ).trim(),

            String(
              student_code
            ).trim(),

            phone
              ? String(phone).trim()
              : null,

            class_id,

            privateToken,
          ]
        );

      const student =
        result.rows[0];

      const privatePath =
        makePrivatePath(
          student.private_token
        );

      const privateLink =
        makePrivateLink(
          req,
          student.private_token
        );

      res.status(201).json({
        id: student.id,
        full_name:
          student.full_name,
        student_code:
          student.student_code,
        phone: student.phone,
        class_id:
          student.class_id,

        // IMPORTANT
        private_path:
          privatePath,

        private_link:
          privateLink,

        student: {
          id: student.id,
          full_name:
            student.full_name,
          student_code:
            student.student_code,
          phone: student.phone,
          class_id:
            student.class_id,
          private_path:
            privatePath,
          private_link:
            privateLink,
        },
      });
    } catch (error) {
      console.error(
        "CREATE STUDENT ERROR:",
        error
      );

      if (
        error.code === "23505"
      ) {
        return res.status(409).json({
          error:
            "Student code kun duraan jira.",
        });
      }

      res.status(500).json({
        error:
          "Barataa uumuu hin dandeenye.",
      });
    }
  }
);

// ===============================
// REGENERATE PRIVATE LINK
// ===============================

app.post(
  "/api/students/:id/regenerate-link",
  auth,
  async (req, res) => {
    try {
      const newToken =
        generatePrivateToken();

      const result =
        await pool.query(
          `
          UPDATE students s
          SET private_token = $1
          FROM classes c
          WHERE s.id = $2
          AND s.class_id = c.id
          AND c.teacher_id = $3
          RETURNING
            s.id,
            s.full_name,
            s.student_code,
            s.private_token
          `,
          [
            newToken,
            req.params.id,
            req.user.id,
          ]
        );

      if (
        result.rows.length === 0
      ) {
        return res.status(404).json({
          error:
            "Barataan hin argamne.",
        });
      }

      const student =
        result.rows[0];

      const privatePath =
        makePrivatePath(
          student.private_token
        );

      const privateLink =
        makePrivateLink(
          req,
          student.private_token
        );

      res.json({
        message:
          "Private link haaromfameera.",

        id: student.id,

        full_name:
          student.full_name,

        student_code:
          student.student_code,

        private_path:
          privatePath,

        private_link:
          privateLink,
      });
    } catch (error) {
      console.error(
        "REGENERATE LINK ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Link haaromsuu hin dandeenye.",
      });
    }
  }
);

// ===============================
// REVOKE PRIVATE LINK
// ===============================

app.post(
  "/api/students/:id/revoke-link",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
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
            req.params.id,
            req.user.id,
          ]
        );

      if (
        result.rows.length === 0
      ) {
        return res.status(404).json({
          error:
            "Barataan hin argamne.",
        });
      }

      res.json({
        message:
          "Private link haqameera.",
      });
    } catch (error) {
      console.error(
        "REVOKE LINK ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Link haqaa'uu hin dandeenye.",
      });
    }
  }
);

// ===============================
// DELETE STUDENT
// ===============================

app.delete(
  "/api/students/:id",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          DELETE FROM students s
          USING classes c
          WHERE s.id = $1
          AND s.class_id = c.id
          AND c.teacher_id = $2
          RETURNING s.id
          `,
          [
            req.params.id,
            req.user.id,
          ]
        );

      if (
        result.rows.length === 0
      ) {
        return res.status(404).json({
          error:
            "Barataan hin argamne.",
        });
      }

      res.json({
        message:
          "Barataan haqameera.",
      });
    } catch (error) {
      console.error(
        "DELETE STUDENT ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Barataa haqaa'uu hin dandeenye.",
      });
    }
  }
);

// ===============================
// ATTENDANCE - GET
// ===============================

app.get(
  "/api/attendance",
  auth,
  async (req, res) => {
    try {
      const {
        class_id,
        date,
      } = req.query;

      if (!class_id || !date) {
        return res.status(400).json({
          error:
            "class_id fi date barbaachisa.",
        });
      }

      const result =
        await pool.query(
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
          ORDER BY s.full_name ASC
          `,
          [
            class_id,
            date,
            req.user.id,
          ]
        );

      res.json(result.rows);
    } catch (error) {
      console.error(
        "GET ATTENDANCE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Attendance argachuu hin dandeenye.",
      });
    }
  }
);

// ===============================
// ATTENDANCE - SAVE
// ===============================

app.post(
  "/api/attendance",
  auth,
  async (req, res) => {
    try {
      const {
        student_id,
        class_id,
        attendance_date,
        status,
        note,
      } = req.body;

      if (
        !student_id ||
        !class_id ||
        !attendance_date ||
        !status
      ) {
        return res.status(400).json({
          error:
            "Attendance odeeffannoo guutuu barbaada.",
        });
      }

      if (
        ![
          "present",
          "absent",
          "late",
        ].includes(status)
      ) {
        return res.status(400).json({
          error:
            "Status sirrii miti.",
        });
      }

      const owner =
        await pool.query(
          `
          SELECT
            s.id
          FROM students s
          JOIN classes c
            ON c.id = s.class_id
          WHERE s.id = $1
          AND s.class_id = $2
          AND c.teacher_id = $3
          `,
          [
            student_id,
            class_id,
            req.user.id,
          ]
        );

      if (
        owner.rows.length === 0
      ) {
        return res.status(403).json({
          error:
            "Attendance kanaaf hayyama hin qabdu.",
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO attendance
          (
            student_id,
            class_id,
            attendance_date,
            status,
            note
          )
          VALUES
          ($1, $2, $3, $4, $5)
          ON CONFLICT
          (student_id, attendance_date)
          DO UPDATE SET
            class_id = EXCLUDED.class_id,
            status = EXCLUDED.status,
            note = EXCLUDED.note
          RETURNING *
          `,
          [
            student_id,
            class_id,
            attendance_date,
            status,
            note || null,
          ]
        );

      res.json(result.rows[0]);
    } catch (error) {
      console.error(
        "SAVE ATTENDANCE ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Attendance galmeessuu hin dandeenye.",
      });
    }
  }
);

// ===============================
// ATTENDANCE REPORT
// ===============================

app.get(
  "/api/attendance/report",
  auth,
  async (req, res) => {
    try {
      const {
        class_id,
        from,
        to,
      } = req.query;

      let query = `
        SELECT
          s.id AS student_id,
          s.full_name,
          s.student_code,
          COUNT(a.id)::int AS total,
          COUNT(
            CASE
              WHEN a.status = 'present'
              THEN 1
            END
          )::int AS present,
          COUNT(
            CASE
              WHEN a.status = 'absent'
              THEN 1
            END
          )::int AS absent,
          COUNT(
            CASE
              WHEN a.status = 'late'
              THEN 1
            END
          )::int AS late
        FROM students s
        JOIN classes c
          ON c.id = s.class_id
        LEFT JOIN attendance a
          ON a.student_id = s.id
      `;

      const params = [
        req.user.id,
      ];

      query += `
        WHERE c.teacher_id = $1
      `;

      if (class_id) {
        params.push(class_id);

        query += `
          AND s.class_id = $${params.length}
        `;
      }

      if (from) {
        params.push(from);

        query += `
          AND (
            a.attendance_date IS NULL
            OR a.attendance_date >= $${params.length}
          )
        `;
      }

      if (to) {
        params.push(to);

        query += `
          AND (
            a.attendance_date IS NULL
            OR a.attendance_date <= $${params.length}
          )
        `;
      }

      query += `
        GROUP BY
          s.id,
          s.full_name,
          s.student_code
        ORDER BY
          s.full_name ASC
      `;

      const result =
        await pool.query(
          query,
          params
        );

      res.json(result.rows);
    } catch (error) {
      console.error(
        "REPORT ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Report uumuu hin dandeenye.",
      });
    }
  }
);

// ===============================
// RESULTS - GET
// ===============================

app.get(
  "/api/results",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
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
          ORDER BY
            r.id DESC
          `,
          [req.user.id]
        );

      const rows =
        result.rows.map(
          (r) => ({
            ...r,
            percentage:
              Number(r.total) > 0
                ? (
                    Number(r.score) /
                    Number(r.total)
                  ) * 100
                : 0,
          })
        );

      res.json(rows);
    } catch (error) {
      console.error(
        "GET RESULTS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Bu'aa argachuu hin dandeenye.",
      });
    }
  }
);

// ===============================
// RESULTS - CREATE
// ===============================

app.post(
  "/api/results",
  auth,
  async (req, res) => {
    try {
      const {
        student_code,
        exam_name,
        subject,
        score,
        total,
        exam_date,
        note,
      } = req.body;

      if (
        !student_code ||
        !exam_name ||
        score === undefined ||
        total === undefined
      ) {
        return res.status(400).json({
          error:
            "Student code, maqaa qormaataa, score fi total guuti.",
        });
      }

      const student =
        await pool.query(
          `
          SELECT
            s.id
          FROM students s
          JOIN classes c
            ON c.id = s.class_id
          WHERE s.student_code = $1
          AND c.teacher_id = $2
          `,
          [
            String(
              student_code
            ).trim(),
            req.user.id,
          ]
        );

      if (
        student.rows.length === 0
      ) {
        return res.status(404).json({
          error:
            "Student code hin argamne.",
        });
      }

      const numericScore =
        Number(score);

      const numericTotal =
        Number(total);

      if (
        Number.isNaN(
          numericScore
        ) ||
        Number.isNaN(
          numericTotal
        ) ||
        numericTotal <= 0 ||
        numericScore < 0 ||
        numericScore > numericTotal
      ) {
        return res.status(400).json({
          error:
            "Score fi total sirrii galchi.",
        });
      }

      const result =
        await pool.query(
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

            String(
              exam_name
            ).trim(),

            subject
              ? String(subject).trim()
              : null,

            numericScore,
            numericTotal,

            exam_date || null,

            note
              ? String(note).trim()
              : null,
          ]
        );

      const row =
        result.rows[0];

      res.status(201).json({
        ...row,
        percentage:
          numericTotal > 0
            ? (
                numericScore /
                numericTotal
              ) * 100
            : 0,
      });
    } catch (error) {
      console.error(
        "CREATE RESULT ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Bu'aa galmeessuu hin dandeenye.",
      });
    }
  }
);

// ===============================
// RESULTS - DELETE
// ===============================

app.delete(
  "/api/results/:id",
  auth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
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
            req.params.id,
            req.user.id,
          ]
        );

      if (
        result.rows.length === 0
      ) {
        return res.status(404).json({
          error:
            "Bu'aan hin argamne.",
        });
      }

      res.json({
        message:
          "Bu'aan haqameera.",
      });
    } catch (error) {
      console.error(
        "DELETE RESULT ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Bu'aa haqaa'uu hin dandeenye.",
      });
    }
  }
);

// =====================================================
// PUBLIC STUDENT API
// =====================================================

app.get(
  "/api/public/student/:token",
  async (req, res) => {
    try {
      const token =
        decodeURIComponent(
          String(req.params.token || "")
        );

      if (
        !isValidPrivateToken(token)
      ) {
        return res.status(400).json({
          error:
            "Private link sirrii miti.",
        });
      }

      const studentResult =
        await pool.query(
          `
          SELECT
            s.id,
            s.full_name,
            s.student_code,
            s.phone,
            c.id AS class_id,
            c.name AS class_name,
            c.grade
          FROM students s
          JOIN classes c
            ON c.id = s.class_id
          WHERE s.private_token = $1
          LIMIT 1
          `,
          [token]
        );

      if (
        studentResult.rows.length === 0
      ) {
        return res.status(404).json({
          error:
            "Private link kun hojii irra hin jiru.",
        });
      }

      const student =
        studentResult.rows[0];

      const attendanceResult =
        await pool.query(
          `
          SELECT
            id,
            attendance_date,
            status,
            note
          FROM attendance
          WHERE student_id = $1
          ORDER BY
            attendance_date DESC,
            id DESC
          `,
          [student.id]
        );

      const resultsResult =
        await pool.query(
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
            exam_date DESC NULLS LAST,
            id DESC
          `,
          [student.id]
        );

      const attendance =
        attendanceResult.rows;

      const results =
        resultsResult.rows.map(
          (r) => {
            const score =
              Number(r.score);

            const total =
              Number(r.total);

            return {
              ...r,
              percentage:
                total > 0
                  ? (score / total) * 100
                  : 0,
            };
          }
        );

      const present =
        attendance.filter(
          (a) =>
            a.status === "present"
        ).length;

      const absent =
        attendance.filter(
          (a) =>
            a.status === "absent"
        ).length;

      const late =
        attendance.filter(
          (a) =>
            a.status === "late"
        ).length;

      const totalAttendance =
        attendance.length;

      const attendancePercentage =
        totalAttendance > 0
          ? (
              present /
              totalAttendance
            ) * 100
          : 0;

      res.set(
        "Cache-Control",
        "no-store"
      );

      res.json({
        student: {
          id: student.id,
          full_name:
            student.full_name,
          student_code:
            student.student_code,
          phone: student.phone,
          class_id:
            student.class_id,
          class_name:
            student.class_name,
          grade: student.grade,
        },

        attendance: {
          records: attendance,

          summary: {
            total:
              totalAttendance,
            present,
            absent,
            late,
            percentage:
              attendancePercentage,
          },
        },

        results,

        generated_at:
          new Date().toISOString(),
      });
    } catch (error) {
      console.error(
        "PUBLIC STUDENT ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Odeeffannoo barataa argachuu irratti rakkoon uumame.",
      });
    }
  }
);

// =====================================================
// PRIVATE STUDENT PAGE
// =====================================================

app.get(
  "/s/:token",
  async (req, res) => {
    try {
      res.set(
        "Cache-Control",
        "no-store"
      );

      res.sendFile(
        path.join(
          __dirname,
          "public",
          "student.html"
        )
      );
    } catch (error) {
      console.error(
        "STUDENT PAGE ERROR:",
        error
      );

      res.status(500).send(
        "Fuulli barataa banamuu hin dandeenye."
      );
    }
  }
);

// ===============================
// API NOT FOUND
// ===============================

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      error:
        "API endpoint hin argamne.",
    });
  }
);

// ===============================
// FRONTEND
// ===============================

app.get("*", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

// ===============================
// START SERVER
// ===============================

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
  } catch (error) {
    console.error(
      "❌ Database initialization failed:",
      error
    );

    process.exit(1);
  }
}

startServer();

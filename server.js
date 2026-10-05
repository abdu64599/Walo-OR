const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
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
  family: 4
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "public")));

/* =========================================================
   DATABASE
========================================================= */

async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(150) NOT NULL,
        email VARCHAR(200) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(30) NOT NULL DEFAULT 'teacher',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS classes (
        id SERIAL PRIMARY KEY,
        name VARCHAR(150) NOT NULL,
        grade VARCHAR(100),
        teacher_id INTEGER NOT NULL
          REFERENCES users(id)
          ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS students (
        id SERIAL PRIMARY KEY,
        full_name VARCHAR(200) NOT NULL,
        student_code VARCHAR(100) UNIQUE NOT NULL,
        phone VARCHAR(50),
        class_id INTEGER
          REFERENCES classes(id)
          ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS attendance (
        id SERIAL PRIMARY KEY,
        student_id INTEGER NOT NULL
          REFERENCES students(id)
          ON DELETE CASCADE,
        class_id INTEGER
          REFERENCES classes(id)
          ON DELETE CASCADE,
        attendance_date DATE NOT NULL,
        status VARCHAR(30) NOT NULL
          CHECK (status IN ('present', 'absent', 'late')),
        note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

        UNIQUE(student_id, attendance_date)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS exam_results (
        id SERIAL PRIMARY KEY,

        student_id INTEGER NOT NULL
          REFERENCES students(id)
          ON DELETE CASCADE,

        exam_name VARCHAR(200) NOT NULL,

        subject VARCHAR(150),

        score NUMERIC(10,2)
          NOT NULL DEFAULT 0,

        total NUMERIC(10,2)
          NOT NULL DEFAULT 100,

        exam_date DATE
          DEFAULT CURRENT_DATE,

        note TEXT,

        created_at TIMESTAMP
          DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("Database migrations completed.");
  } catch (error) {
    console.error("Database initialization failed:", error);
  }
}

/* =========================================================
   DATABASE TEST
========================================================= */

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      message: "Walo-OR server is running.",
      database: "connected"
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      message: "Database connection failed.",
      error: error.message
    });
  }
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: "connected"
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      database: "error",
      error: error.message
    });
  }
});

/* =========================================================
   TOKEN
========================================================= */

function makeToken(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "30d"
    }
  );
}

/* =========================================================
   TEACHER AUTH
========================================================= */

function teacherAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || "";

    if (!auth.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Login godhi."
      });
    }

    const token = auth.substring(7);

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    if (decoded.role !== "teacher") {
      return res.status(403).json({
        error: "Teacher qofaaf."
      });
    }

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Token sirrii miti ykn yeroon isaa darbeera."
    });
  }
}

/* =========================================================
   STUDENT AUTH
========================================================= */

function studentAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || "";

    if (!auth.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Student login godhi."
      });
    }

    const token = auth.substring(7);

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    if (decoded.role !== "student") {
      return res.status(403).json({
        error: "Barataa qofaaf."
      });
    }

    req.student = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Student token sirrii miti."
    });
  }
}

/* =========================================================
   TEACHER REGISTER
========================================================= */

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

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password yoo xiqqaate qubee 6 qabaachuu qaba."
      });
    }

    const existing = await pool.query(
      `
      SELECT id
      FROM users
      WHERE LOWER(email) = LOWER($1)
      `,
      [email]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({
        error: "Email kun duraan fayyadameera."
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 10);

    const result = await pool.query(
      `
      INSERT INTO users
      (
        name,
        email,
        password_hash,
        role
      )
      VALUES ($1, $2, $3, 'teacher')
      RETURNING id, name, email, role
      `,
      [
        name,
        email,
        passwordHash
      ]
    );

    const user = result.rows[0];

    const token = makeToken(user);

    res.json({
      message: "Teacher account uumameera.",
      token,
      user
    });
  } catch (error) {
    console.error("Register error:", error);

    res.status(500).json({
      error: "Account uumuu hin dandeenye."
    });
  }
});

/* =========================================================
   TEACHER LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {
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

    const result = await pool.query(
      `
      SELECT *
      FROM users
      WHERE LOWER(email) = LOWER($1)
      AND role = 'teacher'
      `,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Email ykn password sirrii miti."
      });
    }

    const user = result.rows[0];

    const passwordOk =
      await bcrypt.compare(
        password,
        user.password_hash
      );

    if (!passwordOk) {
      return res.status(401).json({
        error: "Email ykn password sirrii miti."
      });
    }

    const token = makeToken(user);

    res.json({
      message: "Login milkaa'e.",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Login irratti rakkoon uumame."
    });
  }
});

/* =========================================================
   STUDENT LOGIN
========================================================= */

app.post("/api/student/login", async (req, res) => {
  try {
    const {
      studentCode
    } = req.body;

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
      WHERE LOWER(s.student_code) = LOWER($1)
      `,
      [studentCode.trim()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Koodiin barataa hin argamne."
      });
    }

    const student = result.rows[0];

    const token = jwt.sign(
      {
        id: student.id,
        role: "student",
        classId: student.class_id
      },
      JWT_SECRET,
      {
        expiresIn: "30d"
      }
    );

    res.json({
      message: "Baga nagaan dhuftan.",
      token,
      student
    });
  } catch (error) {
    console.error("Student login error:", error);

    res.status(500).json({
      error: "Student login hin milkoofne."
    });
  }
});

/* =========================================================
   CURRENT TEACHER
========================================================= */

app.get("/api/me", teacherAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        role,
        created_at
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
  } catch (error) {
    res.status(500).json({
      error: "Profile argachuu hin dandeenye."
    });
  }
});

/* =========================================================
   CURRENT STUDENT
========================================================= */

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
    } catch (error) {
      res.status(500).json({
        error: "Student profile argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   CLASSES - GET
========================================================= */

app.get(
  "/api/classes",
  teacherAuth,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          c.id,
          c.name,
          c.grade,
          c.teacher_id,
          c.created_at,

          (
            SELECT COUNT(*)
            FROM students s
            WHERE s.class_id = c.id
          ) AS student_count

        FROM classes c
        WHERE c.teacher_id = $1
        ORDER BY c.id DESC
        `,
        [req.user.id]
      );

      res.json(result.rows);
    } catch (error) {
      console.error("Get classes error:", error);

      res.status(500).json({
        error: "Kutaa argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   CLASS CREATE
========================================================= */

app.post(
  "/api/classes",
  teacherAuth,
  async (req, res) => {
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
        (
          name,
          grade,
          teacher_id
        )
        VALUES ($1, $2, $3)
        RETURNING *
        `,
        [
          name.trim(),
          grade || "",
          req.user.id
        ]
      );

      res.json({
        message: "Kutaan uumameera.",
        class: result.rows[0]
      });
    } catch (error) {
      console.error("Create class error:", error);

      res.status(500).json({
        error: "Kutaa uumuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   CLASS DELETE
========================================================= */

app.delete(
  "/api/classes/:id",
  teacherAuth,
  async (req, res) => {
    try {
      const classId = Number(req.params.id);

      const check = await pool.query(
        `
        SELECT id
        FROM classes
        WHERE id = $1
        AND teacher_id = $2
        `,
        [
          classId,
          req.user.id
        ]
      );

      if (check.rows.length === 0) {
        return res.status(404).json({
          error: "Kutaan hin argamne."
        });
      }

      await pool.query(
        `
        DELETE FROM classes
        WHERE id = $1
        `,
        [classId]
      );

      res.json({
        message: "Kutaan haqameera."
      });
    } catch (error) {
      console.error("Delete class error:", error);

      res.status(500).json({
        error: "Kutaa haquu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   STUDENTS - GET
========================================================= */

app.get(
  "/api/students",
  teacherAuth,
  async (req, res) => {
    try {
      const {
        classId
      } = req.query;

      let query = `
        SELECT
          s.id,
          s.full_name,
          s.student_code,
          s.phone,
          s.class_id,
          c.name AS class_name,
          c.grade,
          s.created_at

        FROM students s

        LEFT JOIN classes c
          ON c.id = s.class_id

        WHERE
          c.teacher_id = $1
      `;

      const values = [
        req.user.id
      ];

      if (classId) {
        query += `
          AND s.class_id = $2
        `;

        values.push(Number(classId));
      }

      query += `
        ORDER BY s.id DESC
      `;

      const result =
        await pool.query(
          query,
          values
        );

      res.json(result.rows);
    } catch (error) {
      console.error("Get students error:", error);

      res.status(500).json({
        error: "Barattoota argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   STUDENT CREATE
========================================================= */

app.post(
  "/api/students",
  teacherAuth,
  async (req, res) => {
    try {
      const {
        fullName,
        studentCode,
        phone,
        classId
      } = req.body;

      if (!fullName || !studentCode) {
        return res.status(400).json({
          error:
            "Maqaa barataa fi koodii barataa guuti."
        });
      }

      if (!classId) {
        return res.status(400).json({
          error: "Kutaa filadhu."
        });
      }

      const classCheck =
        await pool.query(
          `
          SELECT id
          FROM classes
          WHERE id = $1
          AND teacher_id = $2
          `,
          [
            Number(classId),
            req.user.id
          ]
        );

      if (classCheck.rows.length === 0) {
        return res.status(403).json({
          error: "Kutaa kana irratti hayyama hin qabdu."
        });
      }

      const existing =
        await pool.query(
          `
          SELECT id
          FROM students
          WHERE LOWER(student_code) = LOWER($1)
          `,
          [studentCode.trim()]
        );

      if (existing.rows.length > 0) {
        return res.status(400).json({
          error: "Koodiin barataa kun duraan jira."
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO students
          (
            full_name,
            student_code,
            phone,
            class_id
          )
          VALUES ($1, $2, $3, $4)
          RETURNING *
          `,
          [
            fullName.trim(),
            studentCode.trim(),
            phone || "",
            Number(classId)
          ]
        );

      res.json({
        message: "Barataan galmaa'eera.",
        student: result.rows[0]
      });
    } catch (error) {
      console.error("Create student error:", error);

      res.status(500).json({
        error: "Barataa galchuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   STUDENT DELETE
========================================================= */

app.delete(
  "/api/students/:id",
  teacherAuth,
  async (req, res) => {
    try {
      const studentId =
        Number(req.params.id);

      const check =
        await pool.query(
          `
          SELECT s.id
          FROM students s
          JOIN classes c
            ON c.id = s.class_id
          WHERE
            s.id = $1
            AND c.teacher_id = $2
          `,
          [
            studentId,
            req.user.id
          ]
        );

      if (check.rows.length === 0) {
        return res.status(404).json({
          error: "Barataan hin argamne."
        });
      }

      await pool.query(
        `
        DELETE FROM students
        WHERE id = $1
        `,
        [studentId]
      );

      res.json({
        message: "Barataan haqameera."
      });
    } catch (error) {
      console.error("Delete student error:", error);

      res.status(500).json({
        error: "Barataa haquu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   ATTENDANCE - GET
========================================================= */

app.get(
  "/api/attendance",
  teacherAuth,
  async (req, res) => {
    try {
      const {
        classId,
        date
      } = req.query;

      if (!classId || !date) {
        return res.status(400).json({
          error: "classId fi date barbaachisa."
        });
      }

      const check =
        await pool.query(
          `
          SELECT id
          FROM classes
          WHERE id = $1
          AND teacher_id = $2
          `,
          [
            Number(classId),
            req.user.id
          ]
        );

      if (check.rows.length === 0) {
        return res.status(403).json({
          error: "Kutaa kana irratti hayyama hin qabdu."
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            s.id,
            s.full_name,
            s.student_code,

            a.attendance_date,
            a.status,
            a.note

          FROM students s

          LEFT JOIN attendance a
            ON a.student_id = s.id
            AND a.attendance_date = $2

          WHERE s.class_id = $1

          ORDER BY s.full_name ASC
          `,
          [
            Number(classId),
            date
          ]
        );

      res.json(result.rows);
    } catch (error) {
      console.error("Get attendance error:", error);

      res.status(500).json({
        error: "Attendance argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   ATTENDANCE - SAVE
========================================================= */

app.post(
  "/api/attendance",
  teacherAuth,
  async (req, res) => {
    try {
      const {
        studentId,
        classId,
        date,
        status,
        note
      } = req.body;

      if (
        !studentId ||
        !classId ||
        !date ||
        !status
      ) {
        return res.status(400).json({
          error: "Odeeffannoo attendance guuti."
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

      const classCheck =
        await pool.query(
          `
          SELECT id
          FROM classes
          WHERE id = $1
          AND teacher_id = $2
          `,
          [
            Number(classId),
            req.user.id
          ]
        );

      if (classCheck.rows.length === 0) {
        return res.status(403).json({
          error: "Kutaa kana irratti hayyama hin qabdu."
        });
      }

      const studentCheck =
        await pool.query(
          `
          SELECT id
          FROM students
          WHERE id = $1
          AND class_id = $2
          `,
          [
            Number(studentId),
            Number(classId)
          ]
        );

      if (studentCheck.rows.length === 0) {
        return res.status(400).json({
          error: "Barataan kutaa kana keessa hin jiru."
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
          VALUES ($1, $2, $3, $4, $5)

          ON CONFLICT
          (
            student_id,
            attendance_date
          )

          DO UPDATE SET
            class_id = EXCLUDED.class_id,
            status = EXCLUDED.status,
            note = EXCLUDED.note

          RETURNING *
          `,
          [
            Number(studentId),
            Number(classId),
            date,
            status,
            note || ""
          ]
        );

      res.json({
        message: "Attendance galmaa'eera.",
        attendance: result.rows[0]
      });
    } catch (error) {
      console.error("Save attendance error:", error);

      res.status(500).json({
        error: "Attendance galchuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   STUDENT ATTENDANCE
   IMPORTANT: THIS MUST BE BEFORE SPA FALLBACK
========================================================= */

app.get(
  "/api/student/attendance",
  studentAuth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            a.id,
            a.attendance_date,
            a.status,
            a.note,
            c.name AS class_name

          FROM attendance a

          LEFT JOIN classes c
            ON c.id = a.class_id

          WHERE a.student_id = $1

          ORDER BY
            a.attendance_date DESC,
            a.id DESC
          `,
          [req.student.id]
        );

      return res.json(result.rows);
    } catch (error) {
      console.error(
        "Student attendance error:",
        error
      );

      return res.status(500).json({
        error: "Attendance argachuu hin dandeenye.",
        data: []
      });
    }
  }
);

/* =========================================================
   STUDENT ATTENDANCE SUMMARY
========================================================= */

app.get(
  "/api/student/attendance-summary",
  studentAuth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            COUNT(*)::int AS total,

            COUNT(*) FILTER (
              WHERE status = 'present'
            )::int AS present,

            COUNT(*) FILTER (
              WHERE status = 'absent'
            )::int AS absent,

            COUNT(*) FILTER (
              WHERE status = 'late'
            )::int AS late

          FROM attendance

          WHERE student_id = $1
          `,
          [req.student.id]
        );

      const row = result.rows[0];

      res.json({
        total: Number(row.total || 0),
        present: Number(row.present || 0),
        absent: Number(row.absent || 0),
        late: Number(row.late || 0)
      });
    } catch (error) {
      console.error(
        "Student attendance summary error:",
        error
      );

      res.status(500).json({
        error: "Summary argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   TEACHER REPORT
========================================================= */

app.get(
  "/api/report",
  teacherAuth,
  async (req, res) => {
    try {
      const {
        classId
      } = req.query;

      let query = `
        SELECT
          s.id,
          s.full_name,
          s.student_code,

          COUNT(a.id)::int AS total_days,

          COUNT(a.id) FILTER (
            WHERE a.status = 'present'
          )::int AS present_days,

          COUNT(a.id) FILTER (
            WHERE a.status = 'absent'
          )::int AS absent_days,

          COUNT(a.id) FILTER (
            WHERE a.status = 'late'
          )::int AS late_days

        FROM students s

        JOIN classes c
          ON c.id = s.class_id

        LEFT JOIN attendance a
          ON a.student_id = s.id

        WHERE c.teacher_id = $1
      `;

      const values = [
        req.user.id
      ];

      if (classId) {
        query += `
          AND s.class_id = $2
        `;

        values.push(
          Number(classId)
        );
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
          values
        );

      res.json(result.rows);
    } catch (error) {
      console.error("Report error:", error);

      res.status(500).json({
        error: "Report argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   TEACHER DASHBOARD
========================================================= */

app.get(
  "/api/dashboard",
  teacherAuth,
  async (req, res) => {
    try {
      const [
        classesResult,
        studentsResult,
        attendanceResult,
        resultsResult
      ] = await Promise.all([
        pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM classes
          WHERE teacher_id = $1
          `,
          [req.user.id]
        ),

        pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM students s
          JOIN classes c
            ON c.id = s.class_id
          WHERE c.teacher_id = $1
          `,
          [req.user.id]
        ),

        pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM attendance a
          JOIN classes c
            ON c.id = a.class_id
          WHERE c.teacher_id = $1
          `,
          [req.user.id]
        ),

        pool.query(
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
        )
      ]);

      res.json({
        classes:
          classesResult.rows[0].count,

        students:
          studentsResult.rows[0].count,

        attendance:
          attendanceResult.rows[0].count,

        results:
          resultsResult.rows[0].count
      });
    } catch (error) {
      console.error(
        "Dashboard error:",
        error
      );

      res.status(500).json({
        error: "Dashboard argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   EXAM RESULTS - TEACHER GET
========================================================= */

app.get(
  "/api/results",
  teacherAuth,
  async (req, res) => {
    try {
      const {
        classId,
        studentCode
      } = req.query;

      let query = `
        SELECT
          r.id,
          r.exam_name,
          r.subject,
          r.score,
          r.total,
          r.exam_date,
          r.note,
          r.created_at,

          s.id AS student_id,
          s.full_name,
          s.student_code,

          c.id AS class_id,
          c.name AS class_name,
          c.grade

        FROM exam_results r

        JOIN students s
          ON s.id = r.student_id

        JOIN classes c
          ON c.id = s.class_id

        WHERE c.teacher_id = $1
      `;

      const values = [
        req.user.id
      ];

      if (classId) {
        values.push(
          Number(classId)
        );

        query += `
          AND c.id = $${values.length}
        `;
      }

      if (studentCode) {
        values.push(
          studentCode.trim()
        );

        query += `
          AND LOWER(s.student_code)
              = LOWER($${values.length})
        `;
      }

      query += `
        ORDER BY
          r.exam_date DESC,
          r.id DESC
      `;

      const result =
        await pool.query(
          query,
          values
        );

      res.json(result.rows);
    } catch (error) {
      console.error(
        "Get results error:",
        error
      );

      res.status(500).json({
        error: "Bu'aa qormaataa argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   EXAM RESULT - TEACHER CREATE
========================================================= */

app.post(
  "/api/results",
  teacherAuth,
  async (req, res) => {
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
        !examName
      ) {
        return res.status(400).json({
          error:
            "Koodii barataa fi maqaa qormaataa guuti."
        });
      }

      const studentResult =
        await pool.query(
          `
          SELECT
            s.id,
            s.full_name,
            s.student_code,
            s.class_id

          FROM students s

          JOIN classes c
            ON c.id = s.class_id

          WHERE
            LOWER(s.student_code)
              = LOWER($1)

            AND c.teacher_id = $2
          `,
          [
            studentCode.trim(),
            req.user.id
          ]
        );

      if (
        studentResult.rows.length === 0
      ) {
        return res.status(404).json({
          error:
            "Barataa koodii kana qabu hin argamne."
        });
      }

      const student =
        studentResult.rows[0];

      const scoreValue =
        Number(score || 0);

      const totalValue =
        Number(total || 100);

      if (totalValue <= 0) {
        return res.status(400).json({
          error:
            "Total qormaataa 0 caalaa ta'uu qaba."
        });
      }

      if (
        scoreValue < 0 ||
        scoreValue > totalValue
      ) {
        return res.status(400).json({
          error:
            "Qabxiin sirrii miti."
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
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            COALESCE($6::date, CURRENT_DATE),
            $7
          )

          RETURNING *
          `,
          [
            student.id,
            examName.trim(),
            subject || "",
            scoreValue,
            totalValue,
            examDate || null,
            note || ""
          ]
        );

      res.json({
        message:
          "Bu'aan qormaataa galmaa'eera.",

        result:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Create result error:",
        error
      );

      res.status(500).json({
        error:
          "Bu'aa qormaataa galchuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   EXAM RESULT - TEACHER UPDATE
========================================================= */

app.put(
  "/api/results/:id",
  teacherAuth,
  async (req, res) => {
    try {
      const resultId =
        Number(req.params.id);

      const {
        examName,
        subject,
        score,
        total,
        examDate,
        note
      } = req.body;

      const check =
        await pool.query(
          `
          SELECT r.id
          FROM exam_results r

          JOIN students s
            ON s.id = r.student_id

          JOIN classes c
            ON c.id = s.class_id

          WHERE
            r.id = $1
            AND c.teacher_id = $2
          `,
          [
            resultId,
            req.user.id
          ]
        );

      if (check.rows.length === 0) {
        return res.status(404).json({
          error:
            "Bu'aan qormaataa hin argamne."
        });
      }

      const scoreValue =
        Number(score || 0);

      const totalValue =
        Number(total || 100);

      if (
        totalValue <= 0 ||
        scoreValue < 0 ||
        scoreValue > totalValue
      ) {
        return res.status(400).json({
          error:
            "Score ykn total sirrii miti."
        });
      }

      const result =
        await pool.query(
          `
          UPDATE exam_results

          SET
            exam_name = $1,
            subject = $2,
            score = $3,
            total = $4,
            exam_date =
              COALESCE(
                $5::date,
                exam_date
              ),
            note = $6

          WHERE id = $7

          RETURNING *
          `,
          [
            examName,
            subject || "",
            scoreValue,
            totalValue,
            examDate || null,
            note || "",
            resultId
          ]
        );

      res.json({
        message:
          "Bu'aan qormaataa sirreeffameera.",

        result:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Update result error:",
        error
      );

      res.status(500).json({
        error:
          "Bu'aa qormaataa sirreessuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   EXAM RESULT - TEACHER DELETE
========================================================= */

app.delete(
  "/api/results/:id",
  teacherAuth,
  async (req, res) => {
    try {
      const resultId =
        Number(req.params.id);

      const check =
        await pool.query(
          `
          SELECT r.id
          FROM exam_results r

          JOIN students s
            ON s.id = r.student_id

          JOIN classes c
            ON c.id = s.class_id

          WHERE
            r.id = $1
            AND c.teacher_id = $2
          `,
          [
            resultId,
            req.user.id
          ]
        );

      if (check.rows.length === 0) {
        return res.status(404).json({
          error:
            "Bu'aan qormaataa hin argamne."
        });
      }

      await pool.query(
        `
        DELETE FROM exam_results
        WHERE id = $1
        `,
        [resultId]
      );

      res.json({
        message:
          "Bu'aan qormaataa haqameera."
      });
    } catch (error) {
      console.error(
        "Delete result error:",
        error
      );

      res.status(500).json({
        error:
          "Bu'aa qormaataa haquu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   STUDENT OWN RESULTS
   IMPORTANT:
   STUDENT CAN ONLY SEE HIS/HER OWN RESULTS
========================================================= */

app.get(
  "/api/student/results",
  studentAuth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            r.id,
            r.exam_name,
            r.subject,
            r.score,
            r.total,
            r.exam_date,
            r.note,
            r.created_at

          FROM exam_results r

          WHERE r.student_id = $1

          ORDER BY
            r.exam_date DESC,
            r.id DESC
          `,
          [req.student.id]
        );

      const rows =
        result.rows.map((row) => {
          const score =
            Number(row.score || 0);

          const total =
            Number(row.total || 100);

          const percentage =
            total > 0
              ? (score / total) * 100
              : 0;

          return {
            ...row,
            score,
            total,
            percentage:
              Number(
                percentage.toFixed(2)
              )
          };
        });

      res.json(rows);
    } catch (error) {
      console.error(
        "Student results error:",
        error
      );

      res.status(500).json({
        error:
          "Bu'aa qormaataa argachuu hin dandeenye.",
        data: []
      });
    }
  }
);

/* =========================================================
   STUDENT RESULT SUMMARY
========================================================= */

app.get(
  "/api/student/result-summary",
  studentAuth,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            COUNT(*)::int AS total_exams,

            COALESCE(
              SUM(score),
              0
            ) AS total_score,

            COALESCE(
              SUM(total),
              0
            ) AS total_possible

          FROM exam_results

          WHERE student_id = $1
          `,
          [req.student.id]
        );

      const row =
        result.rows[0];

      const totalExams =
        Number(row.total_exams || 0);

      const totalScore =
        Number(row.total_score || 0);

      const totalPossible =
        Number(row.total_possible || 0);

      const percentage =
        totalPossible > 0
          ? (totalScore / totalPossible) * 100
          : 0;

      res.json({
        totalExams,
        totalScore,
        totalPossible,
        percentage:
          Number(
            percentage.toFixed(2)
          )
      });
    } catch (error) {
      console.error(
        "Result summary error:",
        error
      );

      res.status(500).json({
        error:
          "Result summary argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   404 API
========================================================= */

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      error: "API endpoint hin argamne."
    });
  }
);

/* =========================================================
   SPA FALLBACK
   MUST BE LAST
========================================================= */

app.get(
  "*",
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  await initDatabase();

  app.listen(
    PORT,
    "0.0.0.0",
    () => {
      console.log(
        `Walo-OR server running on port ${PORT}`
      );
    }
  );
}

startServer();

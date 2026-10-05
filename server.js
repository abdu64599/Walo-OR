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
  family: 4
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  express.static(path.join(__dirname, "public"))
);

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
        private_token TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      ALTER TABLE students
      ADD COLUMN IF NOT EXISTS private_token TEXT;
    `);

    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS
      students_private_token_unique
      ON students(private_token)
      WHERE private_token IS NOT NULL;
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
          CHECK (
            status IN (
              'present',
              'absent',
              'late'
            )
          ),

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

        exam_date DATE DEFAULT CURRENT_DATE,

        note TEXT,

        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    /* Token hin qabneef token haaraa uuma */

    const oldStudents = await pool.query(`
      SELECT id
      FROM students
      WHERE private_token IS NULL
    `);

    for (const student of oldStudents.rows) {

      let token;
      let exists = true;

      while (exists) {

        token =
          crypto.randomBytes(24).toString("hex");

        const check =
          await pool.query(
            `
            SELECT id
            FROM students
            WHERE private_token = $1
            `,
            [token]
          );

        exists = check.rows.length > 0;
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

    console.log(
      "Database migrations completed."
    );

  } catch (error) {

    console.error(
      "Database initialization failed:",
      error
    );

    throw error;
  }
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/health", async (req, res) => {

  try {

    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: "connected",
      message: "Walo-OR server is running."
    });

  } catch (error) {

    res.status(500).json({
      ok: false,
      database: "error",
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
      database: "error"
    });
  }
});

/* =========================================================
   AUTH
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

function teacherAuth(req, res, next) {

  try {

    const auth =
      req.headers.authorization || "";

    if (!auth.startsWith("Bearer ")) {

      return res.status(401).json({
        error: "Login godhi."
      });
    }

    const token =
      auth.substring(7);

    const decoded =
      jwt.verify(
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
      error:
        "Token sirrii miti ykn yeroon isaa darbeera."
    });
  }
}

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", async (req, res) => {

  try {

    const {
      name,
      email,
      password
    } = req.body;

    if (
      !name ||
      !email ||
      !password
    ) {

      return res.status(400).json({
        error:
          "Maqaa, email fi password guuti."
      });
    }

    if (password.length < 6) {

      return res.status(400).json({
        error:
          "Password yoo xiqqaate qubee 6 qabaachuu qaba."
      });
    }

    const existing =
      await pool.query(
        `
        SELECT id
        FROM users
        WHERE LOWER(email) = LOWER($1)
        `,
        [email.trim()]
      );

    if (existing.rows.length) {

      return res.status(400).json({
        error:
          "Email kun duraan jira."
      });
    }

    const hash =
      await bcrypt.hash(
        password,
        10
      );

    const result =
      await pool.query(
        `
        INSERT INTO users
        (
          name,
          email,
          password_hash,
          role
        )

        VALUES
        ($1, $2, $3, 'teacher')

        RETURNING
          id,
          name,
          email,
          role
        `,
        [
          name.trim(),
          email.trim(),
          hash
        ]
      );

    const user =
      result.rows[0];

    res.json({
      token: makeToken(user),
      user
    });

  } catch (error) {

    console.error(
      "Register error:",
      error
    );

    res.status(500).json({
      error:
        "Account uumuu hin dandeenye."
    });
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {

  try {

    const {
      email,
      password
    } = req.body;

    const result =
      await pool.query(
        `
        SELECT *
        FROM users
        WHERE LOWER(email) = LOWER($1)
        AND role = 'teacher'
        `,
        [email]
      );

    if (!result.rows.length) {

      return res.status(401).json({
        error:
          "Email ykn password sirrii miti."
      });
    }

    const user =
      result.rows[0];

    const ok =
      await bcrypt.compare(
        password,
        user.password_hash
      );

    if (!ok) {

      return res.status(401).json({
        error:
          "Email ykn password sirrii miti."
      });
    }

    res.json({
      token: makeToken(user),

      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {

    console.error(
      "Login error:",
      error
    );

    res.status(500).json({
      error:
        "Login hin milkoofne."
    });
  }
});

/* =========================================================
   ME
========================================================= */

app.get(
  "/api/me",
  teacherAuth,
  async (req, res) => {

    try {

      const result =
        await pool.query(
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

      if (!result.rows.length) {

        return res.status(404).json({
          error:
            "User hin argamne."
        });
      }

      res.json(
        result.rows[0]
      );

    } catch (error) {

      res.status(500).json({
        error:
          "Profile argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   CLASSES GET
========================================================= */

app.get(
  "/api/classes",
  teacherAuth,
  async (req, res) => {

    try {

      const result =
        await pool.query(
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

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Kutaa argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   CREATE CLASS
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
          error:
            "Maqaa kutaa galchi."
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO classes
          (
            name,
            grade,
            teacher_id
          )

          VALUES
          ($1, $2, $3)

          RETURNING *
          `,
          [
            name.trim(),
            grade || "",
            req.user.id
          ]
        );

      res.json({
        message:
          "Kutaan uumameera.",
        class:
          result.rows[0]
      });

    } catch (error) {

      res.status(500).json({
        error:
          "Kutaa uumuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   DELETE CLASS
========================================================= */

app.delete(
  "/api/classes/:id",
  teacherAuth,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          DELETE FROM classes
          WHERE id = $1
          AND teacher_id = $2
          RETURNING id
          `,
          [
            Number(req.params.id),
            req.user.id
          ]
        );

      if (!result.rows.length) {

        return res.status(404).json({
          error:
            "Kutaan hin argamne."
        });
      }

      res.json({
        message:
          "Kutaan haqameera."
      });

    } catch (error) {

      res.status(500).json({
        error:
          "Kutaa haquu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   PRIVATE TOKEN
========================================================= */

function generatePrivateToken() {

  return crypto
    .randomBytes(24)
    .toString("hex");
}

function getBaseUrl(req) {

  const host =
    req.get("host");

  if (!host) {
    return "";
  }

  return `${req.protocol}://${host}`;
}

/* =========================================================
   STUDENTS GET
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
          s.private_token,

          c.name AS class_name,
          c.grade

        FROM students s

        LEFT JOIN classes c
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
          AND s.class_id = $${values.length}
        `;
      }

      query += `
        ORDER BY s.id DESC
      `;

      const result =
        await pool.query(
          query,
          values
        );

      const students =
        result.rows.map(
          student => {

            const privatePath =
              student.private_token
                ? `/s/${student.private_token}`
                : null;

            const privateLink =
              privatePath
                ? `${getBaseUrl(req)}${privatePath}`
                : null;

            return {
              id: student.id,
              full_name:
                student.full_name,
              student_code:
                student.student_code,
              phone:
                student.phone,
              class_id:
                student.class_id,
              class_name:
                student.class_name,
              grade:
                student.grade,

              private_path:
                privatePath,

              private_link:
                privateLink
            };
          }
        );

      res.json(
        students
      );

    } catch (error) {

      console.error(
        "Students GET error:",
        error
      );

      res.status(500).json({
        error:
          "Barattoota argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   CREATE STUDENT
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

      if (
        !fullName ||
        !studentCode ||
        !classId
      ) {

        return res.status(400).json({
          error:
            "Maqaa, koodii fi kutaa guuti."
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

      if (!classCheck.rows.length) {

        return res.status(403).json({
          error:
            "Kutaa kana irratti hayyama hin qabdu."
        });
      }

      const duplicate =
        await pool.query(
          `
          SELECT id
          FROM students
          WHERE LOWER(student_code)
            = LOWER($1)
          `,
          [
            studentCode.trim()
          ]
        );

      if (duplicate.rows.length) {

        return res.status(400).json({
          error:
            "Student Code kun duraan jira."
        });
      }

      let privateToken;
      let tokenExists = true;

      while (tokenExists) {

        privateToken =
          generatePrivateToken();

        const check =
          await pool.query(
            `
            SELECT id
            FROM students
            WHERE private_token = $1
            `,
            [privateToken]
          );

        tokenExists =
          check.rows.length > 0;
      }

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

          RETURNING
            id,
            full_name,
            student_code,
            phone,
            class_id,
            private_token
          `,
          [
            fullName.trim(),
            studentCode.trim(),
            phone || "",
            Number(classId),
            privateToken
          ]
        );

      const student =
        result.rows[0];

      const privatePath =
        `/s/${privateToken}`;

      const privateLink =
        `${getBaseUrl(req)}${privatePath}`;

      res.json({
        message:
          "Barataan galmaa'eera.",

        student: {
          ...student,
          private_path:
            privatePath,
          private_link:
            privateLink
        },

        private_path:
          privatePath,

        private_link:
          privateLink
      });

    } catch (error) {

      console.error(
        "Create student error:",
        error
      );

      res.status(500).json({
        error:
          "Barataa galchuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   REGENERATE LINK
========================================================= */

app.post(
  "/api/students/:id/regenerate-link",
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

      if (!check.rows.length) {

        return res.status(404).json({
          error:
            "Barataan hin argamne."
        });
      }

      let token;
      let exists = true;

      while (exists) {

        token =
          generatePrivateToken();

        const tokenCheck =
          await pool.query(
            `
            SELECT id
            FROM students
            WHERE private_token = $1
            `,
            [token]
          );

        exists =
          tokenCheck.rows.length > 0;
      }

      await pool.query(
        `
        UPDATE students
        SET private_token = $1
        WHERE id = $2
        `,
        [
          token,
          studentId
        ]
      );

      const privatePath =
        `/s/${token}`;

      const privateLink =
        `${getBaseUrl(req)}${privatePath}`;

      res.json({
        message:
          "Linkii haaraan uumameera.",

        private_path:
          privatePath,

        private_link:
          privateLink
      });

    } catch (error) {

      console.error(
        "Regenerate error:",
        error
      );

      res.status(500).json({
        error:
          "Link haaraa uumuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   REVOKE LINK
========================================================= */

app.post(
  "/api/students/:id/revoke-link",
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

      if (!check.rows.length) {

        return res.status(404).json({
          error:
            "Barataan hin argamne."
        });
      }

      await pool.query(
        `
        UPDATE students
        SET private_token = NULL
        WHERE id = $1
        `,
        [studentId]
      );

      res.json({
        message:
          "Linkii barataa haqameera."
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Link haquu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   DELETE STUDENT
========================================================= */

app.delete(
  "/api/students/:id",
  teacherAuth,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          DELETE FROM students s
          USING classes c

          WHERE
            s.id = $1
            AND s.class_id = c.id
            AND c.teacher_id = $2

          RETURNING s.id
          `,
          [
            Number(req.params.id),
            req.user.id
          ]
        );

      if (!result.rows.length) {

        return res.status(404).json({
          error:
            "Barataan hin argamne."
        });
      }

      res.json({
        message:
          "Barataan haqameera."
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Barataa haquu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   ATTENDANCE GET
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
          error:
            "Class fi date barbaachisa."
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

      if (!check.rows.length) {

        return res.status(403).json({
          error:
            "Kutaa kana irratti hayyama hin qabdu."
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

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Attendance argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   ATTENDANCE SAVE
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
          error:
            "Attendance guuti."
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
          error:
            "Status sirrii miti."
        });
      }

      const check =
        await pool.query(
          `
          SELECT s.id
          FROM students s

          JOIN classes c
            ON c.id = s.class_id

          WHERE
            s.id = $1
            AND c.id = $2
            AND c.teacher_id = $3
          `,
          [
            Number(studentId),
            Number(classId),
            req.user.id
          ]
        );

      if (!check.rows.length) {

        return res.status(403).json({
          error:
            "Barataa kana irratti hayyama hin qabdu."
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
          (
            student_id,
            attendance_date
          )

          DO UPDATE SET
            class_id =
              EXCLUDED.class_id,

            status =
              EXCLUDED.status,

            note =
              EXCLUDED.note

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
        message:
          "Attendance galmaa'eera.",

        attendance:
          result.rows[0]
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Attendance galchuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   REPORT
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

          COUNT(a.id)::int
            AS total_days,

          COUNT(a.id)
            FILTER (
              WHERE a.status = 'present'
            )::int
            AS present_days,

          COUNT(a.id)
            FILTER (
              WHERE a.status = 'absent'
            )::int
            AS absent_days,

          COUNT(a.id)
            FILTER (
              WHERE a.status = 'late'
            )::int
            AS late_days

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

        values.push(
          Number(classId)
        );

        query += `
          AND s.class_id = $${values.length}
        `;
      }

      query += `
        GROUP BY
          s.id,
          s.full_name,
          s.student_code

        ORDER BY
          s.full_name
      `;

      const result =
        await pool.query(
          query,
          values
        );

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Report argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   DASHBOARD
========================================================= */

app.get(
  "/api/dashboard",
  teacherAuth,
  async (req, res) => {

    try {

      const [
        classes,
        students,
        attendance,
        results
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
          Number(classes.rows[0].count),

        students:
          Number(students.rows[0].count),

        attendance:
          Number(attendance.rows[0].count),

        results:
          Number(results.rows[0].count)
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Dashboard argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   RESULTS GET
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

          s.full_name,
          s.student_code,

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

      res.json(
        result.rows
      );

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Bu'aa qormaataa argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   CREATE RESULT
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

      const student =
        await pool.query(
          `
          SELECT
            s.id,
            s.full_name

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

      if (!student.rows.length) {

        return res.status(404).json({
          error:
            "Barataa hin argamne."
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
            student.rows[0].id,
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

      console.error(error);

      res.status(500).json({
        error:
          "Bu'aa qormaataa galchuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   DELETE RESULT
========================================================= */

app.delete(
  "/api/results/:id",
  teacherAuth,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          DELETE FROM exam_results r
          USING students s, classes c

          WHERE
            r.id = $1
            AND r.student_id = s.id
            AND s.class_id = c.id
            AND c.teacher_id = $2

          RETURNING r.id
          `,
          [
            Number(req.params.id),
            req.user.id
          ]
        );

      if (!result.rows.length) {

        return res.status(404).json({
          error:
            "Bu'aan hin argamne."
        });
      }

      res.json({
        message:
          "Bu'aan qormaataa haqameera."
      });

    } catch (error) {

      res.status(500).json({
        error:
          "Bu'aa haquu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   PUBLIC STUDENT DATA
========================================================= */

app.get(
  "/api/public/student/:token",
  async (req, res) => {

    try {

      const token =
        String(
          req.params.token || ""
        ).trim();

      if (
        !token ||
        token.length < 20 ||
        token.length > 200
      ) {

        return res.status(404).json({
          error:
            "Linkii barataa sirrii miti."
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

            c.name AS class_name,
            c.grade

          FROM students s

          LEFT JOIN classes c
            ON c.id = s.class_id

          WHERE
            s.private_token = $1
          `,
          [token]
        );

      if (!studentResult.rows.length) {

        return res.status(404).json({
          error:
            "Linkiin kun hin jiru ykn haqameera."
        });
      }

      const student =
        studentResult.rows[0];

      const attendanceResult =
        await pool.query(
          `
          SELECT
            a.id,
            a.attendance_date,
            a.status,
            a.note

          FROM attendance a

          WHERE a.student_id = $1

          ORDER BY
            a.attendance_date DESC,
            a.id DESC
          `,
          [student.id]
        );

      const resultResult =
        await pool.query(
          `
          SELECT
            r.id,
            r.exam_name,
            r.subject,
            r.score,
            r.total,
            r.exam_date,
            r.note

          FROM exam_results r

          WHERE r.student_id = $1

          ORDER BY
            r.exam_date DESC,
            r.id DESC
          `,
          [student.id]
        );

      const attendance =
        attendanceResult.rows;

      const present =
        attendance.filter(
          x => x.status === "present"
        ).length;

      const absent =
        attendance.filter(
          x => x.status === "absent"
        ).length;

      const late =
        attendance.filter(
          x => x.status === "late"
        ).length;

      const results =
        resultResult.rows.map(row => {

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

      res.json({

        student,

        attendance,

        attendanceSummary: {

          total:
            attendance.length,

          present,

          absent,

          late
        },

        results
      });

    } catch (error) {

      console.error(
        "Public student error:",
        error
      );

      res.status(500).json({
        error:
          "Odeeffannoo barataa argachuu hin dandeenye."
      });
    }
  }
);

/* =========================================================
   PUBLIC STUDENT PAGE
========================================================= */

app.get(
  "/s/:token",
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "student.html"
      )
    );
  }
);

/* =========================================================
   API 404
========================================================= */

app.use(
  "/api",
  (req, res) => {

    res.status(404).json({
      error:
        "API endpoint hin argamne."
    });
  }
);

/* =========================================================
   MAIN PAGE
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
   START
========================================================= */

async function startServer() {

  try {

    await initDatabase();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          `Walo-OR running on port ${PORT}`
        );
      }
    );

  } catch (error) {

    console.error(
      "Server start failed:",
      error
    );

    process.exit(1);
  }
}

startServer();

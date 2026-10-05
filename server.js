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
  connectionTimeoutMillis: 10000
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "public")));

async function db(query, params = []) {
  const result = await pool.query(query, params);
  return result.rows;
}

async function initDatabase() {
  if (!process.env.DATABASE_URL) {
    throw new Error(
      "DATABASE_URL hin argamne. Render Environment keessatti DATABASE_URL galchi."
    );
  }

  await db(`
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

  console.log("Database tables ready.");
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      error: "Login godhi."
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Token sirrii miti. Irra deebi'ii login godhi."
    });
  }
}

/* HEALTH */

app.get("/health", async (req, res) => {
  try {
    await db("SELECT 1");

    res.json({
      ok: true,
      app: "Walo-OR",
      database: "connected"
    });
  } catch (e) {
    res.status(500).json({
      ok: false,
      database: "error",
      message: e.message
    });
  }
});

/* REGISTER */

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

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

    const exists = await db(
      "SELECT id FROM users WHERE LOWER(email)=LOWER($1)",
      [email.trim()]
    );

    if (exists.length) {
      return res.status(409).json({
        error: "Email kun duraan galmaa'eera."
      });
    }

    const hash = await bcrypt.hash(password, 10);

    const rows = await db(
      `
      INSERT INTO users
      (name,email,password_hash)
      VALUES ($1,$2,$3)
      RETURNING id,name,email,role
      `,
      [
        name.trim(),
        email.trim().toLowerCase(),
        hash
      ]
    );

    const user = rows[0];

    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        role: user.role
      },
      JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    res.json({
      token,
      user
    });

  } catch (e) {
    res.status(500).json({
      error: "Register irratti rakkoon uumame.",
      detail: e.message
    });
  }
});

/* LOGIN */

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const rows = await db(
      "SELECT * FROM users WHERE LOWER(email)=LOWER($1)",
      [email?.trim()]
    );

    if (!rows.length) {
      return res.status(401).json({
        error: "Email ykn password sirrii miti."
      });
    }

    const user = rows[0];

    const ok = await bcrypt.compare(
      password || "",
      user.password_hash
    );

    if (!ok) {
      return res.status(401).json({
        error: "Email ykn password sirrii miti."
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        role: user.role
      },
      JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (e) {
    res.status(500).json({
      error: "Login irratti rakkoon uumame.",
      detail: e.message
    });
  }
});

/* CURRENT USER */

app.get("/api/me", auth, async (req, res) => {
  const rows = await db(
    `
    SELECT id,name,email,role,created_at
    FROM users
    WHERE id=$1
    `,
    [req.user.id]
  );

  res.json(rows[0] || null);
});

/* CLASSES */

app.get("/api/classes", auth, async (req, res) => {
  const rows = await db(
    `
    SELECT
      c.id,
      c.name,
      c.grade,
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

  res.json(rows);
});

app.post("/api/classes", auth, async (req, res) => {
  try {
    const { name, grade } = req.body;

    if (!name) {
      return res.status(400).json({
        error: "Maqaa class guuti."
      });
    }

    const rows = await db(
      `
      INSERT INTO classes
      (name,grade,teacher_id)
      VALUES ($1,$2,$3)
      RETURNING *
      `,
      [
        name.trim(),
        grade?.trim() || null,
        req.user.id
      ]
    );

    res.json(rows[0]);

  } catch (e) {
    res.status(500).json({
      error: "Class uumuu hin dandeenye.",
      detail: e.message
    });
  }
});

app.delete("/api/classes/:id", auth, async (req, res) => {
  const rows = await db(
    `
    DELETE FROM classes
    WHERE id=$1
    AND teacher_id=$2
    RETURNING id
    `,
    [
      req.params.id,
      req.user.id
    ]
  );

  if (!rows.length) {
    return res.status(404).json({
      error: "Class hin argamne."
    });
  }

  res.json({
    ok: true
  });
});

/* STUDENTS */

app.get("/api/students", auth, async (req, res) => {
  const classId = req.query.classId;
  const search = (req.query.search || "").trim();

  let sql = `
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
    WHERE
      c.teacher_id=$1
  `;

  const params = [req.user.id];

  if (classId) {
    params.push(classId);

    sql += `
      AND s.class_id=$${params.length}
    `;
  }

  if (search) {
    params.push(`%${search}%`);

    sql += `
      AND (
        s.full_name ILIKE $${params.length}
        OR COALESCE(s.student_code,'')
        ILIKE $${params.length}
      )
    `;
  }

  sql += `
    ORDER BY s.full_name ASC
  `;

  res.json(
    await db(sql, params)
  );
});

app.post("/api/students", auth, async (req, res) => {
  try {
    const {
      fullName,
      studentCode,
      phone,
      classId
    } = req.body;

    if (!fullName || !classId) {
      return res.status(400).json({
        error: "Maqaa barataa fi class guuti."
      });
    }

    const ownClass = await db(
      `
      SELECT id
      FROM classes
      WHERE id=$1
      AND teacher_id=$2
      `,
      [
        classId,
        req.user.id
      ]
    );

    if (!ownClass.length) {
      return res.status(403).json({
        error: "Class kun kan kee miti."
      });
    }

    const rows = await db(
      `
      INSERT INTO students
      (full_name,student_code,phone,class_id)
      VALUES ($1,$2,$3,$4)
      RETURNING *
      `,
      [
        fullName.trim(),
        studentCode?.trim() || null,
        phone?.trim() || null,
        classId
      ]
    );

    res.json(rows[0]);

  } catch (e) {

    if (e.code === "23505") {
      return res.status(409).json({
        error: "Student code kun duraan jira."
      });
    }

    res.status(500).json({
      error: "Barataa galmeessuu hin dandeenye.",
      detail: e.message
    });
  }
});

app.delete("/api/students/:id", auth, async (req, res) => {
  const rows = await db(
    `
    DELETE FROM students
    WHERE id=$1
    AND class_id IN (
      SELECT id
      FROM classes
      WHERE teacher_id=$2
    )
    RETURNING id
    `,
    [
      req.params.id,
      req.user.id
    ]
  );

  if (!rows.length) {
    return res.status(404).json({
      error: "Barataa hin argamne."
    });
  }

  res.json({
    ok: true
  });
});

/* GET ATTENDANCE */

app.get("/api/attendance", auth, async (req, res) => {
  const classId = req.query.classId;
  const date = req.query.date;

  if (!classId || !date) {
    return res.status(400).json({
      error: "Class fi guyyaa barbaachisa."
    });
  }

  const own = await db(
    `
    SELECT id
    FROM classes
    WHERE id=$1
    AND teacher_id=$2
    `,
    [
      classId,
      req.user.id
    ]
  );

  if (!own.length) {
    return res.status(403).json({
      error: "Class kun kan kee miti."
    });
  }

  const rows = await db(
    `
    SELECT
      s.id,
      s.full_name,
      s.student_code,
      s.class_id,
      COALESCE(a.status,'absent') AS status,
      COALESCE(a.note,'') AS note
    FROM students s
    LEFT JOIN attendance a
      ON a.student_id=s.id
      AND a.attendance_date=$2
    WHERE s.class_id=$1
    ORDER BY s.full_name
    `,
    [
      classId,
      date
    ]
  );

  res.json(rows);
});

/* SAVE ATTENDANCE */

app.post("/api/attendance", auth, async (req, res) => {
  try {
    const {
      classId,
      date,
      records
    } = req.body;

    if (
      !classId ||
      !date ||
      !Array.isArray(records)
    ) {
      return res.status(400).json({
        error: "Class, date fi records guuti."
      });
    }

    const own = await db(
      `
      SELECT id
      FROM classes
      WHERE id=$1
      AND teacher_id=$2
      `,
      [
        classId,
        req.user.id
      ]
    );

    if (!own.length) {
      return res.status(403).json({
        error: "Class kun kan kee miti."
      });
    }

    await db("BEGIN");

    try {

      for (const r of records) {

        if (
          ![
            "present",
            "absent",
            "late"
          ].includes(r.status)
        ) {
          continue;
        }

        await db(
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
          ($1,$2,$3,$4,$5)

          ON CONFLICT
          (student_id,attendance_date)

          DO UPDATE SET
            class_id=EXCLUDED.class_id,
            status=EXCLUDED.status,
            note=EXCLUDED.note
          `,
          [
            r.studentId,
            classId,
            date,
            r.status,
            r.note || null
          ]
        );
      }

      await db("COMMIT");

    } catch (e) {

      await db("ROLLBACK");

      throw e;
    }

    res.json({
      ok: true,
      message: "Attendance olkaa'e."
    });

  } catch (e) {

    res.status(500).json({
      error: "Attendance olchuu hin dandeenye.",
      detail: e.message
    });
  }
});

/* REPORT */

app.get("/api/report", auth, async (req, res) => {

  const {
    classId,
    from,
    to
  } = req.query;

  if (!classId || !from || !to) {
    return res.status(400).json({
      error: "Class, from fi to guuti."
    });
  }

  const own = await db(
    `
    SELECT id
    FROM classes
    WHERE id=$1
    AND teacher_id=$2
    `,
    [
      classId,
      req.user.id
    ]
  );

  if (!own.length) {
    return res.status(403).json({
      error: "Class kun kan kee miti."
    });
  }

  const rows = await db(
    `
    SELECT
      s.id,
      s.full_name,
      s.student_code,

      COUNT(a.id)::int AS total_days,

      COUNT(a.id)
      FILTER (
        WHERE a.status='present'
      )::int AS present,

      COUNT(a.id)
      FILTER (
        WHERE a.status='absent'
      )::int AS absent,

      COUNT(a.id)
      FILTER (
        WHERE a.status='late'
      )::int AS late,

      CASE

        WHEN COUNT(a.id)=0
        THEN 0

        ELSE ROUND(
          (
            COUNT(a.id)
            FILTER (
              WHERE a.status IN
              ('present','late')
            )::numeric

            /

            COUNT(a.id)::numeric
          ) * 100,
          1
        )

      END AS percentage

    FROM students s

    LEFT JOIN attendance a
      ON a.student_id=s.id
      AND a.attendance_date
      BETWEEN $2 AND $3

    WHERE s.class_id=$1

    GROUP BY s.id

    ORDER BY s.full_name
    `,
    [
      classId,
      from,
      to
    ]
  );

  res.json(rows);
});

/* DASHBOARD */

app.get("/api/dashboard", auth, async (req, res) => {

  const rows = await db(
    `
    SELECT

      (
        SELECT COUNT(*)::int
        FROM classes
        WHERE teacher_id=$1
      ) AS classes,

      (
        SELECT COUNT(*)::int
        FROM students s
        JOIN classes c
          ON c.id=s.class_id
        WHERE c.teacher_id=$1
      ) AS students,

      (
        SELECT COUNT(*)::int
        FROM attendance a
        JOIN classes c
          ON c.id=a.class_id
        WHERE c.teacher_id=$1
        AND a.attendance_date=CURRENT_DATE
        AND a.status='present'
      ) AS today_present,

      (
        SELECT COUNT(*)::int
        FROM attendance a
        JOIN classes c
          ON c.id=a.class_id
        WHERE c.teacher_id=$1
        AND a.attendance_date=CURRENT_DATE
        AND a.status='absent'
      ) AS today_absent,

      (
        SELECT COUNT(*)::int
        FROM attendance a
        JOIN classes c
          ON c.id=a.class_id
        WHERE c.teacher_id=$1
        AND a.attendance_date=CURRENT_DATE
        AND a.status='late'
      ) AS today_late
    `,
    [req.user.id]
  );

  res.json(rows[0]);
});

/* FRONTEND */

app.get("*", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

/* START */

async function start() {

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

  } catch (e) {

    console.error(
      "Database initialization failed:",
      e
    );

    process.exit(1);
  }
}

start();

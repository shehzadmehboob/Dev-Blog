require("dotenv").config();

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
});

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

function checkUser(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    res.locals.userId = null;
    return next();
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.locals.userId = decoded.userId;
  } catch (err) {
    res.locals.userId = null;
  }
  next();
}

app.use(checkUser);

function requireJWT(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.redirect("/login");
  }
}


async function savePostTags(postId, tagsInput) {
  await pool.query("DELETE FROM post_tags WHERE post_id = $1", [postId]);
  if (!tagsInput || !tagsInput.trim()) return;

  const tagNames = [
    ...new Set(
      tagsInput
        .split(",")
        .map((t) => t.trim().toLowerCase())
        .filter((t) => t.length > 0)
    ),
  ];

  for (const name of tagNames) {
    
    const tagRes = await pool.query(
      `INSERT INTO tags (name) VALUES ($1)
       ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
       RETURNING id`,
      [name]
    );
    await pool.query(
      "INSERT INTO post_tags (post_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      [postId, tagRes.rows[0].id]
    );
  }
}


app.get("/signup", (req, res) => res.render("signup", { error: null }));

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const userCheck = await pool.query(
      "SELECT id FROM users WHERE email = $1 OR username = $2",
      [email, username]
    );
    if (userCheck.rows.length > 0) {
      return res.render("signup", { error: "Username or email already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3) RETURNING id`,
      [username, email, passwordHash]
    );

    const token = jwt.sign({ userId: result.rows[0].id }, JWT_SECRET, { expiresIn: "30d" });
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.render("signup", { error: "Something went wrong" });
  }
});

app.get("/login", (req, res) => res.render("login", { error: null }));

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.render("login", { error: "Invalid email or password" });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "30d" });
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.render("login", { error: "Something went wrong" });
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});


app.get("/", async (req, res) => {
  const search = req.query.search || "";
  const category = req.query.category || "";
  const tag = req.query.tag || "";
  const page = parseInt(req.query.page) || 1;
  const limit = 10;
  const offset = (page - 1) * limit;

  try {
    const categoriesRes = await pool.query("SELECT * FROM categories ORDER BY name ASC");

    let conditions = [];
    let params = [];

    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(posts.title ILIKE $${params.length} OR posts.content ILIKE $${params.length})`);
    }
    if (category) {
      params.push(category);
      conditions.push(`posts.category_id = $${params.length}`);
    }
    if (tag) {
      params.push(tag.toLowerCase());
      conditions.push(`EXISTS (
        SELECT 1 FROM post_tags pt
        JOIN tags t ON pt.tag_id = t.id
        WHERE pt.post_id = posts.id AND t.name = $${params.length}
      )`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    params.push(limit, offset);
    const queryText = `
      SELECT 
        posts.*, 
        users.username AS author_name,
        categories.name AS category_name,
        COALESCE(ARRAY_AGG(tags.name) FILTER (WHERE tags.name IS NOT NULL), '{}') AS tags
      FROM posts
      JOIN users ON posts.author_id = users.id
      LEFT JOIN categories ON posts.category_id = categories.id
      LEFT JOIN post_tags ON posts.id = post_tags.post_id
      LEFT JOIN tags ON post_tags.tag_id = tags.id
      ${whereClause}
      GROUP BY posts.id, users.username, categories.name
      ORDER BY posts.created_at DESC
      LIMIT $${params.length - 1} OFFSET $${params.length}
    `;

    const result = await pool.query(queryText, params);

    res.render("home", {
      posts: result.rows,
      categories: categoriesRes.rows,
      search,
      selectedCategory: category,
      selectedTag: tag,
      page,
      hasMore: result.rows.length === limit,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

// AUTHOR PAGE
app.get("/author/:username", async (req, res) => {
  const { username } = req.params;

  try {
    const userRes = await pool.query(
      "SELECT id, username, created_at FROM users WHERE username = $1",
      [username]
    );
    if (userRes.rows.length === 0) return res.status(404).send("Author not found");

    const postsRes = await pool.query(
      `SELECT 
        posts.*, 
        users.username AS author_name,
        categories.name AS category_name,
        COALESCE(ARRAY_AGG(tags.name) FILTER (WHERE tags.name IS NOT NULL), '{}') AS tags
       FROM posts
       JOIN users ON posts.author_id = users.id
       LEFT JOIN categories ON posts.category_id = categories.id
       LEFT JOIN post_tags ON posts.id = post_tags.post_id
       LEFT JOIN tags ON post_tags.tag_id = tags.id
       WHERE users.username = $1
       GROUP BY posts.id, users.username, categories.name
       ORDER BY posts.created_at DESC`,
      [username]
    );

    res.render("author", {
      author: userRes.rows[0],
      posts: postsRes.rows,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

app.get("/posts/new", requireJWT, async (req, res) => {
  const categoriesRes = await pool.query("SELECT * FROM categories ORDER BY name ASC");
  res.render("create-post", { categories: categoriesRes.rows });
});

app.post("/posts", requireJWT, async (req, res) => {
  const { title, content, category_id, tags } = req.body;

  try {
    const result = await pool.query(
      `INSERT INTO posts (title, content, author_id, category_id)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [title, content, req.userId, category_id || null]
    );

    await savePostTags(result.rows[0].id, tags);
    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

app.get("/posts/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const postRes = await pool.query(
      `SELECT 
        posts.*, 
        users.username AS author_name,
        categories.name AS category_name,
        COALESCE(ARRAY_AGG(tags.name) FILTER (WHERE tags.name IS NOT NULL), '{}') AS tags
       FROM posts
       JOIN users ON posts.author_id = users.id
       LEFT JOIN categories ON posts.category_id = categories.id
       LEFT JOIN post_tags ON posts.id = post_tags.post_id
       LEFT JOIN tags ON post_tags.tag_id = tags.id
       WHERE posts.id = $1
       GROUP BY posts.id, users.username, categories.name`,
      [id]
    );

    if (postRes.rows.length === 0) return res.status(404).send("Post not found");

    const commentsRes = await pool.query(
      `SELECT comments.*, users.username AS author_name
       FROM comments
       JOIN users ON comments.user_id = users.id
       WHERE comments.post_id = $1
       ORDER BY comments.created_at ASC`,
      [id]
    );

    res.render("single-post", {
      post: postRes.rows[0],
      comments: commentsRes.rows,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

app.get("/posts/:id/edit", requireJWT, async (req, res) => {
  try {
    const postRes = await pool.query(
      `SELECT 
        posts.*,
        COALESCE(ARRAY_AGG(tags.name) FILTER (WHERE tags.name IS NOT NULL), '{}') AS tags
       FROM posts
       LEFT JOIN post_tags ON posts.id = post_tags.post_id
       LEFT JOIN tags ON post_tags.tag_id = tags.id
       WHERE posts.id = $1 AND posts.author_id = $2
       GROUP BY posts.id`,
      [req.params.id, req.userId]
    );

    if (postRes.rows.length === 0) return res.status(403).send("Unauthorized");

    const categoriesRes = await pool.query("SELECT * FROM categories ORDER BY name ASC");
    res.render("edit-post", {
      post: postRes.rows[0],
      categories: categoriesRes.rows,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

app.post("/posts/:id/edit", requireJWT, async (req, res) => {
  const { title, content, category_id, tags } = req.body;

  try {
    await pool.query(
      `UPDATE posts
       SET title = $1, content = $2, category_id = $3, updated_at = CURRENT_TIMESTAMP
       WHERE id = $4 AND author_id = $5`,
      [title, content, category_id || null, req.params.id, req.userId]
    );

    await savePostTags(req.params.id, tags);
    res.redirect(`/posts/${req.params.id}`);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

app.post("/posts/:id/delete", requireJWT, async (req, res) => {
  try {
    await pool.query("DELETE FROM posts WHERE id = $1 AND author_id = $2", [
      req.params.id,
      req.userId,
    ]);
    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});


app.post("/posts/:postId/comments", requireJWT, async (req, res) => {
  try {
    await pool.query(
      "INSERT INTO comments (content, post_id, user_id) VALUES ($1, $2, $3)",
      [req.body.content, req.params.postId, req.userId]
    );
    res.redirect(`/posts/${req.params.postId}`);
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

app.post("/comments/:id/delete", requireJWT, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM comments WHERE id = $1 AND user_id = $2 RETURNING post_id",
      [req.params.id, req.userId]
    );
    if (result.rows.length > 0) {
      return res.redirect(`/posts/${result.rows[0].post_id}`);
    }
    res.redirect("/");
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

app.listen(3000, () => {
  console.log("Server running at http://localhost:3000");
});
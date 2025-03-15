const express = require('express');
const Redis = require('ioredis');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();

// 미들웨어 설정
app.use(express.json());
app.use(cors());

// Redis 연결
const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: parseInt(process.env.REDIS_PORT),
});

// Aurora 연결
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

// 인증 라우트
app.post('/auth/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    // Aurora에 사용자 저장
    const result = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id',
      [username, email, password]
    );
    res.json({ success: true, userId: result.rows[0].id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/auth/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    // 사용자 인증
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length > 0) {
      // Redis에 세션 저장
      const sessionId = Math.random().toString(36).substring(7);
      await redis.set(`session:${sessionId}`, user.rows[0].id, 'EX', 86400);
      res.json({ success: true, sessionId });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 
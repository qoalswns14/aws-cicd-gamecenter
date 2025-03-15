const express = require('express');
const Redis = require('ioredis');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();

// 미들웨어 설정
app.use(express.json());  // 전역으로 설정
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],  // OPTIONS 메소드 추가
    allowedHeaders: ['Content-Type', 'x-session-id'],
    credentials: true
}));

// Redis 연결
const redis = new Redis({
  host: process.env.REDIS_HOST,
  port: parseInt(process.env.REDIS_PORT),
  retryStrategy: function(times) {
    const delay = Math.min(times * 50, 2000);
    return delay;
  }
});

// Redis 연결 에러 핸들링 추가
redis.on('error', function(err) {
  console.error('Redis 연결 에러:', err);
});

// MySQL 연결 풀 생성
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: parseInt(process.env.DB_PORT),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// 데이터베이스 연결 테스트
app.get('/health', async (req, res) => {
  try {
    // DB 연결 테스트
    const [rows] = await pool.query('SELECT NOW() as now');
    
    // Redis 연결 테스트
    const redisResult = await redis.ping();
    
    res.json({
      status: 'healthy',
      database: rows[0],
      redis: redisResult
    });
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

// 회원가입
app.post('/auth/signup', async (req, res) => {
    try {
        console.log('회원가입 요청:', req.body);  // 요청 데이터 로깅
        const { username, email, password } = req.body;
        
        // 필수 필드 검증
        if (!username || !email || !password) {
            return res.status(400).json({ error: '모든 필드를 입력해주세요.' });
        }

        // 이메일 중복 체크
        const [existingUsers] = await pool.query(
            'SELECT id FROM users WHERE email = ?',
            [email]
        );
        
        if (existingUsers.length > 0) {
            return res.status(400).json({ error: '이미 존재하는 이메일입니다.' });
        }
        
        // 비밀번호 해싱
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // 사용자 생성
        const [result] = await pool.query(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );
        
        console.log('회원가입 성공:', { userId: result.insertId, username });  // 성공 로깅
        
        res.status(201).json({
            success: true,
            userId: result.insertId,
            message: '회원가입이 완료되었습니다.'
        });
    } catch (error) {
        console.error('회원가입 에러:', error);  // 에러 로깅
        res.status(500).json({
            error: '회원가입 중 오류가 발생했습니다.',
            details: error.message
        });
    }
});

// 로그인
app.post('/auth/signin', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // 사용자 찾기
    const [users] = await pool.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    
    if (users.length === 0) {
      return res.status(401).json({ error: '이메일 또는 비밀번호가 잘못되었습니다.' });
    }
    
    const user = users[0];
    
    // 비밀번호 확인
    const isValid = await bcrypt.compare(password, user.password);
    
    if (!isValid) {
      return res.status(401).json({ error: '이메일 또는 비밀번호가 잘못되었습니다.' });
    }
    
    // 세션 생성
    const sessionId = Math.random().toString(36).substring(7);
    await redis.set(`session:${sessionId}`, user.id, 'EX', 86400); // 24시간
    
    res.json({
      success: true,
      sessionId,
      username: user.username
    });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({
      error: '로그인 중 오류가 발생했습니다.',
      details: error.message
    });
  }
});

// 세션 확인 엔드포인트
app.get('/api/auth/check', async (req, res) => {
    const sessionId = req.headers['x-session-id'];
    if (!sessionId) {
        return res.status(401).json({ error: 'No session' });
    }

    try {
        const userId = await redis.get(`session:${sessionId}`);
        if (userId) {
            res.json({ valid: true });
        } else {
            res.status(401).json({ error: 'Invalid session' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 
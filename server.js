require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const multer = require('multer');
const cron = require('node-cron');

const app = express();

// --- Configuración variables de entorno ---
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_ORIGIN = 'https://momentto.netlify.app';

// Verificar JWT_SECRET
if (!JWT_SECRET) {
  console.error('❌ ERROR: JWT_SECRET no está definido en las variables de entorno. El servidor no iniciará.');
  process.exit(1);
}

// --- Conexión a MongoDB ---
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('✅ MongoDB conectado'))
  .catch(err => {
    console.error('❌ Error MongoDB:', err);
    process.exit(1);
  });

// --- Esquema de usuario ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email:    { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// --- Middlewares globales ---
app.use(express.json());  // parsear JSON
app.use(cors({
  origin: FRONTEND_ORIGIN,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.options('*', cors({ origin: FRONTEND_ORIGIN }));
app.use(helmet());
app.use(morgan('dev'));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Demasiadas solicitudes, intenta más tarde' }
}));

// --- Rutas de prueba ---
app.get('/', (req, res) => res.send('Servidor OK - Momento'));
app.get('/api/ping', async (req, res, next) => {
  try {
    await mongoose.connection.db.admin().ping();
    res.json({ message: 'MongoDB está activo' });
  } catch (err) {
    next(err);
  }
});

// --- Evitar error GET login ---
app.get('/api/auth/login', (req, res) => {
  res.status(200).send('El endpoint /api/auth/login acepta solo peticiones POST.');
});

// --- Middleware de verificación JWT ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token no proporcionado' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
}

// --- Registro de usuario ---
app.post('/api/auth/register',
  body('username').isLength({ min: 3 }),
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array() });
      }

      const { username, email, password } = req.body;

      const existing = await User.findOne({ email });
      if (existing) {
        return res.status(400).json({ error: 'Email ya registrado' });
      }

      const passwordHash = await bcrypt.hash(password, 10);
      await new User({ username, email, passwordHash }).save();

      res.status(201).json({ message: 'Usuario registrado correctamente' });
    } catch (err) {
      console.error('Error registro:', err);
      next(err);
    }
  }
);

// --- Login de usuario ---
app.post('/api/auth/login',
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array() });
      }

      const { email, password } = req.body;
      console.log('🔐 Login attempt:', { email });

      // Encontrar usuario
      const user = await User.findOne({ email });
      if (!user || !user.passwordHash) {
        console.warn('🛑 Usuario no encontrado o sin hash:', email);
        return res.status(401).json({ error: 'Credenciales incorrectas' });
      }

      // Comparar contraseñas
      if (typeof password !== 'string') {
        return res.status(400).json({ error: 'Contraseña inválida' });
      }

      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match) {
        console.warn('🛑 Contraseña incorrecta para:', email);
        return res.status(401).json({ error: 'Credenciales incorrectas' });
      }

      // Generar token
      const payload = { id: user._id, username: user.username, email: user.email };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

      console.log('✅ Login exitoso:', email);
      res.json({ token, username: user.username });
    } catch (err) {
      console.error('🔥 Error en /api/auth/login:', err);
      next(err);
    }
  }
);

// --- Ruta protegida de sesión ---
app.get('/api/auth/session', authenticateToken, (req, res) => {
  res.json({ message: 'Sesión válida', user: req.user });
});

// --- Subida de imágenes ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const { v4: uuidv4 } = require('uuid');
    const ext = file.originalname.split('.').pop();
    cb(null, uuidv4() + '.' + ext);
  }
});
const upload = multer({ storage });

app.post('/api/upload', authenticateToken, upload.single('imagen'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Archivo no subido' });
  }
  res.json({ mensaje: 'Imagen subida correctamente', filename: req.file.filename });
});

// --- Cron para limpiar imágenes antiguas ---
cron.schedule('0 0 * * *', () => {
  console.log('🧹 Tarea cron: limpiar imágenes antiguas');
  // Lógica de borrado pendiente
});

// --- Servir archivos estáticos ---
app.use('/uploads', express.static('uploads'));

// --- Middleware global de manejo de errores ---
app.use((err, req, res, next) => {
  console.error('💥 Error capturado:', err.stack || err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// --- Iniciar servidor ---
app.listen(PORT, () => {
  console.log(`🚀 Servidor escuchando en puerto ${PORT}`);
});


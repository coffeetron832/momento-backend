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

// --- Middlewares globales ---
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json()); // Debe ir antes de cors y rutas para parsear JSON correctamente

// --- Ruta raíz para comprobar servidor ---
app.get('/', (req, res) => {
  res.status(200).send('🚀 Momento API está corriendo correctamente');
});

// --- Ruta de prueba de conexión a la base de datos ---
app.get('/api/ping', async (req, res) => {
  try {
    const count = await mongoose.connection.db.collection('users').countDocuments();
    return res.json({ message: 'DB conectada', usersCount: count });
  } catch (err) {
    console.error('🌐 Error ping DB:', err);
    return res.status(500).json({ error: 'Error de conexión a la base de datos' });
  }
});

// --- CORS sin cookies ---
app.use(cors({
  origin: FRONTEND_ORIGIN,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.options('*', cors({ origin: FRONTEND_ORIGIN }));

// --- Limitador de solicitudes ---
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Demasiadas solicitudes, intenta más tarde' }
}));

// --- Conexión a MongoDB ---
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('✅ MongoDB conectado');
}).catch(err => {
  console.error('❌ Error MongoDB:', err);
});

// --- Esquema de usuario ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email:    { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// --- Configuración de subida de archivos con multer ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const { v4: uuidv4 } = require('uuid');
    const ext = file.originalname.split('.').pop();
    cb(null, uuidv4() + '.' + ext);
  }
});
const upload = multer({ storage });

// --- Verificación de token JWT ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token no proporcionado' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('🔒 Token inválido:', err);
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
}

// --- Registro de usuario ---
app.post('/api/auth/register',
  body('username').isLength({ min: 3 }),
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.warn('⚠️ Registro inválido:', errors.array());
      return res.status(400).json({ error: errors.array() });
    }

    const { username, email, password } = req.body;

    try {
      const existUser = await User.findOne({ email });
      if (existUser) {
        console.warn('🛑 Email ya registrado:', email);
        return res.status(400).json({ error: 'Email ya registrado' });
      }

      const passwordHash = await bcrypt.hash(password, 10);
      const newUser = new User({ username, email, passwordHash });
      await newUser.save();

      return res.status(201).json({ message: 'Usuario registrado correctamente' });
    } catch (err) {
      console.error('🔴 Error registro:', err);
      return res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
);

// --- Login de usuario ---
app.post('/api/auth/login',
  body('email').isEmail(),
  body('password').exists(),
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.warn('⚠️ Login inválido:', errors.array());
      return res.status(400).json({ error: errors.array() });
    }

    const { email, password } = req.body;
    console.log('🔐 Login attempt:', { email });

    if (!JWT_SECRET) {
      console.error('⚠️ JWT_SECRET no definido en el entorno');
      return res.status(500).json({ error: 'JWT_SECRET no definido en el servidor' });
    }

    try {
      const user = await User.findOne({ email });
      if (!user) {
        console.warn('🛑 Usuario no encontrado:', email);
        return res.status(401).json({ error: 'Credenciales incorrectas' });
      }

      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match) {
        console.warn('🛑 Contraseña incorrecta para:', email);
        return res.status(401).json({ error: 'Credenciales incorrectas' });
      }

      const payload = { id: user._id, username: user.username, email: user.email };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
      console.log('✅ Login exitoso:', email);

      return res.json({ token, username: user.username });
    } catch (err) {
      console.error('🔥 Error interno en /api/auth/login:', err);
      return next(err); // Pasa al middleware de error
    }
  }
);

// --- Ruta protegida para verificar sesión ---
app.get('/api/auth/session', authenticateToken, (req, res) => {
  return res.json({ message: 'Sesión válida', user: req.user });
});

// --- Subida de imagen protegida ---
app.post('/api/upload', authenticateToken, upload.single('imagen'), (req, res) => {
  if (!req.file) {
    console.warn('⚠️ Intento de subir sin archivo');
    return res.status(400).json({ error: 'Archivo no subido' });
  }
  return res.json({ mensaje: 'Imagen subida correctamente', filename: req.file.filename });
});

// --- Tarea automática para limpiar imágenes antiguas ---
cron.schedule('0 0 * * *', () => {
  console.log('🧹 Tarea cron: limpiar imágenes antiguas');
  // Aquí agrega la lógica para borrar archivos expirados
});

// --- Servir carpeta uploads estática ---
app.use('/uploads', express.static('uploads'));

// --- Middleware de manejo de errores ---
app.use((err, req, res, next) => {
  console.error('💥 Unhandled error:', err);
  res.status(500).json({ error: 'Error interno (capturado por middleware)' });
});

// --- Iniciar servidor ---
app.listen(PORT, () => {
  console.log(`🚀 Servidor escuchando en puerto ${PORT}`);
});

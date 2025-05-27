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
const cookieParser = require('cookie-parser');

const app = express();

// --- Configuración variables de entorno ---
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://coffeetron:VP7x-Vf@momentclu.tpsspsi.mongodb.net/?retryWrites=true&w=majority&appName=MomentClu';
const JWT_SECRET = process.env.JWT_SECRET || '7f4b3c9d1a2e5f6a8b0c1d3e4f5a6b7c
';
const FRONTEND_ORIGIN = 'https://momentto.netlify.app';

// --- Conexión a MongoDB ---
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('MongoDB conectado');
}).catch(err => {
  console.error('Error MongoDB:', err);
});

// --- Modelos Mongoose ejemplo ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// --- Middleware global ---
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json());
app.use(cookieParser());

app.use(cors({
  origin: FRONTEND_ORIGIN,
  credentials: true
}));

// Rate limiter global (por ejemplo, 100 requests por 15 minutos)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Demasiadas solicitudes, intenta más tarde' }
});
app.use(limiter);

// --- Multer configuración para subir imágenes ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // carpeta uploads (debe existir)
  },
  filename: (req, file, cb) => {
    // renombra archivo con uuid para evitar conflictos
    const { v4: uuidv4 } = require('uuid');
    const ext = file.originalname.split('.').pop();
    cb(null, uuidv4() + '.' + ext);
  }
});
const upload = multer({ storage });

// --- Middleware para verificar JWT ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token no proporcionado' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
}

// --- Rutas ---
// Registro de usuario
app.post('/api/auth/register',
  // Validación con express-validator
  body('username').isLength({ min: 3 }),
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array() });
    }

    const { username, email, password } = req.body;

    try {
      const existUser = await User.findOne({ email });
      if (existUser) return res.status(400).json({ error: 'Email ya registrado' });

      const passwordHash = await bcrypt.hash(password, 10);

      const newUser = new User({ username, email, passwordHash });
      await newUser.save();

      res.json({ message: 'Usuario registrado correctamente' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  });

// Login de usuario
app.post('/api/auth/login',
  body('email').isEmail(),
  body('password').exists(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array() });
    }

    const { email, password } = req.body;
    try {
      const user = await User.findOne({ email });
      if (!user) return res.status(401).json({ error: 'Credenciales incorrectas' });

      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match) return res.status(401).json({ error: 'Credenciales incorrectas' });

      const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

      res.json({ token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  });

// Ruta protegida de ejemplo (chequea token)
app.get('/api/auth/session', authenticateToken, (req, res) => {
  res.json({ message: 'Sesión válida', user: req.user });
});

// Subida de imagen protegida
app.post('/api/upload', authenticateToken, upload.single('imagen'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Archivo no subido' });
  // Aquí puedes guardar info en BD si quieres

  res.json({ mensaje: 'Imagen subida correctamente', filename: req.file.filename });
});

// Ejemplo de cron para borrar imágenes antiguas (requiere que implementes lógica)
// Se ejecuta cada día a las 00:00
cron.schedule('0 0 * * *', () => {
  console.log('Tarea cron: limpiar imágenes antiguas');
  // Aquí pones la lógica para borrar archivos expirados
});

// --- Servir carpeta uploads estática (opcional) ---
app.use('/uploads', express.static('uploads'));

// --- Iniciar servidor ---
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});


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

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_ORIGIN = 'https://momentto.netlify.app';

// MongoDB conexión
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('✅ MongoDB conectado'))
  .catch(err => console.error('❌ Error MongoDB:', err));

// Usuario esquema y modelo
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// Middlewares
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json());

// CORS configuración
app.use(cors({
  origin: FRONTEND_ORIGIN,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.options('*', cors({ origin: FRONTEND_ORIGIN }));

// Rate limiter
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Demasiadas solicitudes, intenta más tarde' }
}));

// Multer para uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const { v4: uuidv4 } = require('uuid');
    const ext = file.originalname.split('.').pop();
    cb(null, uuidv4() + '.' + ext);
  }
});
const upload = multer({ storage });

// Middleware JWT auth
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

// Registro usuario
app.post('/api/auth/register',
  body('username').isLength({ min: 3 }),
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ error: errors.array() });

    const { username, email, password } = req.body;

    try {
      const existUser = await User.findOne({ email });
      if (existUser)
        return res.status(400).json({ error: 'Email ya registrado' });

      const passwordHash = await bcrypt.hash(password, 10);
      const newUser = new User({ username, email, passwordHash });
      await newUser.save();

      res.json({ message: 'Usuario registrado correctamente' });
    } catch (err) {
      console.error('Error registro:', err);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  });

// Login usuario
app.post('/api/auth/login',
  body('email').isEmail(),
  body('password').exists(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ error: errors.array() });

    const { email, password } = req.body;
    try {
      const user = await User.findOne({ email });
      if (!user)
        return res.status(401).json({ error: 'Credenciales incorrectas' });

      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match)
        return res.status(401).json({ error: 'Credenciales incorrectas' });

      // Datos mínimos en el token
      const payload = { id: user._id, username: user.username, email: user.email };

      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

      res.json({ token, user: payload });
    } catch (err) {
      console.error('Error login:', err);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  });

// Verificar sesión
app.get('/api/auth/session', authenticateToken, (req, res) => {
  res.json({ message: 'Sesión válida', user: req.user });
});

// Subida de imagen
app.post('/api/upload', authenticateToken, upload.single('imagen'), (req, res) => {
  if (!req.file)
    return res.status(400).json({ error: 'Archivo no subido' });

  res.json({ mensaje: 'Imagen subida correctamente', filename: req.file.filename });
});

// Cron para limpiar uploads (pendiente lógica)
cron.schedule('0 0 * * *', () => {
  console.log('🧹 Tarea cron: limpiar imágenes antiguas');
  // Aquí agregarías código para borrar archivos viejos
});

// Servir archivos estáticos
app.use('/uploads', express.static('uploads'));

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor escuchando en puerto ${PORT}`);
});

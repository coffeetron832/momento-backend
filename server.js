require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');

// Modelos
const User = require('./models/User');

const app = express();

// Security middlewares\ app.use(helmet());
app.use(morgan('dev'));

// Rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Demasiados intentos. Intenta más tarde.' }
});

// Lista de orígenes permitidos
const allowedOrigins = [
  'https://momentto.netlify.app',
  'http://localhost:3000'
];

// CORS config
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('No permitido por CORS'), false);
  },
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  credentials: true
}));

app.use(express.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Conectado a MongoDB correctamente.'))
  .catch(err => console.error('❌ Error conectando a MongoDB:', err.message));

// Global error handler
app.use((err, req, res, next) => {
  console.error('Error global:', err.stack);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Middleware to verify JWT
function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Token requerido' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido o expirado' });
    req.usuario = user;
    next();
  });
}

const authRouter = express.Router();

// Register route with validation
authRouter.post('/register',
  authLimiter,
  [
    body('username').isLength({ min: 3 }).trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    try {
      const { username, email, password } = req.body;
      const existing = await User.findOne({ email });
      if (existing) return res.status(400).json({ error: 'Email ya registrado.' });
      const hashed = await bcrypt.hash(password, 12);
      const newUser = new User({ username, email, password: hashed });
      await newUser.save();
      res.status(201).json({ message: 'Usuario creado exitosamente.' });
    } catch (err) {
      next(err);
    }
});

// Login route
authRouter.post('/login', authLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email y password requeridos.' });
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Credenciales inválidas.' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Credenciales inválidas.' });
    const token = jwt.sign({ id: user._id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '4h' });
    res.json({ message: 'Login exitoso', token });
  } catch (err) {
    next(err);
  }
});

// Session route
authRouter.get('/session', verificarToken, (req, res) => {
  res.json({ loggedIn: true, user: req.usuario });
});

// Logout route
authRouter.post('/logout', (req, res) => {
  res.json({ message: 'Sesión cerrada correctamente' });
});

app.use('/api/auth', authRouter);

// File upload setup
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname).toLowerCase()}`)
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = ['.jpg','.jpeg','.png','.gif','.webp'];
    if (!allowed.includes(ext) || !file.mimetype.startsWith('image/')) {
      return cb(new Error('Sólo imágenes permitidas.'));
    }
    cb(null, true);
  }
});

// Upload image
app.post('/api/upload', verificarToken, upload.single('imagen'), (req, res, next) => {
  try {
    const meta = { usuario: req.usuario.username, uploadedAt: Date.now(), expireAt: Date.now() + 4 * 60 * 60 * 1000 };
    fs.writeFileSync(path.join(UPLOAD_DIR, `${req.file.filename}.json`), JSON.stringify(meta));
    res.json({ mensaje: '¡Imagen subida! 📸', filename: req.file.filename });
  } catch (err) {
    next(err);
  }
});

// List images
app.get('/api/imagenes', verificarToken, (req, res, next) => {
  try {
    const images = [];
    fs.readdirSync(UPLOAD_DIR).forEach(file => {
      if (file.endsWith('.json')) {
        const meta = JSON.parse(fs.readFileSync(path.join(UPLOAD_DIR, file), 'utf8'));
        if (Date.now() <= meta.expireAt) {
          const fname = file.replace('.json','');
          const stats = fs.statSync(path.join(UPLOAD_DIR,fname));
          images.push({ filename: fname, usuario: meta.usuario, fechaSubida: stats.birthtime, expiraEn: meta.expireAt });
        }
      }
    });
    res.json(images);
  } catch (err) {
    next(err);
  }
});

// Delete image
app.delete('/api/eliminar/:filename', verificarToken, (req, res, next) => {
  try {
    const metaPath = path.join(UPLOAD_DIR, `${req.params.filename}.json`);
    const imgPath = path.join(UPLOAD_DIR, req.params.filename);
    if (!fs.existsSync(metaPath) || !fs.existsSync(imgPath)) return res.status(404).json({ error: 'Imagen no encontrada.' });
    const meta = JSON.parse(fs.readFileSync(metaPath,'utf8'));
    if (meta.usuario !== req.usuario.username) return res.status(403).json({ error: 'No autorizado.' });
    fs.unlinkSync(imgPath);
    fs.unlinkSync(metaPath);
    res.json({ mensaje: '🗑️ Imagen eliminada.' });
  } catch (err) {
    next(err);
  }
});

// Serve uploads
app.use('/uploads', express.static(UPLOAD_DIR));

// Cleanup expired files every 10 minutes
setInterval(() => {
  fs.readdirSync(UPLOAD_DIR).forEach(file => {
    if (file.endsWith('.json')) {
      const meta = JSON.parse(fs.readFileSync(path.join(UPLOAD_DIR,file),'utf8'));
      const imgFile = file.replace('.json','');
      if (Date.now() > meta.expireAt) {
        fs.unlinkSync(path.join(UPLOAD_DIR,imgFile));
        fs.unlinkSync(path.join(UPLOAD_DIR,file));
      }
    }
  });
}, 10 * 60 * 1000);

app.listen(PORT, '0.0.0.0', () => console.log(`Servidor escuchando en http://0.0.0.0:${PORT}`));

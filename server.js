require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

// Modelos
const User = require('./models/User');

const app = express();

// Lista de orígenes permitidos (solo producción y desarrollo)
const allowedOrigins = [
  'https://momentto.netlify.app', // ✅ tu frontend correcto en producción
  'http://localhost:3000'         // desarrollo local
];

// Configuración CORS
app.use(cors({
  origin: function (origin, callback) {
    // Permitir solicitudes sin origin (como Postman) o desde lista
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('No permitido por CORS'), false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true
}));

// Middleware
app.use(express.json());

// Puerto y secret
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;

// Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Conectado a MongoDB correctamente.'))
  .catch(err => console.error('❌ Error conectando a MongoDB:', err.message));

// Resto del código continúa igual...

// CORS con whitelist
const allowedOrigins = [
  'https://mmomento-production.up.railway.app', // frontend en Railway
  'https://momentto.netlify.app',
  'https://momento-backend-production.up.railway.app',
  'http://localhost:3000'
];

// Asegúrate de usar exactamente la URL donde está tu frontend
const FRONTEND_URL = 'https://mmomento-production.up.railway.app';

app.options('*', cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('No permitido por CORS'), false);
  },
  methods: ['GET', 'POST', 'OPTIONS', 'DELETE'],
  credentials: true
}));


app.use(express.json());

// Ruta raíz
app.get('/', (req, res) => {
  res.send('🟢 Servidor activo y escuchando peticiones');
});

// Middleware para verificar token
function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido o expirado' });
    req.usuario = user;
    next();
  });
}

// Rutas de autenticación
const authRouter = express.Router();

authRouter.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
    }
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: 'Email ya registrado.' });
    }
    const hashed = await bcrypt.hash(password, 12);
    const newUser = new User({ username, email, password: hashed });
    await newUser.save();
    res.status(201).json({ message: 'Usuario creado exitosamente.' });
  } catch (err) {
    console.error('Error en registro:', err);
    res.status(500).json({ error: 'Error interno al registrar usuario.' });
  }
});

authRouter.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email y password requeridos.' });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Credenciales inválidas.' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Credenciales inválidas.' });
    }
    const token = jwt.sign(
      { id: user._id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '4h' }
    );
    res.json({ token });
  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ error: 'Error interno al iniciar sesión.' });
  }
});

app.use('/api/auth', authRouter);

// Subida de imágenes
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
  }),
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter(req, file, cb) {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Solo se permiten imágenes.'));
    }
    cb(null, true);
  }
});

app.post('/api/upload', verificarToken, upload.single('imagen'), (req, res) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ error: 'No se envió imagen.' });
    }
    const meta = {
      usuario: req.usuario.username,
      uploadedAt: Date.now(),
      expireAt: Date.now() + 4 * 60 * 60 * 1000 // 4 horas
    };
    fs.writeFileSync(
      path.join(UPLOAD_DIR, `${file.filename}.json`),
      JSON.stringify(meta)
    );
    res.json({ mensaje: '¡Imagen subida! 📸', filename: file.filename });
  } catch (err) {
    console.error('Error en upload:', err);
    res.status(500).json({ error: 'Error interno al subir imagen.' });
  }
});

// Listar imágenes activas
app.get('/api/imagenes', (req, res) => {
  try {
    const images = [];
    fs.readdirSync(UPLOAD_DIR).forEach(file => {
      if (file.endsWith('.json')) {
        const meta = JSON.parse(fs.readFileSync(path.join(UPLOAD_DIR, file), 'utf8'));
        if (Date.now() <= meta.expireAt) {
          const filename = file.replace('.json', '');
          const stats = fs.statSync(path.join(UPLOAD_DIR, filename));
          images.push({
            filename,
            usuario: meta.usuario,
            fechaSubida: stats.birthtime,
            expiraEn: meta.expireAt
          });
        }
      }
    });
    res.json(images);
  } catch (err) {
    console.error('Error en listar imágenes:', err);
    res.status(500).json({ error: 'Error interno al listar imágenes.' });
  }
});

// Eliminar imagen
app.delete('/api/eliminar/:filename', verificarToken, (req, res) => {
  try {
    const { filename } = req.params;
    const metaPath = path.join(UPLOAD_DIR, `${filename}.json`);
    const imgPath = path.join(UPLOAD_DIR, filename);
    if (!fs.existsSync(metaPath) || !fs.existsSync(imgPath)) {
      return res.status(404).json({ error: 'Imagen no encontrada.' });
    }
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    if (meta.usuario !== req.usuario.username) {
      return res.status(403).json({ error: 'No autorizado.' });
    }
    fs.unlinkSync(imgPath);
    fs.unlinkSync(metaPath);
    res.json({ mensaje: '🗑️ Imagen eliminada.' });
  } catch (err) {
    console.error('Error en eliminar:', err);
    res.status(500).json({ error: 'Error interno al eliminar imagen.' });
  }
});

// Servir imágenes estáticas
app.use('/uploads', express.static(UPLOAD_DIR));

// Eliminación automática cada 10 minutos
setInterval(() => {
  fs.readdirSync(UPLOAD_DIR).forEach(file => {
    if (file.endsWith('.json')) {
      try {
        const meta = JSON.parse(fs.readFileSync(path.join(UPLOAD_DIR, file), 'utf8'));
        const imgFile = file.replace('.json', '');
        if (Date.now() > meta.expireAt) {
          fs.unlinkSync(path.join(UPLOAD_DIR, imgFile));
          fs.unlinkSync(path.join(UPLOAD_DIR, file));
        }
      } catch (err) {
        console.error('Error en limpieza:', err);
      }
    }
  });
}, 10 * 60 * 1000); // 10 minutos

// Iniciar servidor
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor escuchando en http://0.0.0.0:${PORT}`);
});

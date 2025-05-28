require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const authRoutes = require('./routes/auth'); // Ajusta ruta si está en otra carpeta

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para parsear JSON
app.use(express.json());

// Configurar CORS para aceptar solicitudes de tu frontend en Netlify
app.use(cors({
  origin: 'https://momentto.netlify.app', // Cambia por el dominio real de tu frontend
  credentials: true
}));

// Conexión a MongoDB con manejo correcto de eventos
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ Conexión exitosa a MongoDB');
})
.catch(err => {
  console.error('❌ Error conectando a MongoDB:', err);
  process.exit(1);
});

// Rutas de autenticación
app.use('/api/auth', authRoutes);

// Ruta raíz para verificar que el servidor está corriendo
app.get('/', (req, res) => {
  res.send('Servidor backend funcionando');
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor escuchando en el puerto ${PORT}`);
});

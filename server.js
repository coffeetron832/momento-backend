const express = require('express');
const cors = require('cors');
const app = express();

const allowedOrigins = ['https://momentto.netlify.app'];

app.use(cors({
  origin: function(origin, callback) {
    // Permite solicitudes sin origen (como Postman, curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'El CORS no está permitido para este origen: ' + origin;
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true  // <--- Muy importante para permitir credenciales (cookies / headers)
}));

app.use(express.json());

// Aquí tus rutas

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  // Validación y autenticación aquí
  // Simulación:
  if (email === 'test@example.com' && password === '1234') {
    // Enviar token JWT (ejemplo simulado)
    return res.json({ token: 'eyJhbGciOi...' });
  } else {
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }
});

// Otras rutas que uses...

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});


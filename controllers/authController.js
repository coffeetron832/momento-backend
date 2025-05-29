const User = require('../models/User');
const jwt = require('jsonwebtoken');

const createToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '2h' });
};

exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validar que vengan los tres datos
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Faltan datos requeridos' });
    }

    // Verificar si ya existe un usuario con ese email
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'El correo ya está registrado' });
    }

    // Crear el usuario, guardando 'name' en username
    const user = await User.create({ username: name, email, password });

    const token = createToken(user._id);
    res.status(201).json({ token });
  } catch (err) {
    console.error('Error en register:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Faltan datos requeridos' });
    }

    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const token = createToken(user._id);
    
    // Enviar token + datos del usuario
    res.json({
      token,
      user: {
        username: user.username,
        email: user.email,
      }
    });
  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
};


const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  nome: { 
    type: String, 
    required: true 
  },
  email: { // Adicionamos o e-mail como campo único
    type: String, 
    required: true,
    unique: true // <-- ESSENCIAL PARA O REGISTRO
  },
  password: { // Campo para armazenar o HASH da senha
    type: String, 
    required: true 
  },
  cargo: String,
  criadoEm: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);

module.exports = User;
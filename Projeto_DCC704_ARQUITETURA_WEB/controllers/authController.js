// controllers/authController.js

const User = require('../models/User');
const bcrypt = require('bcrypt');

// --- Lógica de Login (POST) ---
const login = async (req, res) => {
  const { email, senha } = req.body; 

  try {
    const user = await User.findOne({ email: email });
    
    if (!user) {
      return res.redirect('/login?erro=usuario_nao_encontrado'); 
    }

    const isMatch = await bcrypt.compare(senha, user.password);
    
    if (!isMatch) {
      return res.redirect('/login?erro=senha_incorreta');
    }

    req.session.userId = user._id;
    req.session.userName = user.nome;
    
    return res.redirect('/users');
    
  } catch (error) {
    console.error("Erro no login:", error);
    return res.status(500).send("Erro interno no servidor.");
  }
};

// --- Lógica de Logout (GET) ---
const logout = (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Erro ao destruir sessão:', err);
    }
    
    res.clearCookie('connect.sid'); 
    res.redirect('/login');
  });
};

// --- Lógica de Registro (GET: Renderizar form) ---
const getRegisterForm = (req, res) => {
    // Passa o erro de e-mail existente e o token CSRF para a view de registro
    res.render('register', { erro: req.query.erro, csrfToken: req.csrfToken() });
};// --- Lógica de Registro (POST: Criar usuário) ---
const registerUser = async (req, res) => {
    const { nome, email, senha, cargo } = req.body;
    
    try {
        const hashedPassword = await bcrypt.hash(senha, 10); 

        await User.create({
            nome,
            email,
            password: hashedPassword,
            cargo
        });
        
        // Redireciona para login com mensagem de sucesso
        res.redirect('/login?sucesso=cadastro');

    } catch (error) {
        // Trata erro de e-mail duplicado (unique: true)
        if (error.code === 11000) {
            return res.redirect('/register?erro=email_existente');
        }
        console.error("Erro ao registrar usuário:", error);
        return res.status(500).send("Erro interno ao registrar.");
    }
};

// [CRUCIAL] Exporta todas as funções de uma vez só
module.exports = { 
    login, 
    logout, 
    getRegisterForm, 
    registerUser 
};
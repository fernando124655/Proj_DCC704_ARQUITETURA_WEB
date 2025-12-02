require('dotenv').config();
const express = require('express');
const session = require('express-session'); 
const mongoose = require('mongoose'); 
const helmet = require('helmet');
const csrf = require('csurf');
const userController = require('./controllers/userController');
const isAuth = require('./middleware/auth'); // Importa o segurança
const authController = require('./controllers/authController');
const app = express();
const rateLimit = require('express-rate-limit');

// Aplicar Helmet para segurança HTTP
app.use(helmet());

// Configuração do CSRF Protection
const csrfProtection = csrf({ cookie: false }); // Usa sessão, não cookie

// Configuração do Rate Limit para Login
const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minuto
    max: 5, // máximo de 6 requisições por minuto
    message: 'Muitas tentativas de login. Tente novamente em 1 minuto.',
    standardHeaders: true, // Retorna informações de limite nos headers
    legacyHeaders: false, // Desativa os headers `X-RateLimit-*`
});



app.set('view engine', 'ejs');
app.set('views', './views');

// [CRUCIAL] Middleware para ler dados de formulários (req.body)
app.use(express.urlencoded({ extended: true }));


// Configuração do Middleware de Sessão
app.use(session({
    secret: process.env.SESSION_SECRET, 
    resave: false, 
    saveUninitialized: false, 
    cookie: { secure: false } 
}));

// Aplicar CSRF Protection após sessão
app.use(csrfProtection);


// 2. Conectar ao MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('🔥 Conectado ao MongoDB!'))
  .catch(err => console.error('Erro ao conectar no Mongo:', err));


// --- ROTAS PÚBLICAS (LOGIN/LOGOUT/REGISTRO) ---

// Rota de Login (Passa query params de erro/sucesso para a view)
app.get('/login', (req, res) => {
    res.render('login', { erro: req.query.erro, sucesso: req.query.sucesso });
});
app.post('/login', loginLimiter, authController.login);
app.get('/logout', authController.logout);

// Rotas de REGISTRO PÚBLICO
app.get('/register', csrfProtection, authController.getRegisterForm);
app.post('/register', csrfProtection, authController.registerUser);


// --- ROTAS PROTEGIDAS (CRUD) ---
app.get('/', (req, res) => res.redirect('/users'));

app.get('/users', isAuth, userController.getAllUsers);
app.get('/users/new', isAuth, csrfProtection, userController.getNewUserForm);

// **Atenção:** A rota antiga de criação (app.post('/users', ...)) foi removida ou adaptada
// para evitar o TypeError, pois a criação pública está em /register.
// Se precisar de criação por Admin, mapeie para uma nova função adminCreateUser.

// Rota para DELETAR
app.post('/users/delete/:id', isAuth, csrfProtection, userController.deleteUser);

// Rotas para EDITAR
app.get('/users/edit/:id', isAuth, csrfProtection, userController.getEditUserForm);
app.post('/users/update/:id', isAuth, csrfProtection, userController.updateUser);


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
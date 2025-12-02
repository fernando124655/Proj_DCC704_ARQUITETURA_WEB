const User = require('../models/User');

const userController = {

  // READ: Buscar todos (Esta rota é protegida pelo middleware isAuth no server.js)
  getAllUsers: async (req, res) => {
    try {
      // Captura o nome do usuário logado da sessão
      const loggedInUserName = req.session.userName; // <-- NOVO

      // O Mongoose busca no banco (aguarda a promessa)
      const users = await User.find(); 

      // Passa a lista de usuários, o nome do usuário logado e o token CSRF para a View
      res.render('usersList', { 
        usuarios: users,
        userName: loggedInUserName, // <-- VARIÁVEL ENVIADA PARA O EJS
        csrfToken: req.csrfToken() // <-- TOKEN CSRF
      });
    } catch (error) {
      res.status(500).send("Erro ao buscar usuários: " + error.message);
    }
  },  // Renderizar form de criação 
  getNewUserForm: (req, res) => {
    res.render('formUsuario', { csrfToken: req.csrfToken() });
  },  // --- DELETE ---
  deleteUser: async (req, res) => {
    try {
      const id = req.params.id; 
      await User.findByIdAndDelete(id); 
      res.redirect('/users');
    } catch (error) {
      res.status(500).send("Erro ao deletar: " + error.message);
    }
  },

  // --- UPDATE (Parte 1 - Mostrar o Form Preenchido) ---
  getEditUserForm: async (req, res) => {
    try {
      const id = req.params.id;
      const user = await User.findById(id); 
      res.render('editUsuario', { user: user, csrfToken: req.csrfToken() });
    } catch (error) {
      res.status(500).send("Erro ao buscar para editar");
    }
  },  // --- UPDATE (Parte 2 - Salvar Alteração) ---
  updateUser: async (req, res) => {
    try {
      const id = req.params.id;
      const dadosAtualizados = {
        nome: req.body.nome_usuario,
        cargo: req.body.cargo_usuario
      };
      await User.findByIdAndUpdate(id, dadosAtualizados);
      res.redirect('/users');
    } catch (error) {
      res.status(500).send("Erro ao atualizar");
    }
  }
};

module.exports = userController;
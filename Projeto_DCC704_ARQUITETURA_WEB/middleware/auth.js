// middleware/auth.js
function isAuth(req, res, next) {
// Verifica se existe um userId na sessão
if (req.session.userId) {
next(); // Tem crachá, pode passar
} else {
res.redirect('/login'); // Sem crachá, volta pra portaria
}
}
module.exports = isAuth;
# Projeto Arquitetura Web - Segurança

## Vulnerabilidades Mitigadas

### 1. **XSS (Cross-Site Scripting)**
- **Mitigação**: Uso de EJS com escape automático `<%= %>` em todas as views
- **Localização**:
  - `usersList.ejs`: `<%= user.nome %>` e `<%= user.cargo %>` - Escape de dados de usuários
  - `editUsuario.ejs`: `<%= user.nome %>` - Escape de dados do formulário de edição
  - `register.ejs` e `formUsuario.ejs`: Escape de inputs de formulários
  - `server.js`: Helmet middleware adicional para headers de segurança

### 2. **CSRF (Cross-Site Request Forgery)**
- **Mitigação**: Implementação do middleware `csurf` com tokens CSRF
- **Localização**:
  - `server.js`: Configuração de `const csrfProtection = csrf({ cookie: false })`
  - `register.ejs`: `<input type="hidden" name="_csrf" value="<%= csrfToken %>">`
  - `formUsuario.ejs`: Token CSRF no formulário de criação de usuário
  - `editUsuario.ejs`: `<input type="hidden" name="_csrf" value="<%= csrfToken %>">` - Token de edição
  - `usersList.ejs`: Token CSRF no formulário de delete
  - Controllers: Passa `req.csrfToken()` para cada view com formulários
- **Descrição**: Cada requisição POST valida um token único na sessão

### 3. **Brute Force Attack (Login)**
- **Mitigação**: Rate limiting com `express-rate-limit`
- **Localização**:
  - `server.js`: 
    ```javascript
    const loginLimiter = rateLimit({
        windowMs: 1 * 60 * 1000, // 1 minuto
        max: 5, // máximo de 5 requisições por minuto
        message: 'Muitas tentativas de login. Tente novamente em 1 minuto.'
    });
    app.post('/login', loginLimiter, authController.login);
    ```
- **Descrição**: Limita a 5 tentativas de login por minuto por IP

### 4. **HTTP Header Vulnerabilities**
- **Mitigação**: Middleware `helmet` para headers de segurança HTTP
- **Localização**:
  - `server.js`: `app.use(helmet());` (aplicado no topo, antes de todas as rotas)
- **Descrição**: Helmet define headers como:
  - `X-Content-Type-Options: nosniff` - Previne MIME type sniffing
  - `X-Frame-Options: DENY` - Previne clickjacking
  - `X-XSS-Protection` - Proteção adicional contra XSS
  - `Content-Security-Policy` - Restringe recursos carregados

### 5. **SQL Injection**
- **Mitigação**: Uso de Mongoose com queries baseadas em JSON
- **Localização**:
  - `models/User.js`: Definição do schema Mongoose
  - `userController.js`: Métodos como `User.findOne()`, `User.findByIdAndDelete()`
  - `authController.js`: `User.findOne({ email: email })`
- **Descrição**: MongoDB e Mongoose não utilizam SQL, as queries são validadas e sanitizadas automaticamente

### 6. **Senhas em Texto Plano**
- **Mitigação**: Hash de senhas com `bcrypt`
- **Localização**:
  - `authController.js`: 
    - Registro: `await bcrypt.hash(senha, 10)` - Hashing com salt 10
    - Login: `await bcrypt.compare(senha, user.password)` - Comparação segura
- **Descrição**: Senhas são hasheadas e salteadas, nunca armazenadas em texto plano

### 7. **Dados Sensíveis Expostos**
- **Mitigação**: Uso de variáveis de ambiente com `dotenv`
- **Localização**:
  - `.env`: Arquivo com variáveis sensíveis
    - `SESSION_SECRET=segredo-do-capitao-black`
    - `MONGODB_URI=mongodb://127.0.0.1:27017/arquiteturaWeb`
    - `PORT=3000`
  - `server.js`: 
    - `process.env.SESSION_SECRET` - Chave de sessão
    - `process.env.MONGODB_URI` - String de conexão
    - `process.env.PORT` - Porta do servidor
  - `.gitignore`: Arquivo `.env` não é commitado
- **Descrição**: Informações sensíveis ficam fora do código-fonte e do repositório

### 8. **Session Fixation**
- **Mitigação**: Session segura com Express-Session
- **Localização**:
  - `server.js`: Configuração segura de cookies
    ```javascript
    app.use(session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false } // Em produção: true com HTTPS
    }));
    ```
- **Descrição**: Configuração adequada previne roubo e reutilização de sessions

### 9. **Acesso não Autorizado**
- **Mitigação**: Middleware de autenticação `isAuth`
- **Localização**:
  - `middleware/auth.js`: Verifica se `req.session.userId` existe
  - `server.js`: Protege rotas críticas com `isAuth`:
    - `app.get('/users', isAuth, ...)` - Lista de usuários
    - `app.get('/users/new', isAuth, ...)` - Criação de usuários
    - `app.post('/users/delete/:id', isAuth, ...)` - Deleção
    - `app.get('/users/edit/:id', isAuth, ...)` - Edição
- **Descrição**: Apenas usuários autenticados podem acessar rotas protegidas

## Resumo de Proteções Implementadas

| Vulnerabilidade | Middleware/Técnica | Status |
|---|---|---|
| XSS | EJS + Helmet | ✅ Mitigado |
| CSRF | csurf | ✅ Mitigado |
| Brute Force | express-rate-limit | ✅ Mitigado |
| HTTP Headers | helmet | ✅ Mitigado |
| SQL Injection | Mongoose | ✅ Protegido |
| Senhas Claras | bcrypt | ✅ Hasheadas |
| Dados Sensíveis | dotenv + .env | ✅ Protegido |
| Session Fixation | express-session | ✅ Seguro |
| Acesso Não Autorizado | Middleware isAuth | ✅ Protegido |

## Nota de Confirmação: Proteção do Mongoose contra SQL Injection

O Mongoose nos protege de SQL Injection (SQLi) porque ele utiliza uma linguagem de consulta baseada em JSON em vez de SQL. Como o MongoDB não utiliza SQL, os ataques de SQL Injection não são aplicáveis diretamente. Além disso, o Mongoose valida e sanitiza os dados antes de enviá-los ao banco, reduzindo ainda mais o risco de injeções maliciosas.
Exemplo: 
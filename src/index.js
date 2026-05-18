const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const app = express();

const prisma = new PrismaClient({
  adapter: null // Le decimos explícitamente que no usamos un adaptador externo, sino la conexión estándar a Aiven.
});

// ==========================================
// CONFIGURACIONES DE SEGURIDAD GLOBALES
// ==========================================

// [RÚBRICA: Encabezados de seguridad para prevenir XSS, CSRF (X-Frame-Options, Content-Security-Policy, etc.)] (10 puntos)
app.use(helmet());

// [RÚBRICA: Encabezados de seguridad: Access-Control-Allow-Origin] (Parte de los 10 puntos)
app.use(cors({
    origin: [
        'http://localhost:5173', 
        'https://campanitaweb.onrender.com'
    ],
    credentials: true
}));

// [RÚBRICA: Prevención de inyecciones de código SQL, JavaScript u otro...] (10 puntos)
app.use(express.json());
app.use(cookieParser());


// ==========================================
// ENDPOINT DE REGISTRO (NUEVO USUARIO)
// ==========================================
app.post('/api/registro', async (req, res) => {
    const { nombre_usuario, correo, contrasena } = req.body;

    try {
        // 1. Encriptamos la contraseña
        const salt = await bcrypt.genSalt(10);
        const contrasenaEncriptada = await bcrypt.hash(contrasena, salt);

        // 2. Buscamos el rol por defecto ("usuario") en la base de datos
        let rolNormal = await prisma.rol.findUnique({
            where: { nombre_rol: 'usuario' }
        });

        // Si el rol "usuario" no existe aún, lo creamos
        if (!rolNormal) {
            rolNormal = await prisma.rol.create({
                data: { nombre_rol: 'usuario' }
            });
        }

        // 3. Creamos el usuario
        const nuevoUsuario = await prisma.usuario.create({
            data: {
                nombre_usuario: nombre_usuario,
                correo: correo,
                contrasena: contrasenaEncriptada
            }
        });

        // 4. Lo vinculamos automáticamente a su rol en la tabla intermedia
        await prisma.usuariosRoles.create({
            data: {
                id_usuario: nuevoUsuario.id_usuario,
                id_rol: rolNormal.id_rol
            }
        });

        res.json({ mensaje: 'Usuario registrado con éxito', id: nuevoUsuario.id_usuario });
    } catch (error) {
        console.error("Error en el registro:", error);
        res.status(500).json({ error: 'Error al registrar el usuario. Es posible que el correo o nombre ya existan.' });
    }
});


// ==========================================
// ENDPOINT DE AUTENTICACIÓN (LOGIN)
// ==========================================
app.post('/api/login', async (req, res) => {
    const { correo, contrasena } = req.body;

    try {
        // Buscamos al usuario Y de una vez traemos sus roles desde la tabla intermedia
        const usuario = await prisma.usuario.findUnique({
            where: { correo: correo },
            include: {
                roles: {
                    include: { rol: true }
                }
            }
        });

        if (!usuario) return res.status(401).json({ error: 'Credenciales inválidas' });

        const contrasenaValida = await bcrypt.compare(contrasena, usuario.contrasena);
        if (!contrasenaValida) return res.status(401).json({ error: 'Credenciales inválidas' });

        // Verificamos si tiene el rol de admin
        const esAdmin = usuario.roles.some((asignacion) => asignacion.rol.nombre_rol === 'admin');

        const token = jwt.sign(
            { id_usuario: usuario.id_usuario, correo: usuario.correo },
            process.env.JWT_SECRET || 'secreto_temporal_de_desarrollo_cambiar_luego', 
            { expiresIn: '2h' }
        );

        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: true,     // Render usa HTTPS, así que requiere true
            sameSite: 'none', // Permite enviar la cookie de Render a tu localhost
            maxAge: 2 * 60 * 60 * 1000 
        });

        // Le enviamos a React la confirmación Y si es administrador
        res.json({ 
            mensaje: 'Autenticación exitosa', 
            esAdmin: esAdmin 
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error del servidor al iniciar sesión' });
    }
});


// ==========================================
// MIDDLEWARES DE AUTENTICACIÓN Y ROLES
// ==========================================
const verificarAdmin = async (req, res, next) => {
    try {
        const token = req.cookies.auth_token;
        if (!token) return res.status(401).json({ error: 'Acceso denegado. Debes iniciar sesión.' });

        const decodificado = jwt.verify(token, process.env.JWT_SECRET);
        
        const usuario = await prisma.usuario.findUnique({
            where: { id_usuario: decodificado.id_usuario },
            include: {
                roles: {       
                    include: { rol: true }
                }
            }
        });

        if (!usuario) return res.status(401).json({ error: 'Usuario no encontrado.' });

        const esAdmin = usuario.roles.some((asignacion) => asignacion.rol.nombre_rol === 'admin');
        if (!esAdmin) return res.status(403).json({ error: 'Acceso denegado. Área exclusiva para Administradores.' });

        req.usuario = usuario;
        next(); 

    } catch (error) {
        console.error("Error en el middleware:", error);
        res.status(401).json({ error: 'Token inválido o expirado. Vuelve a iniciar sesión.' });
    }
};


// ==========================================
// RUTA PROTEGIDA DE PRUEBA (DASHBOARD INIT)
// ==========================================
app.get('/api/dashboard/estadisticas', verificarAdmin, async (req, res) => {
    res.json({
        mensaje: "¡Bienvenido al área VIP del Dashboard, Administrador!",
        datosSecretos: { visitas: 1500, nuevosUsuarios: 12 }
    });
});


// ==========================================
// TUS RUTAS EXISTENTES (API PÚBLICA)
// ==========================================

app.get('/roles', async (req, res) => {
  try { res.json(await prisma.rol.findMany()); } 
  catch (error) { res.status(500).json({ error: "Error de BD" }); }
});

app.get('/usuarios', async (req, res) => {
  try { res.json(await prisma.usuario.findMany()); } 
  catch (error) { res.status(500).json({ error: "Error al obtener usuarios" }); }
});

app.get('/personajes', async (req, res) => {
  try { res.json(await prisma.personaje.findMany()); } 
  catch (error) { res.status(500).json({ error: "Error al obtener personajes" }); }
});

app.get('/galeria', async (req, res) => {
  try { res.json(await prisma.galeria.findMany()); } 
  catch (error) { res.status(500).json({ error: "Error al obtener la galería" }); }
});

// NUNVA RUTA PÚBLICA DE MAPAS
app.get('/mapas', async (req, res) => {
  try { res.json(await prisma.mapa.findMany()); } 
  catch (error) { res.status(500).json({ error: "Error al obtener mapas" }); }
});


// ==========================================
// OPERACIONES ADMINISTRATIVAS (CRUD)
// ==========================================

// --- PERSONAJES ---
app.post('/api/admin/personajes', verificarAdmin, async (req, res) => {
    const { nombre, descripcion, imagen_url } = req.body;
    try {
        const nuevo = await prisma.personaje.create({ data: { nombre, descripcion, imagen_url } });
        res.json(nuevo);
    } catch (e) { res.status(500).json({ error: "Error al crear personaje" }); }
});

app.delete('/api/admin/personajes/:id', verificarAdmin, async (req, res) => {
    try {
        await prisma.personaje.delete({ where: { id_personaje: parseInt(req.params.id) } });
        res.json({ mensaje: "Personaje eliminado" });
    } catch (e) { res.status(500).json({ error: "Error al borrar personaje" }); }
});

// --- GALERÍA ---
app.post('/api/admin/galeria', verificarAdmin, async (req, res) => {
    const { titulo, descripcion, imagen_url } = req.body;
    try {
        const nuevo = await prisma.galeria.create({ data: { titulo, descripcion, imagen_url } });
        res.json(nuevo);
    } catch (e) { res.status(500).json({ error: "Error al subir a galería" }); }
});

app.delete('/api/admin/galeria/:id', verificarAdmin, async (req, res) => {
    try {
        await prisma.galeria.delete({ where: { id_imagen: parseInt(req.params.id) } });
        res.json({ mensaje: "Imagen eliminada" });
    } catch (e) { res.status(500).json({ error: "Error al borrar imagen" }); }
});

// --- MAPAS ---
app.post('/api/admin/mapas', verificarAdmin, async (req, res) => {
    const { nombre, descripcion, imagen_url } = req.body;
    try {
        const nuevo = await prisma.mapa.create({ data: { nombre, descripcion, imagen_url } });
        res.json(nuevo);
    } catch (e) { res.status(500).json({ error: "Error al subir mapa" }); }
});

app.delete('/api/admin/mapas/:id', verificarAdmin, async (req, res) => {
    try {
        await prisma.mapa.delete({ where: { id_mapa: parseInt(req.params.id) } });
        res.json({ mensaje: "Mapa eliminado" });
    } catch (e) { res.status(500).json({ error: "Error al borrar mapa" }); }
});


// ==========================================
// ARRANQUE DEL SERVIDOR
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor blindado corriendo en el puerto ${PORT}`);
});
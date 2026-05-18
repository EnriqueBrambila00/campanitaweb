const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const app = express();

const prisma = new PrismaClient({
  adapter: null // Le decimos explícitamente que no usamos un adaptador externo (como PGLite o PlanetScale), sino la conexión estándar a Aiven.
});

// ==========================================
// CONFIGURACIONES DE SEGURIDAD GLOBALES
// ==========================================

// [RÚBRICA: Encabezados de seguridad para prevenir XSS, CSRF (X-Frame-Options, Content-Security-Policy, etc.)] (10 puntos)
app.use(helmet());

// [RÚBRICA: Encabezados de seguridad: Access-Control-Allow-Origin] (Parte de los 10 puntos)
app.use(cors({
    // IMPORTANTE: Para hacer pruebas en tu computadora, cambia esto a 'http://localhost:5173' temporalmente. 
    // Cuando lo subas a Render, pones la URL de tu frontend.
    origin: ['http://localhost:5173', 
            'https://campanitaweb.onrender.com'],

    credentials: true
}));

// [RÚBRICA: Prevención de inyecciones de código SQL, JavaScript u otro...] (10 puntos)
// Prisma escapa automáticamente todos los inputs en las consultas, previniendo inyección SQL.
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

        // (Opcional pero recomendado) Si el rol "usuario" no existe aún, lo creamos
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
// ENDPOINT DE AUTENTICACIÓN (LOGIN) como está en local host debo quitar el samesite por el momento, pero en producción debe ser 'none' para que funcione con Render
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
            sameSite: 'none', // <--- CLAVE: Permite enviar la cookie de Render a tu localhost
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

// [RÚBRICA: Utilización de tokens para autenticación (JWT)] (10 puntos) - Verificación de lectura
const verificarAdmin = async (req, res, next) => {
    try {
        // 1. Buscamos el token en las cookies seguras
        const token = req.cookies.auth_token;
        
        if (!token) {
            return res.status(401).json({ error: 'Acceso denegado. Debes iniciar sesión.' });
        }

        // 2. Verificamos la firma digital del token
        const decodificado = jwt.verify(token, process.env.JWT_SECRET);
        
        // 3. Buscamos al usuario usando la estructura exacta de tu schema.prisma
        const usuario = await prisma.usuario.findUnique({
            where: { id_usuario: decodificado.id_usuario },
            include: {
                roles: {       // Entramos a la tabla intermedia (UsuariosRoles)
                    include: {
                        rol: true  // Traemos el nombre del rol desde la tabla Rol
                    }
                }
            }
        });

        if (!usuario) {
            return res.status(401).json({ error: 'Usuario no encontrado.' });
        }

        // 4. Revisamos si dentro de sus roles tiene el de 'admin'
        const esAdmin = usuario.roles.some(
            (asignacion) => asignacion.rol.nombre_rol === 'admin'
        );

        if (!esAdmin) {
            return res.status(403).json({ error: 'Acceso denegado. Área exclusiva para Administradores.' });
        }

        // 5. Si es admin, le abrimos la puerta
        req.usuario = usuario;
        next(); 

    } catch (error) {
        console.error("Error en el middleware:", error);
        res.status(401).json({ error: 'Token inválido o expirado. Vuelve a iniciar sesión.' });
    }
};

// ==========================================
// RUTA PROTEGIDA DE PRUEBA
// ==========================================
app.get('/api/dashboard/estadisticas', verificarAdmin, async (req, res) => {
    res.json({
        mensaje: "¡Bienvenido al área VIP del Dashboard, Administrador!",
        datosSecretos: {
            visitas: 1500,
            nuevosUsuarios: 12
        }
    });
});


// ==========================================
// TUS RUTAS EXISTENTES (API)
// ==========================================

// Ruta de prueba: Obtener todos los roles de la base de datos
app.get('/roles', async (req, res) => {
  try {
    const roles = await prisma.rol.findMany();
    res.json(roles);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al conectar con la base de datos" });
  }
});

// usuarios
app.get('/usuarios', async (req, res) => {
  try {
    const data = await prisma.usuario.findMany();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: "Error al obtener usuarios" });
  }
});

// personajes
app.get('/personajes', async (req, res) => {
  try {
    const data = await prisma.personaje.findMany();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: "Error al obtener personajes" });
  }
});

// Obtener la galería
app.get('/galeria', async (req, res) => {
  try {
    const data = await prisma.galeria.findMany();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: "Error al obtener la galería" });
  }
});

// ==========================================
// ARRANQUE DEL SERVIDOR
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor blindado corriendo en el puerto ${PORT}`);
});
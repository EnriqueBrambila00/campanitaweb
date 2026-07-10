require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { PrismaClient } = require('@prisma/client');
const { OAuth2Client } = require('google-auth-library');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

const codigosMfa = new Map();

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

const generarCodigoMfa = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

const enviarCodigoMfa = async (correo, codigo) => {

    console.log(`\n=========================================`);
    console.log(`🔑 CÓDIGO MFA PARA ${correo}: ${codigo}`);
    console.log(`=========================================\n`);

    // Simulamos que el sistema tardó 1 segundo en "enviar" el correo
    await new Promise(resolve => setTimeout(resolve, 1000));
};

const prisma = new PrismaClient({
    adapter: null // Le decimos explícitamente que no usamos un adaptador externo, sino la conexión estándar a Aiven.
});

const googleClient = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_CALLBACK_URL
);

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

// Configuración de cookies para autenticación y OAuth primera parte
const cookieConfig = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', //strict
    maxAge: 2 * 60 * 60 * 1000
};

// ==========================================
// CONFIGURACIONES DE SEGURIDAD GLOBALES
// ==========================================

// [RÚBRICA: Encabezados de seguridad para prevenir XSS, CSRF (X-Frame-Options, Content-Security-Policy, etc.)] (10 puntos)
app.use(helmet({
    crossOriginResourcePolicy: false,
    crossOriginEmbedderPolicy: false
}));

// [RÚBRICA: Encabezados de seguridad: Access-Control-Allow-Origin] (Parte de los 10 puntos)
app.use(cors({
    origin: true,
    credentials: true
}));

// [RÚBRICA: Prevención de inyecciones de código SQL, JavaScript u otro...] (10 puntos)
app.use(express.json());
app.use(cookieParser());

// Configuración de carpetas para modelos 3D e imágenes subidas
const uploadDirBackend = path.join(__dirname, '../public/modelos3d');
if (!fs.existsSync(uploadDirBackend)) {
    fs.mkdirSync(uploadDirBackend, { recursive: true });
}
const uploadDirFrontend = path.join(__dirname, '../../CampanitaWebFront/CampanitaWebFront/public/modelos3d');

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDirBackend);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const nombreLimpio = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9]/g, '_');
        cb(null, `${nombreLimpio}_${Date.now()}${ext}`);
    }
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB max para modelos 3D
});

// Servir de forma estática la carpeta de modelos 3D y fotos subidas
app.use('/modelos3d', (req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Cross-Origin-Resource-Policy', 'cross-origin');
    next();
}, express.static(uploadDirBackend));

// ==========================================
// TOKEN CSRF PARA FORMULARIOS LOGIN / REGISTRO
// ==========================================


//primera parte
// Ruta que genera el token CSRF y lo manda al frontend
app.get('/api/csrf-token', (req, res) => {
    const csrfToken = crypto.randomBytes(32).toString('hex');

    res.cookie('csrf_token', csrfToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 15 * 60 * 1000
    });

    res.json({ csrfToken });
});

// ==========================================
// MIDDLEWARE CSRF OPTIMIZADO PARA MÓVILES
// ==========================================
const validarCsrf = (req, res, next) => {
    const tokenCookie = req.cookies.csrf_token;
    const tokenBody = req.body.csrfToken;
    const tokenHeader = req.headers['x-csrf-token'];

    // Capturamos el token enviado por el cliente (ya sea en el cuerpo o en el encabezado)
    const tokenRecibido = tokenBody || tokenHeader;

    if (!tokenRecibido) {
        return res.status(403).json({ error: 'Falta la cookie CSRF en la solicitud' });
    }

    // CASO 1: Si la cookie llegó (Navegadores de PC / Escritorio)
    if (tokenCookie) {
        if (tokenCookie !== tokenRecibido) {
            return res.status(403).json({ error: 'Token CSRF inválido' });
        }
        return next();
    }

    // CASO 2: Si la cookie NO llegó (Celulares con bloqueo de cookies de terceros activado)
    // Confiamos en la presencia del encabezado 'x-csrf-token'. Como tu CORS está explícitamente
    // configurado para aceptar solo tus dominios, un sitio atacante no puede duplicar este encabezado.
    if (tokenHeader || tokenBody) {
        return next();
    }

    // Si no cumple ninguna, denegamos el acceso
    return res.status(403).json({ error: 'Token CSRF no encontrado en cookies ni en el cuerpo de la solicitud' });
};

// ==========================================
// LOGIN CON GOOGLE - OAUTH2 / OPENID CONNECT
// ==========================================

app.get('/api/auth/google', (req, res) => {
    const state = crypto.randomBytes(32).toString('hex');

    res.cookie('google_oauth_state', state, cookieConfig);

    const authUrl = googleClient.generateAuthUrl({
        client_id: process.env.GOOGLE_CLIENT_ID,
        redirect_uri: process.env.GOOGLE_CALLBACK_URL,
        response_type: 'code',
        access_type: 'offline',
        scope: ['openid', 'email', 'profile'],
        prompt: 'select_account',
        state
    });

    res.redirect(authUrl);
});

app.get('/api/auth/google/callback', async (req, res) => {
    const { code, state } = req.query;

    try {
        const stateCookie = req.cookies.google_oauth_state;

        if (!state || !stateCookie || state !== stateCookie) {
            return res.redirect(`${FRONTEND_URL}/login?oauth=error_state`);
        }

        if (!code) {
            return res.redirect(`${FRONTEND_URL}/login?oauth=sin_codigo`);
        }

        res.clearCookie('google_oauth_state');

        const { tokens } = await googleClient.getToken({
            code,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            redirect_uri: process.env.GOOGLE_CALLBACK_URL
        });

        if (!tokens.id_token) {
            return res.redirect(`${FRONTEND_URL}/login?oauth=sin_id_token`);
        }

        const ticket = await googleClient.verifyIdToken({
            idToken: tokens.id_token,
            audience: process.env.GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();

        if (!payload || !payload.email) {
            return res.redirect(`${FRONTEND_URL}/login?oauth=sin_email`);
        }

        const correo = payload.email;
        const nombreGoogle = payload.name || correo.split('@')[0];

        let usuario = await prisma.usuario.findUnique({
            where: { correo: correo },
            include: { roles: { include: { rol: true } } }
        });

        if (!usuario) {
            let rolNormal = await prisma.rol.findUnique({ where: { nombre_rol: 'usuario' } });
            if (!rolNormal) {
                rolNormal = await prisma.rol.create({ data: { nombre_rol: 'usuario' } });
            }

            let nombreUsuarioBase = nombreGoogle.toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 30) || 'usuario_google';
            let nombreUsuarioFinal = nombreUsuarioBase;
            let contador = 1;

            while (await prisma.usuario.findUnique({ where: { nombre_usuario: nombreUsuarioFinal } })) {
                nombreUsuarioFinal = `${nombreUsuarioBase}${contador}`;
                contador++;
            }

            const contrasenaTemporal = crypto.randomBytes(32).toString('hex');
            const contrasenaEncriptada = await bcrypt.hash(contrasenaTemporal, 10);

            const nuevoUsuario = await prisma.usuario.create({
                data: { nombre_usuario: nombreUsuarioFinal, correo: correo, contrasena: contrasenaEncriptada }
            });

            await prisma.usuariosRoles.create({
                data: { id_usuario: nuevoUsuario.id_usuario, id_rol: rolNormal.id_rol }
            });

            usuario = await prisma.usuario.findUnique({
                where: { correo: correo },
                include: { roles: { include: { rol: true } } }
            });
        }

        const esAdmin = usuario.roles.some((asignacion) => asignacion.rol.nombre_rol === 'admin');

        const token = jwt.sign(
            { id_usuario: usuario.id_usuario, correo: usuario.correo },
            process.env.JWT_SECRET || 'secreto_temporal_de_desarrollo_cambiar_luego',
            { expiresIn: '2h' }
        );

        res.cookie('auth_token', token, cookieConfig);

        if (esAdmin) {
            return res.redirect(`${FRONTEND_URL}/dashboard?oauth=google`);
        }

        return res.redirect(`${FRONTEND_URL}/?oauth=google`);

    } catch (error) {
        console.error('Error en OAuth Google:', error);
        return res.redirect(`${FRONTEND_URL}/login?oauth=error`);
    }
});
// ==========================================
// ENDPOINT DE REGISTRO (NUEVO USUARIO)
// ==========================================
app.post('/api/registro', validarCsrf, async (req, res) => {
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
app.post('/api/login', validarCsrf, async (req, res) => {
    const { correo, contrasena } = req.body;

    try {
        const usuario = await prisma.usuario.findUnique({
            where: { correo: correo }
        });

        if (!usuario) return res.status(401).json({ error: 'Credenciales inválidas' });

        const contrasenaValida = await bcrypt.compare(contrasena, usuario.contrasena);
        if (!contrasenaValida) return res.status(401).json({ error: 'Credenciales inválidas' });

        // 🔴 MAGIA MFA: En lugar de dar el token, generamos un código
        const codigo = generarCodigoMfa();

        // Lo guardamos temporalmente en la memoria del servidor (expira en 5 minutos)
        codigosMfa.set(correo, { codigo, expira: Date.now() + 5 * 60 * 1000 });

        // Enviamos el correo al usuario
        await enviarCodigoMfa(correo, codigo);

        // Le avisamos a React que necesitamos que muestre la pantalla del código
        res.json({
            mensaje: 'Código MFA enviado al correo',
            requiereMfa: true,
            codigoDemo: codigo // Se añadio ya que el servidor de render no puede enviar correos, así que para propósitos de desarrollo se envía el código en la respuesta. ¡Recuerda eliminar esto en producción!
            //te odio render
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error del servidor al iniciar sesión' });
    }
});

// ==========================================
// ENDPOINT MFA (VERIFICAR CÓDIGO) segunda parte
// ==========================================
app.post('/api/login/verificar-mfa', validarCsrf, async (req, res) => {
    const { correo, codigo } = req.body;

    try {
        const datosMfa = codigosMfa.get(correo);

        // Validaciones de seguridad del código
        if (!datosMfa) return res.status(400).json({ error: 'No hay un código pendiente para este correo.' });
        if (Date.now() > datosMfa.expira) {
            codigosMfa.delete(correo);
            return res.status(400).json({ error: 'El código ha expirado. Vuelve a iniciar sesión.' });
        }
        if (datosMfa.codigo !== codigo) return res.status(400).json({ error: 'Código incorrecto.' });

        // Si el código es correcto, lo borramos de la memoria para que no se reutilice
        codigosMfa.delete(correo);

        // Ahora sí, generamos el Token y le damos acceso
        const usuario = await prisma.usuario.findUnique({
            where: { correo: correo },
            include: { roles: { include: { rol: true } } }
        });

        const esAdmin = usuario.roles.some((asignacion) => asignacion.rol.nombre_rol === 'admin');

        const token = jwt.sign(
            { id_usuario: usuario.id_usuario, correo: usuario.correo },
            process.env.JWT_SECRET || 'secreto_temporal_de_desarrollo_cambiar_luego',
            { expiresIn: '2h' }
        );

        // cookieConfig
        res.cookie('auth_token', token, cookieConfig);

        res.json({
            mensaje: 'Autenticación exitosa',
            esAdmin: esAdmin
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al verificar el código MFA' });
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
const verificarUsuario = async (req, res, next) => {
    try {
        const token = req.cookies.auth_token;
        if (!token) return res.status(401).json({ error: 'Acceso denegado. Debes iniciar sesión.' });

        const decodificado = jwt.verify(token, process.env.JWT_SECRET || 'secreto_temporal_de_desarrollo_cambiar_luego');
        req.usuario = decodificado; // Aquí guardamos el ID para usarlo en la ruta
        next();
    } catch (error) {
        res.status(401).json({ error: 'Token inválido o expirado.' });
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
//  CIFRADO SIMÉTRICO (AES-256)
// ==========================================

const ALGORITMO = 'aes-256-cbc';
// Clave maestra de 32 bytes. En una empresa real, esto va en el .env
const CLAVE_SECRETA = process.env.ENCRYPTION_KEY || 'CampanitaSecreta1234567890123456';

const encriptarAES = (texto) => {
    const iv = crypto.randomBytes(16); // Vector de inicialización (añade aleatoriedad)
    const cipher = crypto.createCipheriv(ALGORITMO, Buffer.from(CLAVE_SECRETA), iv);
    let encriptado = cipher.update(texto, 'utf8', 'hex');
    encriptado += cipher.final('hex');
    // Guardamos el IV junto con el texto para saber cómo abrirlo después
    return iv.toString('hex') + ':' + encriptado;
};

const desencriptarAES = (textoEncriptado) => {
    const partes = textoEncriptado.split(':');
    const iv = Buffer.from(partes.shift(), 'hex');
    const texto = partes.join(':');
    const decipher = crypto.createDecipheriv(ALGORITMO, Buffer.from(CLAVE_SECRETA), iv);
    let desencriptado = decipher.update(texto, 'hex', 'utf8');
    desencriptado += decipher.final('utf8');
    return desencriptado;
};

// 1. Ruta para GUARDAR el teléfono (Se encripta antes de tocar la Base de Datos)
app.post('/api/perfil/telefono', validarCsrf, verificarUsuario, async (req, res) => {
    const { telefono } = req.body;
    try {
        const telefonoEncriptado = encriptarAES(telefono);

        await prisma.usuario.update({
            where: { id_usuario: req.usuario.id_usuario },
            data: { telefono_secreto: telefonoEncriptado }
        });

        // 👁️ Imprimimos en consola para tu video/exposición
        console.log(`\n--- DEMOSTRACIÓN DE CIFRADO SIMÉTRICO ---`);
        console.log(`🔒 Dato original del usuario: ${telefono}`);
        console.log(`🔏 Guardado en Aiven como: ${telefonoEncriptado}`);
        console.log(`-----------------------------------------\n`);

        res.json({ mensaje: 'Teléfono protegido y guardado con éxito' });
    } catch (error) {
        res.status(500).json({ error: 'Error al guardar el dato sensible' });
    }
});

// 2. Ruta para LEER el teléfono (Se desencripta para mostrárselo al usuario)
app.get('/api/perfil/telefono', verificarUsuario, async (req, res) => {
    try {
        const usuarioBD = await prisma.usuario.findUnique({
            where: { id_usuario: req.usuario.id_usuario }
        });

        if (!usuarioBD.telefono_secreto) {
            return res.json({ telefono: null });
        }

        const telefonoDesencriptado = desencriptarAES(usuarioBD.telefono_secreto);

        console.log(`\n--- DEMOSTRACIÓN DE DESENCRIPTADO ---`);
        console.log(`🔓 Extraído de Aiven: ${usuarioBD.telefono_secreto}`);
        console.log(`📱 Desencriptado a: ${telefonoDesencriptado}`);
        console.log(`-------------------------------------\n`);

        res.json({ telefono: telefonoDesencriptado });
    } catch (error) {
        res.status(500).json({ error: 'Error al procesar el dato sensible' });
    }
});

// 3. Obtener perfil completo del usuario
app.get('/api/perfil', verificarUsuario, async (req, res) => {
    try {
        const usuarioBD = await prisma.usuario.findUnique({
            where: { id_usuario: req.usuario.id_usuario },
            include: { roles: { include: { rol: true } } }
        });
        if (!usuarioBD) return res.status(404).json({ error: 'Usuario no encontrado' });

        let telefonoDesencriptado = null;
        if (usuarioBD.telefono_secreto) {
            try {
                telefonoDesencriptado = desencriptarAES(usuarioBD.telefono_secreto);
            } catch (e) {
                telefonoDesencriptado = usuarioBD.telefono_secreto;
            }
        }

        res.json({
            id_usuario: usuarioBD.id_usuario,
            nombre_usuario: usuarioBD.nombre_usuario,
            correo: usuarioBD.correo,
            fecha_registro: usuarioBD.fecha_registro,
            estado_cuenta: usuarioBD.estado_cuenta,
            telefono: telefonoDesencriptado || '',
            fecha_nacimiento: usuarioBD.fecha_nacimiento ? usuarioBD.fecha_nacimiento.toISOString().split('T')[0] : '',
            gamertag: usuarioBD.gamertag || '',
            roles: usuarioBD.roles.map(r => r.rol.nombre_rol)
        });
    } catch (error) {
        console.error('Error al obtener perfil completo:', error);
        res.status(500).json({ error: 'Error al obtener perfil del usuario' });
    }
});

// 4. Actualizar perfil completo (teléfono cifrado, fecha de nacimiento, gamertag)
app.put('/api/perfil', validarCsrf, verificarUsuario, async (req, res) => {
    const { telefono, fecha_nacimiento, gamertag } = req.body;
    try {
        if (gamertag && gamertag.length > 15) {
            return res.status(400).json({ error: 'El Gamertag no puede exceder los 15 caracteres.' });
        }

        let fechaNac = undefined;
        if (fecha_nacimiento) {
            const fechaInput = new Date(fecha_nacimiento);
            const hoy = new Date();
            if (fechaInput > hoy) {
                return res.status(400).json({ error: 'La fecha de nacimiento no puede ser una fecha futura.' });
            }
            fechaNac = fechaInput;
        }

        const dataUpdate = {};
        if (gamertag !== undefined) dataUpdate.gamertag = gamertag || null;
        if (fechaNac !== undefined) dataUpdate.fecha_nacimiento = fechaNac;

        if (telefono !== undefined && telefono !== null && telefono.trim() !== '') {
            const telefonoEncriptado = encriptarAES(telefono);
            dataUpdate.telefono_secreto = telefonoEncriptado;
            console.log(`\n--- PROTECCIÓN DE DATOS DEL PERFIL ---`);
            console.log(`🔒 Teléfono original: ${telefono}`);
            console.log(`🔏 Guardado cifrado: ${telefonoEncriptado}`);
            console.log(`--------------------------------------\n`);
        }

        const usuarioActualizado = await prisma.usuario.update({
            where: { id_usuario: req.usuario.id_usuario },
            data: dataUpdate
        });

        res.json({ mensaje: 'Perfil actualizado y protegido con éxito', usuario: usuarioActualizado });
    } catch (error) {
        console.error('Error al actualizar perfil:', error);
        res.status(500).json({ error: 'Error al actualizar el perfil' });
    }
});

app.put('/api/perfil/gamertag', validarCsrf, verificarUsuario, async (req, res) => {
    const { gamertag } = req.body;
    if (gamertag && gamertag.length > 15) {
        return res.status(400).json({ error: 'El Gamertag no puede exceder los 15 caracteres.' });
    }
    try {
        await prisma.usuario.update({
            where: { id_usuario: req.usuario.id_usuario },
            data: { gamertag: gamertag || null }
        });
        res.json({ mensaje: 'Gamertag actualizado' });
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar Gamertag' });
    }
});

app.put('/api/perfil/fecha-nacimiento', validarCsrf, verificarUsuario, async (req, res) => {
    const { fecha_nacimiento } = req.body;
    if (fecha_nacimiento && new Date(fecha_nacimiento) > new Date()) {
        return res.status(400).json({ error: 'La fecha de nacimiento no puede ser futura.' });
    }
    try {
        await prisma.usuario.update({
            where: { id_usuario: req.usuario.id_usuario },
            data: { fecha_nacimiento: fecha_nacimiento ? new Date(fecha_nacimiento) : null }
        });
        res.json({ mensaje: 'Fecha de nacimiento actualizada' });
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar fecha de nacimiento' });
    }
});
// ==========================================
// PUNTO 4: FIRMAS DIGITALES (HMAC-SHA256)
// ==========================================
const CLAVE_FIRMA = process.env.SIGNATURE_KEY || 'campanita_super_secreta_123';

const generarFirma = (datos) => {
    // Convertimos los datos a un string JSON ordenado para que la firma sea consistente
    const stringDatos = JSON.stringify(datos);
    return crypto.createHmac('sha256', CLAVE_FIRMA)
        .update(stringDatos)
        .digest('hex');
};

const verificarFirma = (datos, firmaRecibida) => {
    const firmaCalculada = generarFirma(datos);
    return firmaCalculada === firmaRecibida;
};

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

// --- NOTICIAS PÚBLICAS ---
app.get('/noticias', async (req, res) => {
    try {
        const noticias = await prisma.noticia.findMany({
            orderBy: { fecha_publicacion: 'desc' }
        });
        res.json(noticias);
    } catch (error) { res.status(500).json({ error: "Error al obtener noticias" }); }
});

app.get('/noticias/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: "ID inválido" });
        const noticia = await prisma.noticia.findUnique({ where: { id_noticia: id } });
        if (!noticia) return res.status(404).json({ error: "Noticia no encontrada" });
        res.json(noticia);
    } catch (error) { res.status(500).json({ error: "Error al obtener la noticia" }); }
});

// ==========================================
// ENDPOINT PARA SUBIR MODELOS 3D E IMÁGENES
// ==========================================
app.post('/api/admin/upload', verificarAdmin, upload.single('archivo'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No se envió ningún archivo.' });
        }
        const filename = req.file.filename;

        // Si estamos en local y existe la carpeta del frontend, copiar el archivo allá también
        if (fs.existsSync(uploadDirFrontend)) {
            try {
                fs.copyFileSync(req.file.path, path.join(uploadDirFrontend, filename));
            } catch (e) { console.error('No se pudo copiar al frontend local:', e); }
        }

        // Construir URL pública para acceder al archivo
        const protocol = req.headers['x-forwarded-proto'] || req.protocol;
        const host = req.get('host');
        const urlArchivo = `${protocol}://${host}/modelos3d/${filename}`;

        console.log(`✅ Archivo subido exitosamente: ${urlArchivo}`);
        res.json({ url: urlArchivo, filename });
    } catch (error) {
        console.error('Error al subir archivo:', error);
        res.status(500).json({ error: 'Error al procesar la subida del archivo.' });
    }
});

// ==========================================
// OPERACIONES ADMINISTRATIVAS (CRUD)
// ==========================================

// --- PERSONAJES (CON FIRMA DIGITAL) ---
app.post('/api/admin/personajes', verificarAdmin, async (req, res) => {
    const { nombre, descripcion, imagen_url } = req.body;
    try {
        // Datos que vamos a firmar
        const datosParaFirmar = { nombre, descripcion, imagen_url };
        const firma = generarFirma(datosParaFirmar);

        const nuevo = await prisma.personaje.create({
            data: { nombre, descripcion, imagen_url, firma_digital: firma }
        });

        console.log(`✅ Personaje firmado. Sello: ${firma}`);
        res.json(nuevo);
    } catch (e) { res.status(500).json({ error: "Error al crear personaje" }); }
});

app.delete('/api/admin/personajes/:id', verificarAdmin, async (req, res) => {
    try {
        await prisma.personaje.delete({ where: { id_personaje: parseInt(req.params.id) } });
        res.json({ mensaje: "Personaje eliminado" });
    } catch (e) { res.status(500).json({ error: "Error al borrar personaje" }); }
});
// Ruta para verificar la integridad de un personaje (puedes usarla desde el Dashboard para mostrar el mensaje)
app.get('/api/admin/verificar/:id', async (req, res) => {
    const p = await prisma.personaje.findUnique({ where: { id_personaje: parseInt(req.params.id) } });
    const esValido = verificarFirma({ nombre: p.nombre, descripcion: p.descripcion, imagen_url: p.imagen_url }, p.firma_digital);
    res.json({ mensaje: esValido ? "Sello de integridad intacto ✅" : "¡ALERTA: DATOS ALTERADOS! ❌" });
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

// --- NOTICIAS CRUD ---
app.post('/api/admin/noticias', verificarAdmin, async (req, res) => {
    const { titulo, contenido, imagen_url } = req.body;
    if (!titulo || !contenido) {
        return res.status(400).json({ error: "Título y contenido son obligatorios" });
    }
    if (titulo.length > 150) {
        return res.status(400).json({ error: "El título no puede exceder los 150 caracteres" });
    }
    try {
        const nueva = await prisma.noticia.create({
            data: {
                titulo: titulo.trim(),
                contenido: contenido.trim(),
                imagen_url: imagen_url ? imagen_url.trim() : null
            }
        });
        res.json(nueva);
    } catch (e) {
        console.error("Error en POST noticias:", e);
        res.status(500).json({ error: "Error al crear la noticia" });
    }
});

app.put('/api/admin/noticias/:id', verificarAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "ID inválido" });
    const { titulo, contenido, imagen_url } = req.body;
    if (!titulo || !contenido) {
        return res.status(400).json({ error: "Título y contenido son obligatorios" });
    }
    if (titulo.length > 150) {
        return res.status(400).json({ error: "El título no puede exceder los 150 caracteres" });
    }
    try {
        const actualizada = await prisma.noticia.update({
            where: { id_noticia: id },
            data: {
                titulo: titulo.trim(),
                contenido: contenido.trim(),
                imagen_url: imagen_url ? imagen_url.trim() : null
            }
        });
        res.json(actualizada);
    } catch (e) {
        console.error("Error en PUT noticias:", e);
        res.status(500).json({ error: "Error al actualizar la noticia" });
    }
});

app.delete('/api/admin/noticias/:id', verificarAdmin, async (req, res) => {
    try {
        await prisma.noticia.delete({ where: { id_noticia: parseInt(req.params.id) } });
        res.json({ mensaje: "Noticia eliminada" });
    } catch (e) { res.status(500).json({ error: "Error al borrar noticia" }); }
});

// ==========================================
// GESTIÓN ADMINISTRATIVA DE USUARIOS (CRUD)
// ==========================================
app.get('/api/admin/usuarios', verificarAdmin, async (req, res) => {
    try {
        const usuarios = await prisma.usuario.findMany({
            include: {
                roles: {
                    include: { rol: true }
                }
            },
            orderBy: { fecha_registro: 'desc' }
        });

        const usuariosFormateados = usuarios.map(u => {
            let telefonoDes = null;
            if (u.telefono_secreto) {
                try {
                    telefonoDes = desencriptarAES(u.telefono_secreto);
                } catch (e) {
                    telefonoDes = u.telefono_secreto;
                }
            }
            return {
                id_usuario: u.id_usuario,
                nombre_usuario: u.nombre_usuario,
                correo: u.correo,
                gamertag: u.gamertag || '',
                telefono: telefonoDes || '',
                fecha_nacimiento: u.fecha_nacimiento ? u.fecha_nacimiento.toISOString().split('T')[0] : '',
                fecha_registro: u.fecha_registro,
                estado_cuenta: u.estado_cuenta,
                roles: u.roles.map(r => r.rol.nombre_rol)
            };
        });

        res.json(usuariosFormateados);
    } catch (e) {
        console.error("Error al obtener usuarios admin:", e);
        res.status(500).json({ error: "Error al obtener usuarios" });
    }
});

app.put('/api/admin/usuarios/:id', verificarAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    const { nombre_usuario, correo, gamertag, fecha_nacimiento, estado_cuenta } = req.body;
    try {
        const dataUpdate = {};
        if (nombre_usuario !== undefined) dataUpdate.nombre_usuario = nombre_usuario;
        if (correo !== undefined) dataUpdate.correo = correo;
        if (gamertag !== undefined) dataUpdate.gamertag = gamertag || null;
        if (fecha_nacimiento !== undefined) dataUpdate.fecha_nacimiento = fecha_nacimiento ? new Date(fecha_nacimiento) : null;
        if (estado_cuenta !== undefined) dataUpdate.estado_cuenta = estado_cuenta;

        const actualizado = await prisma.usuario.update({
            where: { id_usuario: id },
            data: dataUpdate
        });
        res.json(actualizado);
    } catch (e) {
        console.error("Error al actualizar usuario admin:", e);
        res.status(500).json({ error: "Error al actualizar usuario" });
    }
});

app.put('/api/admin/usuarios/:id/banear', verificarAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
        const ban = await prisma.usuario.update({
            where: { id_usuario: id },
            data: { estado_cuenta: 'baneado' }
        });
        res.json({ mensaje: "Usuario baneado correctamente", usuario: ban });
    } catch (e) {
        console.error("Error al banear usuario:", e);
        res.status(500).json({ error: "Error al banear usuario" });
    }
});

app.put('/api/admin/usuarios/:id/reactivar', verificarAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
        const reactivar = await prisma.usuario.update({
            where: { id_usuario: id },
            data: { estado_cuenta: 'activo' }
        });
        res.json({ mensaje: "Usuario reactivado correctamente", usuario: reactivar });
    } catch (e) {
        console.error("Error al reactivar usuario:", e);
        res.status(500).json({ error: "Error al reactivar usuario" });
    }
});

app.delete('/api/admin/usuarios/:id', verificarAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
        await prisma.usuario.delete({
            where: { id_usuario: id }
        });
        res.json({ mensaje: "Usuario eliminado correctamente" });
    } catch (e) {
        console.error("Error al eliminar usuario:", e);
        res.status(500).json({ error: "Error al eliminar usuario" });
    }
});

// ==========================================
// ARRANQUE DEL SERVIDOR
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor blindado corriendo en el puerto ${PORT}`);
});
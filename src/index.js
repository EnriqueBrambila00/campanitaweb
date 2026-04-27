const express = require('express');
const { PrismaClient } = require('@prisma/client');

const app = express();

// Inicializamos Prisma pasándole la URL directa (por el cambio en la versión 7)
const prisma = new PrismaClient({
  adapter: null // Le decimos explícitamente que no usamos un adaptador externo (como PGLite o PlanetScale), sino la conexión estándar a Aiven.
});
app.use(cors()); 
app.use(express.json());

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
//usuarios
app.get('/usuarios', async (req, res) => {
  try {
    const data = await prisma.usuario.findMany();
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: "Error al obtener usuarios" });
  }
});

//personajes
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

// Arrancar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
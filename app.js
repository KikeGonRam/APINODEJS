const express = require("express");
const mysql = require("mysql2");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require('cors');

// Crear la conexión a la base de datos
const db = mysql.createConnection({
  host: "localhost",
  user: "root", // Usa tu usuario de MySQL
  password: "", // Usa tu contraseña de MySQL
  database: "iot2", // Nombre de tu base de datos
});

// Verifica si la conexión es exitosa
db.connect((err) => {
  if (err) {
    console.error("Error al conectar a la base de datos:", err);
    return;
  }
  console.log("Base de datos conectada");
});

// Crear la aplicación Express
const app = express();
const port = 5000; // Puerto para el servidor

// Permitir solicitudes CORS
app.use(cors());

// Middleware para parsear el cuerpo de las solicitudes
app.use(express.json()); // Para manejar JSON en el cuerpo de la solicitud

// Ruta de prueba
app.get("/", (req, res) => {
  res.send("¡Hola Mundo!");
});

// Ruta para el login del administrador
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "El correo y la contraseña son obligatorios" });
  }

  // Buscar al administrador por el email
  const query = "SELECT * FROM admins WHERE email = ?";
  
  db.query(query, [email], (err, results) => {
    if (err) {
      console.error("Error al buscar el administrador:", err);
      return res.status(500).json({ error: "Error al buscar el administrador" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "Administrador no encontrado" });
    }

    const admin = results[0];

    // Comparar las contraseñas
    bcrypt.compare(password, admin.password, (err, isMatch) => {
      if (err) {
        console.error("Error al comparar la contraseña:", err);
        return res.status(500).json({ error: "Error al comparar la contraseña" });
      }

      if (!isMatch) {
        return res.status(400).json({ error: "Contraseña incorrecta" });
      }

      // Si la contraseña es correcta, generar un token JWT
      const payload = {
        id: admin.id,
        nombre: admin.nombre,
        email: admin.email,
      };

      const token = jwt.sign(payload, "secreto_muy_secreto", { expiresIn: "1h" });

      res.json({
        message: "Inicio de sesión exitoso",
        token: token,
      });
    });
  });
});



// Ruta para obtener todos los usuarios
app.get("/admin/users", (req, res) => {
    const query = "SELECT * FROM usuarios"; // Cambia 'users' por el nombre real de tu tabla de usuarios
    
    db.query(query, (err, results) => {
      if (err) {
        console.error("Error al obtener los usuarios:", err);
        return res.status(500).json({ error: "Error al obtener los usuarios" });
      }
  
      if (results.length === 0) {
        return res.status(404).json({ message: "No se encontraron usuarios" });
      }
  
      // Responder con los usuarios obtenidos
      res.json(results);
    });
  });
  

// Ruta para crear un nuevo usuario
app.post("/admin/users", (req, res) => {
    const { nombre, app, apm, fn, telefono, email, password } = req.body;
  
    // Verificar si todos los campos son proporcionados
    if (!nombre || !app || !apm || !fn || !telefono || !email || !password) {
      return res.status(400).json({ error: "Todos los campos son obligatorios" });
    }
  
    // Comprobar si el correo ya está registrado en la base de datos
    const checkEmailQuery = "SELECT * FROM usuarios WHERE email = ?";
    db.query(checkEmailQuery, [email], (err, results) => {
      if (err) {
        console.error("Error al verificar el correo:", err);
        return res.status(500).json({ error: "Error al verificar el correo" });
      }
  
      // Si el correo ya existe, devolver un error
      if (results.length > 0) {
        return res.status(400).json({ error: "El correo electrónico ya está registrado" });
      }
  
      // Encriptar la contraseña
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
          console.error("Error al encriptar la contraseña:", err);
          return res.status(500).json({ error: "Error al encriptar la contraseña" });
        }
  
        // Insertar usuario en la base de datos
        const query = `INSERT INTO usuarios (nombre, app, apm, fn, telefono, email, password) VALUES (?, ?, ?, ?, ?, ?, ?)`;
  
        db.query(query, [nombre, app, apm, fn, telefono, email, hashedPassword], (err, result) => {
          if (err) {
            console.error("Error al crear el usuario:", err);
            return res.status(500).json({ error: "Error al crear el usuario" });
          }
  
          res.status(201).json({
            message: "Usuario creado exitosamente",
            id_usuario: result.insertId, // Devolvemos el ID del nuevo usuario
          });
        });
      });
    });
  });
  

// Ruta para actualizar un usuario
app.put("/admin/users/:id", (req, res) => {
    const { id } = req.params;
    const { nombre, app, apm, fn, telefono, email, password } = req.body;
  
    if (!nombre || !app || !apm || !fn || !telefono || !email || !password) {
      return res.status(400).json({ error: "Todos los campos son obligatorios" });
    }
  
    // Encriptar la nueva contraseña
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error("Error al encriptar la contraseña:", err);
        return res.status(500).json({ error: "Error al encriptar la contraseña" });
      }
  
      const query = `UPDATE usuarios SET nombre = ?, app = ?, apm = ?, fn = ?, telefono = ?, email = ?, password = ? WHERE id_usuario = ?`;
      
      db.query(query, [nombre, app, apm, fn, telefono, email, hashedPassword, id], (err, result) => {
        if (err) {
          console.error("Error al actualizar el usuario:", err);
          return res.status(500).json({ error: "Error al actualizar el usuario" });
        }
  
        if (result.affectedRows === 0) {
          return res.status(404).json({ message: "Usuario no encontrado" });
        }
  
        res.json({ message: "Usuario actualizado exitosamente" });
      });
    });
  });


// Ruta para eliminar un usuario
app.delete("/admin/users/:id", (req, res) => {
    const { id } = req.params;
  
    const query = `DELETE FROM usuarios WHERE id_usuario = ?`;
    
    db.query(query, [id], (err, result) => {
      if (err) {
        console.error("Error al eliminar el usuario:", err);
        return res.status(500).json({ error: "Error al eliminar el usuario" });
      }
  
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Usuario no encontrado" });
      }
  
      res.json({ message: "Usuario eliminado exitosamente" });
    });
  });
  
  

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});

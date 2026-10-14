const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────
// 📁 Carpeta uploads/
// ─────────────────────────────────────────────
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log("📁 Carpeta uploads/ creada");
}
app.use("/uploads", express.static(uploadsDir));

// ─────────────────────────────────────────────
// 🔑 Secreto JWT
// ─────────────────────────────────────────────
const JWT_SECRET = process.env.SECRET_KEY || "clave_secreta_inframen_2026";

// ─────────────────────────────────────────────
// 🔌 Conexión MySQL
// ─────────────────────────────────────────────
const conexion = mysql.createConnection({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "incidencias_escolares",
    port: process.env.DB_PORT || 3306,
    ssl: process.env.DB_HOST ? { rejectUnauthorized: false } : false
});

conexion.connect((err) => {
    if (err) {
        console.error("❌ Error MySQL:", err);
        return;
    }
    console.log("✅ Conectado a MySQL");
});

// ─────────────────────────────────────────────
// 📦 Multer
// ─────────────────────────────────────────────
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
        const nombreUnico = Date.now() + "-" + Math.round(Math.random() * 1e9);
        const ext = path.extname(file.originalname).toLowerCase() || ".jpg";
        cb(null, nombreUnico + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const mimetypesValidos = [
            "image/jpeg", "image/jpg", "image/pjpeg", "image/png",
            "image/webp", "image/heic", "image/heif",
            "application/octet-stream",
        ];
        const extensionesValidas = /\.(jpe?g|png|webp|heic|heif)$/i;
        const mimetypeOk = mimetypesValidos.includes(file.mimetype);
        const extensionOk = extensionesValidas.test(file.originalname);
        if (mimetypeOk || extensionOk) return cb(null, true);
        cb(new Error(`Formato no permitido: ${file.mimetype}`));
    }
});

// ─────────────────────────────────────────────
// 🔐 Middlewares
// ─────────────────────────────────────────────
const verificarToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
        return res.status(403).json({ mensaje: "Token requerido" });
    }
    try {
        const token = authHeader.startsWith("Bearer ")
            ? authHeader.split(" ")[1]
            : authHeader;
        const decoded = jwt.verify(token, JWT_SECRET);
        req.usuario = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ mensaje: "Token inválido o expirado" });
    }
};

const verificarAdmin = (req, res, next) => {
    if (req.usuario?.rol !== "Admin") {
        return res.status(403).json({
            mensaje: "Acceso denegado. Se requieren permisos de Administrador."
        });
    }
    next();
};

// ═════════════════════════════════════════════
// 🔐 AUTENTICACIÓN
// ═════════════════════════════════════════════

app.post("/registro", async (req, res) => {
    const { nombre, email, password, rol } = req.body;

    if (!nombre || !email || !password) {
        return res.status(400).json({ mensaje: "Todos los campos son obligatorios" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const rolFinal = (rol === "Admin") ? "Admin" : "Usuario";
        const sql = "INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)";

        conexion.query(sql, [nombre, email, hashedPassword, rolFinal], (error, resultado) => {
            if (error) {
                console.error(error);
                if (error.code === "ER_DUP_ENTRY") {
                    return res.status(409).json({ mensaje: "El email ya está registrado" });
                }
                return res.status(500).json({ error: error.message });
            }
            res.json({
                mensaje: "Usuario registrado correctamente",
                id: resultado.insertId
            });
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ mensaje: "Error al procesar el registro" });
    }
});

app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ mensaje: "Email y contraseña son obligatorios" });
    }

    const sql = "SELECT * FROM usuarios WHERE email = ?";
    conexion.query(sql, [email], async (error, resultado) => {
        if (error) return res.status(500).json({ error: error.message });

        if (resultado.length === 0) {
            return res.status(404).json({ mensaje: "Usuario no encontrado" });
        }

        const usuario = resultado[0];
        const passwordValida = await bcrypt.compare(password, usuario.password);

        if (!passwordValida) {
            return res.status(401).json({ mensaje: "Contraseña incorrecta" });
        }

        const token = jwt.sign(
            { id: usuario.id, nombre: usuario.nombre, rol: usuario.rol },
            JWT_SECRET,
            { expiresIn: "8h" }
        );

        res.json({
            mensaje: "Inicio de sesión exitoso",
            token,
            usuario: {
                id: usuario.id,
                nombre: usuario.nombre,
                email: usuario.email,
                rol: usuario.rol
            }
        });
    });
});

app.get("/verificar-token", verificarToken, (req, res) => {
    res.json({ valido: true, usuario: req.usuario });
});

app.get("/perfil", verificarToken, (req, res) => {
    const usuarioId = req.usuario.id;
    const sql = "SELECT id, nombre, email, rol, fecha_registro FROM usuarios WHERE id = ?";
    conexion.query(sql, [usuarioId], (error, resultado) => {
        if (error) return res.status(500).json({ error: error.message });
        if (resultado.length === 0) {
            return res.status(404).json({ mensaje: "Usuario no encontrado" });
        }
        res.json(resultado[0]);
    });
});

// ═════════════════════════════════════════════
// 📋 CATEGORÍAS
// ═════════════════════════════════════════════
app.get("/categorias", (req, res) => {
    conexion.query("SELECT * FROM categorias", (error, resultado) => {
        if (error) return res.status(500).json({ error: error.message });
        res.json(resultado);
    });
});

// ═════════════════════════════════════════════
// 📄 INCIDENCIAS
// ═════════════════════════════════════════════
app.get("/incidencias", (req, res) => {
    const { buscar, categoria_id, estado } = req.query;

    let sql = `
        SELECT i.id, i.descripcion, i.estado, i.fecha, i.imagen,
               c.nombre AS categoria,
               u.nombre AS usuario
        FROM incidencias i
        INNER JOIN categorias c ON i.categoria_id = c.id
        LEFT JOIN usuarios u ON i.usuario_id = u.id
        WHERE 1=1
    `;

    const parametros = [];

    if (buscar && buscar.trim() !== "") {
        sql += " AND i.descripcion LIKE ?";
        parametros.push(`%${buscar.trim()}%`);
    }
    if (categoria_id && categoria_id !== "") {
        sql += " AND i.categoria_id = ?";
        parametros.push(categoria_id);
    }
    if (estado && estado !== "") {
        sql += " AND i.estado = ?";
        parametros.push(estado);
    }

    sql += " ORDER BY i.fecha DESC";

    conexion.query(sql, parametros, (error, resultado) => {
        if (error) return res.status(500).json({ error: error.message });
        res.json(resultado);
    });
});

app.get("/incidencias/exportar", (req, res) => {
    const { fecha_inicio, fecha_fin } = req.query;

    let sql = `
        SELECT i.id, i.descripcion, i.estado, i.fecha,
               c.nombre AS categoria,
               u.nombre AS usuario
        FROM incidencias i
        INNER JOIN categorias c ON i.categoria_id = c.id
        LEFT JOIN usuarios u ON i.usuario_id = u.id
        WHERE 1=1
    `;
    const parametros = [];

    if (fecha_inicio && fecha_fin) {
        sql += " AND DATE(i.fecha) BETWEEN ? AND ?";
        parametros.push(fecha_inicio, fecha_fin);
    }

    sql += " ORDER BY i.fecha DESC";

    conexion.query(sql, parametros, (error, resultado) => {
        if (error) return res.status(500).json({ error: error.message });
        res.json(resultado);
    });
});

app.get("/incidencias/resueltas", (req, res) => {
    const sql = `
        SELECT i.id, i.descripcion, i.estado, i.fecha, i.imagen,
               c.nombre AS categoria,
               u.nombre AS usuario
        FROM incidencias i
        INNER JOIN categorias c ON i.categoria_id = c.id
        LEFT JOIN usuarios u ON i.usuario_id = u.id
        WHERE i.estado = 'Resuelto'
        ORDER BY i.fecha DESC
    `;
    conexion.query(sql, (error, resultado) => {
        if (error) return res.status(500).json({ error: error.message });
        res.json(resultado);
    });
});

app.post("/incidencias", verificarToken, (req, res) => {
    upload.single("imagen")(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });

        const { categoria_id, descripcion } = req.body;
        const imagen = req.file ? req.file.filename : null;
        const usuario_id = req.usuario.id;

        if (!categoria_id || !descripcion) {
            return res.status(400).json({ error: "Faltan datos obligatorios" });
        }

        const sql = "INSERT INTO incidencias (usuario_id, categoria_id, descripcion, imagen) VALUES (?, ?, ?, ?)";
        conexion.query(sql, [usuario_id, categoria_id, descripcion, imagen], (error, resultado) => {
            if (error) return res.status(500).json({ error: error.message });
            res.json({
                mensaje: "Incidencia registrada correctamente",
                id: resultado.insertId,
                imagen: imagen
            });
        });
    });
});

app.put("/incidencias/:id/estado", verificarToken, verificarAdmin, (req, res) => {
    const { id } = req.params;
    const { estado } = req.body;

    const estadosValidos = ["Pendiente", "En proceso", "Resuelto"];
    if (!estado || !estadosValidos.includes(estado)) {
        return res.status(400).json({
            error: `Estado inválido. Permitidos: ${estadosValidos.join(", ")}`
        });
    }

    const sql = "UPDATE incidencias SET estado = ? WHERE id = ?";
    conexion.query(sql, [estado, id], (error, resultado) => {
        if (error) return res.status(500).json({ error: error.message });
        if (resultado.affectedRows === 0) {
            return res.status(404).json({ error: "Incidencia no encontrada" });
        }
        res.json({
            mensaje: "Estado actualizado correctamente",
            id: id,
            nuevo_estado: estado
        });
    });
});

app.delete("/incidencias/:id", verificarToken, verificarAdmin, (req, res) => {
    const { id } = req.params;
    const sqlBuscar = "SELECT imagen FROM incidencias WHERE id = ?";

    conexion.query(sqlBuscar, [id], (error, filas) => {
        if (error) return res.status(500).json({ error: error.message });
        if (filas.length === 0) {
            return res.status(404).json({ error: "Incidencia no encontrada" });
        }

        const nombreImagen = filas[0].imagen;
        const sqlDelete = "DELETE FROM incidencias WHERE id = ?";

        conexion.query(sqlDelete, [id], (error, resultado) => {
            if (error) return res.status(500).json({ error: error.message });

            if (nombreImagen) {
                const rutaImagen = path.join(uploadsDir, nombreImagen);
                if (fs.existsSync(rutaImagen)) {
                    try { fs.unlinkSync(rutaImagen); } catch (_) {}
                }
            }

            res.json({
                mensaje: "Incidencia eliminada correctamente",
                id: id
            });
        });
    });
});

// ═════════════════════════════════════════════
// 📊 ESTADÍSTICAS
// ═════════════════════════════════════════════
app.get("/estadisticas/categorias", (req, res) => {
    const sql = `
        SELECT c.nombre AS categoria, COUNT(i.id) AS total
        FROM categorias c
        LEFT JOIN incidencias i ON c.id = i.categoria_id
        GROUP BY c.id, c.nombre
        ORDER BY total DESC
    `;
    conexion.query(sql, (error, resultado) => {
        if (error) return res.status(500).json({ error: error.message });
        res.json(resultado);
    });
});

app.get("/estadisticas/estados", (req, res) => {
    const sql = `SELECT estado, COUNT(id) AS total FROM incidencias GROUP BY estado`;
    conexion.query(sql, (error, resultado) => {
        if (error) return res.status(500).json({ error: error.message });
        res.json(resultado);
    });
});

// ─────────────────────────────────────────────
// 🚀 Escucha
// ─────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Servidor iniciado en el puerto ${PORT}`);
    console.log(`   → DB: ${process.env.DB_HOST || "localhost"}`);
});
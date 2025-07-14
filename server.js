// BackendApp/server.js
require('dotenv').config();

const express = require('express');
const { google } = require('googleapis');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// --- Google Sheets Configuration ---
const GOOGLE_SHEET_ID = process.env.GOOGLE_SHEET_ID;
const GOOGLE_SERVICE_ACCOUNT_EMAIL = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
const GOOGLE_PRIVATE_KEY = process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n');

const USERS_SHEET_NAME = process.env.USERS_SHEET_NAME || 'Usuarios';
const EBOOKS_SHEET_NAME = process.env.EBOOKS_SHEET_NAME || 'Ebooks';
const CLASSES_SHEET_NAME = process.env.CLASSES_SHEET_NAME || 'Clases';
const PLANS_SHEET_NAME = process.env.PLANS_SHEET_NAME || 'PlanesNutricionales';

let sheets; // Global variable for Google Sheets API client

// --- Google Sheets Authentication ---
async function authenticateGoogleSheets() {
    if (sheets) return; // Already authenticated

    const auth = new google.auth.JWT(
        GOOGLE_SERVICE_ACCOUNT_EMAIL,
        null,
        GOOGLE_PRIVATE_KEY,
        ['https://www.googleapis.com/auth/spreadsheets']
    );

    await auth.authorize();
    sheets = google.sheets({ version: 'v4', auth });
    console.log('✅ Google Sheets API autenticada.');
}

// --- Google Sheets Utility Functions ---

// Function to get all rows from a sheet
async function getSheetData(sheetName) {
    await authenticateGoogleSheets();
    const response = await sheets.spreadsheets.values.get({
        spreadsheetId: GOOGLE_SHEET_ID,
        range: sheetName,
    });
    // Si no hay datos, devuelve un array vacío, no null o undefined
    const rows = response.data.values || [];
    // Si solo hay cabecera, devuelve un array con la cabecera y ningún dato
    if (rows.length === 1 && rows[0].every(cell => !cell)) return []; // Si solo hay una fila vacía
    if (rows.length > 0 && rows[0].length === 0) return []; // Si la primera fila está vacía

    // Convertir a formato de objeto { cabecera: valor }
    if (rows.length > 0) {
        const header = rows[0];
        return rows.slice(1).map(row => {
            const rowObject = {};
            header.forEach((key, index) => {
                rowObject[key] = row[index];
            });
            return rowObject;
        });
    }
    return []; // Si no hay cabecera o datos, devuelve vacío
}

// Function to append a new row to a sheet (used for user registration and initial content setup)
async function appendSheetRow(sheetName, rowData) {
    await authenticateGoogleSheets();
    await sheets.spreadsheets.values.append({
        spreadsheetId: GOOGLE_SHEET_ID,
        range: sheetName,
        valueInputOption: 'USER_ENTERED',
        resource: {
            values: [rowData],
        },
    });
}

// Function to find a row by a specific column value
async function findSheetRow(sheetName, columnName, searchValue) {
    const rows = await getSheetData(sheetName); // getSheetData ahora devuelve objetos
    const headerRow = (await sheets.spreadsheets.values.get({ spreadsheetId: GOOGLE_SHEET_ID, range: sheetName + '!1:1' })).data.values[0];

    if (!headerRow) return null; // No header means empty sheet or issue

    for (let i = 0; i < rows.length; i++) { // Iterate through parsed objects
        if (rows[i][columnName] === searchValue) {
            // Reconstruir el objeto con el índice de fila para la actualización
            return {
                rowData: rows[i],
                rowIndex: i + 2 // +2 because getSheetData slices header (1) and Sheets is 1-indexed for content rows
            };
        }
    }
    return null;
}

// Function to update a specific row by index (used for user data like membership)
async function updateSheetRowByIndex(sheetName, rowIndex, newData) {
    await authenticateGoogleSheets();
    const header = (await sheets.spreadsheets.values.get({ spreadsheetId: GOOGLE_SHEET_ID, range: sheetName + '!1:1' })).data.values[0];
    if (!header) {
        console.error('No se encontró cabecera en la hoja para actualizar.');
        return;
    }

    // Obtener la fila actual completa para no sobrescribir celdas vacías
    const currentRowResponse = await sheets.spreadsheets.values.get({
        spreadsheetId: GOOGLE_SHEET_ID,
        range: `${sheetName}!A${rowIndex}:${String.fromCharCode(64 + header.length)}${rowIndex}` // Range for the specific row
    });
    let currentRow = currentRowResponse.data.values && currentRowResponse.data.values[0] ? currentRowResponse.data.values[0] : new Array(header.length).fill('');

    // Aplicar los nuevos datos a la fila actual
    for (const key in newData) {
        const colIndex = header.indexOf(key);
        if (colIndex !== -1) {
            currentRow[colIndex] = newData[key];
        }
    }

    await sheets.spreadsheets.values.update({
        spreadsheetId: GOOGLE_SHEET_ID,
        range: `${sheetName}!A${rowIndex}`,
        valueInputOption: 'RAW',
        resource: {
            values: [currentRow],
        },
    });
}

// --- Middlewares ---
app.use(cors());
app.use(express.json());

// Middleware para verificar JWT y obtener datos del usuario
const authMiddleware = async (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ message: 'Acceso denegado. No se proporcionó token.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Buscar el usuario en la hoja para obtener su membresía actual
        const userEntry = await findSheetRow(USERS_SHEET_NAME, 'userId', decoded.userId);
        
        if (!userEntry) {
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }
        
        req.user = userEntry.rowData; // Adjuntar todos los datos del usuario a la solicitud
        next();
    } catch (err) {
        console.error('Error al verificar token:', err.message);
        res.status(403).json({ message: 'Token inválido o expirado.' });
    }
};

// --- Rutas de Autenticación (Existentes) ---

// Ruta de Registro de Usuario
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Por favor, introduce email y contraseña.' });
    }

    try {
        // Asegurarse de que la hoja de Usuarios existe con las columnas correctas
        const usersHeader = ['userId', 'email', 'passwordHash', 'membership', 'createdAt', 'updatedAt'];
        const existingUsersDataRaw = (await sheets.spreadsheets.values.get({ spreadsheetId: GOOGLE_SHEET_ID, range: USERS_SHEET_NAME + '!1:1' })).data.values || [];
        if (existingUsersDataRaw.length === 0 || JSON.stringify(existingUsersDataRaw[0]) !== JSON.stringify(usersHeader)) {
            // Si la hoja está vacía o la cabecera no coincide, establecerla
            if (existingUsersDataRaw.length === 0) { // Si la hoja está totalmente vacía
                await appendSheetRow(USERS_SHEET_NAME, usersHeader);
            } else { // Si tiene alguna cabecera pero no la correcta, la sobrescribe o añade
                 await sheets.spreadsheets.values.update({
                    spreadsheetId: GOOGLE_SHEET_ID,
                    range: USERS_SHEET_NAME + '!1:1',
                    valueInputOption: 'RAW',
                    resource: {
                        values: [usersHeader],
                    },
                });
            }
            console.log(`Cabecera para '${USERS_SHEET_NAME}' establecida/verificada.`);
        }

        const userFound = await findSheetRow(USERS_SHEET_NAME, 'email', email);
        if (userFound) {
            return res.status(400).json({ message: 'El email ya está registrado.' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const userId = uuidv4();
        const now = new Date().toISOString();

        const newUserRow = [userId, email, passwordHash, 'free', now, now];

        // Obtener la cabecera actual para asegurar el orden de las columnas al añadir la fila
        const currentHeader = (await sheets.spreadsheets.values.get({ spreadsheetId: GOOGLE_SHEET_ID, range: USERS_SHEET_NAME + '!1:1' })).data.values[0];
        const newRowOrdered = usersHeader.map(col => { // Usa la cabecera esperada para el orden
            switch(col) {
                case 'userId': return userId;
                case 'email': return email;
                case 'passwordHash': return passwordHash;
                case 'membership': return 'free';
                case 'createdAt': return now;
                case 'updatedAt': return now;
                default: return '';
            }
        });

        await appendSheetRow(USERS_SHEET_NAME, newRowOrdered);

        const payload = { userId: userId, email: email };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({
            message: 'Usuario registrado con éxito.',
            token,
            user: { id: userId, email: email, membership: 'free' }
        });

    } catch (err) {
        console.error('Error al registrar usuario en Sheets:', err.message);
        res.status(500).send('Error del servidor al registrar usuario.');
    }
});

// Ruta de Inicio de Sesión
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Por favor, introduce email y contraseña.' });
    }

    try {
        const userFound = await findSheetRow(USERS_SHEET_NAME, 'email', email);
        if (!userFound) {
            return res.status(400).json({ message: 'Credenciales inválidas.' });
        }

        const userRow = userFound.rowData;
        const isMatch = await bcrypt.compare(password, userRow.passwordHash);
        if (!isMatch) {
            return res.status(400).json({ message: 'Credenciales inválidas.' });
        }

        const payload = { userId: userRow.userId, email: userRow.email };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        res.json({
            message: 'Inicio de sesión exitoso.',
            token,
            user: { id: userRow.userId, email: userRow.email, membership: userRow.membership }
        });

    } catch (err) {
        console.error('Error al iniciar sesión en Sheets:', err.message);
        res.status(500).send('Error del servidor al iniciar sesión.');
    }
});

// --- Rutas de Contenido (Nuevas) ---

// Función genérica para obtener contenido con filtro de membresía
async function getFilteredContent(sheetName, userMembership) {
    const allContent = await getSheetData(sheetName);
    return allContent.filter(item => {
        // Si el contenido es premium (TRUE)
        if (item.premiumAccess && item.premiumAccess.toUpperCase() === 'TRUE') {
            // Solo lo devuelve si el usuario es premium
            return userMembership.toLowerCase() === 'premium';
        }
        // Si no es premium (FALSE o cualquier otro valor), siempre lo devuelve
        return true;
    }).map(item => {
        // Para contenido premium al que el usuario gratuito no tiene acceso,
        // ocultar la URL del archivo/video, pero mostrar el resto de la info.
        if (item.premiumAccess && item.premiumAccess.toUpperCase() === 'TRUE' && userMembership.toLowerCase() !== 'premium') {
            return { ...item, fileURL: null, videoURL: null }; // Eliminar las URLs sensibles
        }
        return item;
    });
}

// Ruta para obtener Ebooks
app.get('/api/content/ebooks', authMiddleware, async (req, res) => {
    try {
        const ebooks = await getFilteredContent(EBOOKS_SHEET_NAME, req.user.membership);
        res.json(ebooks);
    } catch (err) {
        console.error('Error al obtener ebooks:', err.message);
        res.status(500).send('Error del servidor al obtener ebooks.');
    }
});

// Ruta para obtener Clases
app.get('/api/content/classes', authMiddleware, async (req, res) => {
    try {
        const classes = await getFilteredContent(CLASSES_SHEET_NAME, req.user.membership);
        res.json(classes);
    } catch (err) {
        console.error('Error al obtener clases:', err.message);
        res.status(500).send('Error del servidor al obtener clases.');
    }
});

// Ruta para obtener Planes Nutricionales
app.get('/api/content/plans', authMiddleware, async (req, res) => {
    try {
        const plans = await getFilteredContent(PLANS_SHEET_NAME, req.user.membership);
        res.json(plans);
    } catch (err) {
        console.error('Error al obtener planes nutricionales:', err.message);
        res.status(500).send('Error del servidor al obtener planes nutricionales.');
    }
});

// Ruta para cambiar membresía del usuario (ej. después de una compra)
// ESTA RUTA NO ESTARÍA ACCESIBLE DESDE EL CLIENTE MÓVIL DIRECTAMENTE POR SEGURIDAD.
// SERÍA LLAMADA POR UN SISTEMA DE PAGOS (Webhook) O UN PANEL DE ADMINISTRACIÓN.
app.post('/api/admin/update-membership', async (req, res) => {
    const { userId, newMembership } = req.body; // newMembership debería ser 'premium' o 'free'

    if (!userId || !newMembership) {
        return res.status(400).json({ message: 'Se requiere userId y newMembership.' });
    }
    
    try {
        const userFound = await findSheetRow(USERS_SHEET_NAME, 'userId', userId);
        if (!userFound) {
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }

        const rowIndex = userFound.rowIndex;
        const now = new Date().toISOString();
        
        await updateSheetRowByIndex(USERS_SHEET_NAME, rowIndex, {
            membership: newMembership,
            updatedAt: now
        });

        res.status(200).json({ message: `Membresía del usuario ${userId} actualizada a ${newMembership}.` });

    } catch (err) {
        console.error('Error al actualizar membresía:', err.message);
        res.status(500).send('Error del servidor al actualizar membresía.');
    }
});


// Ruta de Bienvenida (para verificar que el servidor está funcionando)
app.get('/', (req, res) => {
    res.send('Backend de la App Ebook funcionando con Google Sheets! Rutas: /api/auth/register, /api/auth/login, /api/content/ebooks, /api/content/classes, /api/content/plans.');
});

// Iniciar el servidor
authenticateGoogleSheets().then(() => {
    app.listen(PORT, () => {
        console.log(`Servidor backend escuchando en el puerto ${PORT}`);
    });
}).catch(err => {
    console.error('Fallo al iniciar el servidor debido a un error de autenticación de Google Sheets:', err);
    process.exit(1);
});
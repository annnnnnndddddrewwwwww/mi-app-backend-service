// BackendApp/server.js
require('dotenv').config();

const express = require('express');
const { google } = require('googleapis');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid'); // Para generar IDs únicos si necesitas

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// --- Google Sheets Configuration ---
const GOOGLE_SHEET_ID = process.env.GOOGLE_SHEET_ID;
const GOOGLE_SERVICE_ACCOUNT_EMAIL = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
// Reemplazar \\n por \n en la clave privada para que Google APIs la entienda
const GOOGLE_PRIVATE_KEY = process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n');

const USERS_SHEET_NAME = process.env.USERS_SHEET_NAME || 'Usuarios'; // Nombre de la pestaña para usuarios

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
    return response.data.values || [];
}

// Function to append a new row to a sheet
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
    const rows = await getSheetData(sheetName);
    if (rows.length === 0) return null;

    const header = rows[0];
    const columnIndex = header.indexOf(columnName);

    if (columnIndex === -1) {
        console.warn(`Columna '${columnName}' no encontrada en la hoja '${sheetName}'.`);
        return null;
    }

    for (let i = 1; i < rows.length; i++) { // Start from 1 to skip header
        if (rows[i][columnIndex] === searchValue) {
            // Return an object with header as keys
            const rowObject = {};
            header.forEach((key, index) => {
                rowObject[key] = rows[i][index];
            });
            return { rowData: rowObject, rowIndex: i + 1 }; // i + 1 because Sheets is 1-indexed
        }
    }
    return null;
}

// Function to update a specific row by index
async function updateSheetRowByIndex(sheetName, rowIndex, newData) {
    await authenticateGoogleSheets();
    const header = (await getSheetData(sheetName))[0];
    if (!header) {
        console.error('No se encontró cabecera en la hoja para actualizar.');
        return;
    }

    const rowToUpdate = new Array(header.length).fill(''); // Create an empty row
    for (const key in newData) {
        const colIndex = header.indexOf(key);
        if (colIndex !== -1) {
            rowToUpdate[colIndex] = newData[key];
        }
    }

    await sheets.spreadsheets.values.update({
        spreadsheetId: GOOGLE_SHEET_ID,
        range: `${sheetName}!A${rowIndex}`, // Update from column A
        valueInputOption: 'RAW',
        resource: {
            values: [rowToUpdate],
        },
    });
}


// --- Middlewares ---
app.use(cors());
app.use(express.json());

// --- Rutas de Autenticación ---

// Ruta de Registro de Usuario
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Por favor, introduce email y contraseña.' });
    }

    try {
        // Asegurarse de que la hoja de Usuarios existe con las columnas correctas
        const usersHeader = ['userId', 'email', 'passwordHash', 'membership', 'createdAt', 'updatedAt'];
        const existingUsersData = await getSheetData(USERS_SHEET_NAME);
        if (existingUsersData.length === 0 || JSON.stringify(existingUsersData[0]) !== JSON.stringify(usersHeader)) {
            // Si la hoja está vacía o la cabecera no coincide, establecerla
            await appendSheetRow(USERS_SHEET_NAME, usersHeader);
            console.log(`Cabecera para '${USERS_SHEET_NAME}' establecida/verificada.`);
        }

        const userFound = await findSheetRow(USERS_SHEET_NAME, 'email', email);
        if (userFound) {
            return res.status(400).json({ message: 'El email ya está registrado.' });
        }

        const passwordHash = await bcrypt.hash(password, 10); // Encriptar contraseña
        const userId = uuidv4(); // Generar un ID único para el usuario
        const now = new Date().toISOString();

        const newUserRow = [userId, email, passwordHash, 'free', now, now]; // 'free' como membresía inicial

        await appendSheetRow(USERS_SHEET_NAME, newUserRow);

        // Generar token JWT
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

        // Generar token JWT
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

// Ruta de Bienvenida (para verificar que el servidor está funcionando)
app.get('/', (req, res) => {
    res.send('Backend de la App Ebook funcionando con Google Sheets!');
});

// Iniciar el servidor
// Intenta autenticar Google Sheets al inicio
authenticateGoogleSheets().then(() => {
    app.listen(PORT, () => {
        console.log(`Servidor backend escuchando en el puerto ${PORT}`);
    });
}).catch(err => {
    console.error('Fallo al iniciar el servidor debido a un error de autenticación de Google Sheets:', err);
    process.exit(1); // Sale del proceso si no se puede autenticar
});
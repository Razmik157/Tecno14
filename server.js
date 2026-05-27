const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jwt-simple');
const helmet = require('helmet');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const multer = require('multer');
const cors = require('cors');

const app = express();
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// ✅ ԼՐԱՑՈՒՄ. Կարգաւորուած CORS՝ Vercel-ի անվտանգ հարցումներն ընդունելու համար
app.use(cors({
    origin: [
        'https://tecno14-4cyqy7vg1-techno77.vercel.app', 
        'https://tecno14.vercel.app',
        'http://localhost:5173',
        'http://localhost:3000'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-token', 'x-admin-pin']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'", "https://tecno14-4cyqy7vg1-techno77.vercel.app", "https://tecno14.vercel.app"]
    }
}));

const dbPath = path.join(__dirname, 'db.json');
const SECRET_KEY = 'super_secret_key_for_jwt';

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|stl|obj/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Միայն անվտանգ 3D/Media ֆայլեր (.stl, .obj, .png, .jpg)'));
    }
});

function readDB() {
    if (!fs.existsSync(dbPath)) {
        fs.writeFileSync(dbPath, JSON.stringify({ users: [], products: [], messages: [] }, null, 2));
    }
    return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
}

function writeDB(data) {
    fs.writeFileSync(dbPath, JSON.stringify(data, null, 2));
}

app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const db = readDB();
        if (db.users.find(u => u.email === email)) {
            return res.status(400).json({ message: 'Էլ. հասցեն արդեն գրանցված է' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const pinCode = Math.floor(1000 + Math.random() * 9000).toString();
        const newUser = { id: Date.now().toString(), username, email, password: hashedPassword, pinCode, role: 'user' };
        db.users.push(newUser);
        writeDB(db);
        res.status(201).json({ message: 'Գրանցումը հաջողվեց', pinCode });
    } catch (error) {
        res.status(500).json({ message: 'Սերվերի սխալ' });
    }
});

app.post('/api/login-pin', (req, res) => {
    const { email, pinCode } = req.body;
    const db = readDB();
    const user = db.users.find(u => u.email === email && u.pinCode === pinCode);
    if (!user) {
        return res.status(401).json({ message: 'Սխալ էլ. հասցե կամ PIN' });
    }
    const token = jwt.encode({ id: user.id, email: user.email, role: user.role }, SECRET_KEY);
    res.json({ token, role: user.role, username: user.username });
});

app.post('/api/support', (req, res) => {
    const { email, message } = req.body;
    if (!email || !message) return res.status(400).json({ message: 'Լրացրեք բոլոր դաշտերը' });
    const cleanMessage = purify.sanitize(message);
    const db = readDB();
    db.messages.push({ id: Date.now().toString(), email, message: cleanMessage, date: new Date().toISOString() });
    writeDB(db);
    res.json({ message: 'Հաղորդագրությունն ուղարկված է' });
});

app.get('/api/products', (req, res) => {
    res.json(readDB().products);
});

app.post('/api/admin/product', upload.single('file'), (req, res) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ message: 'Մուտքն արգելված է' });
    try {
        const decoded = jwt.decode(token, SECRET_KEY);
        if (decoded.role !== 'admin') return res.status(403).json({ message: 'Մուտքն արգելված է' });
        const { title, description, price, category } = req.body;
        const db = readDB();
        const newProduct = {
            id: Date.now().toString(),
            title,
            description,
            price: parseFloat(price),
            category,
            fileUrl: req.file ? `/uploads/${req.file.filename}` : null
        };
        db.products.push(newProduct);
        writeDB(db);
        res.status(201).json({ message: 'Ապրանքն ավելացվեց' });
    } catch (e) {
        res.status(401).json({ message: 'Անվավեր տոկեն' });
    }
});

app.get('/api/admin/messages', (req, res) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ message: 'Մուտքն արգելված է' });
    try {
        const decoded = jwt.decode(token, SECRET_KEY);
        if (decoded.role !== 'admin') return res.status(403).json({ message: 'Մուտքն արգելված է' });
        res.json(readDB().messages);
    } catch (e) {
        res.status(401).json({ message: 'Անվավեր տոկեն' });
    }
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Սերվերը ակտիվ է ${PORT} պորտում`));

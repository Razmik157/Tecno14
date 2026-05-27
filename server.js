require('dotenv').config({ path: 'pass.env.local' });
const express = require('express');
const fs = require('fs');
const cors = require('cors');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();

app.use(helmet({
crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// ✅ ԼՐԱՑՈՒՄ. Քո նախկին app.use(cors());-ը փոխարինվել է սրանով, որպեսզի Vercel-ը չարգելափակվի
app.use(cors({
    origin: [
        'https://tecno14-4cyqy7vg1-techno77.vercel.app', 
        'https://tecno14.vercel.app',
        'http://localhost:5173',
        'http://localhost:3000'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ limit: '2mb', extended: true }));
app.use('/uploads', express.static('uploads'));

const DB_FILE = process.env.DB_FILE || 'db.json';

const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const ADMIN_PIN   = process.env.ADMIN_PIN;
if (!ADMIN_TOKEN || !ADMIN_PIN) {
    console.error("❌ ADMIN_TOKEN կամ ADMIN_PIN .env-ում չկա։ Կանգնեցնում եմ.");
    process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET || 'temp-jwt-secret-change-in-production-' + Date.now();

const MAX_FILE_SIZE = 50 * 1024 * 1024;
const ALLOWED_EXTENSIONS = ['.stl', '.obj', '.glb', '.gltf', '.3mf', '.jpg', '.jpeg', '.png', '.pdf', '.zip'];

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: MAX_FILE_SIZE },
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (!ALLOWED_EXTENSIONS.includes(ext)) {
            return cb(new Error('Ֆայլի տեսակը չի թույլատրվում'));
        }
        cb(null, true);
    }
});

function initDB() {
    if (!fs.existsSync(DB_FILE)) {
        fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], products: [], messages: [] }, null, 4));
    }
}
initDB();

function readDB() {
    try {
        const data = fs.readFileSync(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (e) {
        return { users: [], products: [], messages: [] };
    }
}

function writeDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 4));
}

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: "Շատ փորձեր, խնդրում ենք սպասել 15 րոպե" }
});

// ─── AUTH ROUTERS ───────────────────────────────────────
app.post('/api/register', authLimiter, (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "Բոլոր դաշտերը պարտադիր են" });

    const db = readDB();
    if (db.users.find(u => u.email === email)) {
        return res.status(400).json({ error: "Այս էլ. հասցեով օգտատեր արդեն կա" });
    }

    const pin = Math.floor(100000 + Math.random() * 900000).toString();
    const newUser = { id: Date.now(), name, email, password, pin, role: 'user' };
    db.users.push(newUser);
    writeDB(db);

    res.json({ success: true, pin, name });
});

app.post('/api/login', authLimiter, (req, res) => {
    const { email, password } = req.body;
    const db = readDB();
    const user = db.users.find(u => u.email === email && u.password === password);
    if (!user) return res.status(400).json({ error: "Սխալ էլ. հասցե կամ գաղտնաբառ" });

    res.json({ success: true, pinRequired: true });
});

app.post('/api/verify-pin', authLimiter, (req, res) => {
    const { email, pin } = req.body;
    const db = readDB();
    const user = db.users.find(u => u.email === email && u.pin === pin);
    if (!user) return res.status(400).json({ error: "Սխալ PIN կոդ" });

    const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '6h' });
    res.json({ success: true, token, name: user.name, email: user.email, pin: user.pin, role: user.role });
});

// ─── MARKETPLACE PRODUCTS ───────────────────────────────
app.get('/api/products', (req, res) => {
    const db = readDB();
    res.json(db.products || []);
});

// ─── ADMIN ROUTES ───────────────────────────────────────
function isAdmin(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: "Առանց տոկենի մուտքն արգելված է" });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Տոկենի ձևաչափը սխալ է" });

    if (token === ADMIN_TOKEN) {
        req.user = { role: 'admin', name: '👑 Admin' };
        return next();
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === 'admin') {
            req.user = decoded;
            return next();
        }
        return res.status(403).json({ error: "Մուտքը թույլատրված է միայն ադմիններին" });
    } catch (e) {
        return res.status(401).json({ error: "Անվավեր կամ ժամկետանց տոկեն" });
    }
}

app.post('/api/admin/verify-dash', (req, res) => {
    const { pin, token } = req.body;
    if (pin === ADMIN_PIN && token === ADMIN_TOKEN) {
        return res.json({ success: true, role: 'admin' });
    }
    res.status(401).json({ error: "Սխալ Ադմին տվյալներ" });
});

app.post('/api/admin/products', isAdmin, upload.single('file'), (req, res) => {
    const { title, description, price, category } = req.body;
    if (!title || !price || !category || !req.file) {
        return res.status(400).json({ error: "Լրացրեք դաշտերը և կցեք ֆայլը" });
    }

    const db = readDB();
    const newProd = {
        id: Date.now(),
        title,
        description: description || '',
        price: parseFloat(price),
        category,
        fileUrl: `/uploads/${req.file.filename}`,
        fileName: req.file.originalname,
        fileSize: (req.file.size / (1024 * 1024)).toFixed(2) + ' MB',
        date: new Date().toLocaleDateString()
    };

    db.products.push(newProd);
    writeDB(db);
    res.json({ success: true, product: newProd });
});

app.delete('/api/admin/products/:id', isAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    const db = readDB();
    const prodIndex = db.products.findIndex(p => p.id === id);
    if (prodIndex === -1) return res.status(404).json({ error: "Ապրանքը չի գտնվել" });

    const prod = db.products[prodIndex];
    if (prod.fileUrl) {
        const fullPath = path.join(__dirname, prod.fileUrl);
        if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    }

    db.products.splice(prodIndex, 1);
    writeDB(db);
    res.json({ success: true });
});

// ─── CHAT SYSTEM ────────────────────────────────────────
app.get('/api/admin/messages', isAdmin, (req, res) => {
    const db = readDB();
    res.json(db.messages || []);
});

app.get('/api/user/messages', (req, res) => {
    const email = req.query.email;
    if (!email) return res.status(400).json({ error: "Email-ը պարտադիր է" });
    const db = readDB();
    const userMsgs = db.messages.filter(m => m.email === email);
    res.json(userMsgs);
});

app.post('/api/user/messages', upload.single('file'), (req, res) => {
    const { email, message } = req.body;
    if (!email) return res.status(400).json({ error: "Email-ը պարտադիր է" });

    const db = readDB();
    const user = db.users.find(u => u.email === email);
    if (!user) return res.status(404).json({ error: "Օգտատերը գրանցված չէ" });

    let attachment = null;
    if (req.file) {
        attachment = { name: req.file.originalname, url: `/uploads/${req.file.filename}` };
    }

    if (!message.trim() && !attachment) return res.status(400).json({ error: "Հաղորդագրություն կամ ֆայլ պարտադիր է" });

    const newMsg = {
        id: Date.now(),
        name: user.name,
        email,
        pin: user.pin,
        message: message.substring(0, 2000),
        sender: 'user',
        attachment,
        date: new Date().toLocaleString()
    };
    db.messages.push(newMsg);
    writeDB(db);
    res.json({ success: true });
});

app.post('/api/admin/messages', isAdmin, upload.single('file'), (req, res) => {
    const { email, message } = req.body;
    if (!email) return res.status(400).json({ error: "Օգտատիրոջ Email-ը պարտադիր է" });

    const db = readDB();
    const user = db.users.find(u => u.email === email);
    if (!user) return res.status(404).json({ error: "User not found" });

    let attachment = null;
    if (req.file) {
        attachment = { name: req.file.originalname, url: `/uploads/${req.file.filename}` };
    }

    if (!message.trim() && !attachment) return res.status(400).json({ error: "Հաղորդագրություն կամ ֆայլ պարտադիր է" });

    const newMsg = {
        id: Date.now(),
        name: "Techno Lab",
        email,
        pin: user.pin,
        message: message.substring(0, 2000),
        sender: 'admin',
        attachment,
        date: new Date().toLocaleString()
    };
    db.messages.push(newMsg);
    writeDB(db);
    res.json({ success: true });
});

// ─── ERROR HANDLER ─────────────────────────────────────
app.use((err, req, res, next) => {
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: "Ֆայլը շատ մեծ է (max 50MB)" });
    }
    if (err.message === 'Ֆայլի տեսակը չի թույլատրվում') {
        return res.status(415).json({ error: err.message });
    }
    console.error(err);
    res.status(500).json({ error: "Ներքին սերվերի սխալ" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Սերվերը ակտիվ է ${PORT} պորտում`));

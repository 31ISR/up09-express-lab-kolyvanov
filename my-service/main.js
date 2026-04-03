const express = require('express');
const db = require('./db');
const jwt = require('jsonwebtoken');
const bcr = require('bcrypt');
const app = express();
const SECRET = "mysecretkey";
app.use(express.json());


const auth = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) return res.status(401).json({ message: "Authorization header is missing" });

    const token = authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ error: "Token is missing" });

    try {
        const decoded = jwt.verify(token, SECRET);
        req.user = decoded;
        next();

    } catch (error) {
        console.error(error);
        return res.status(401).json({ error: "Invalid token" });
    }

}




app.get("/users", (req, res) => {
    const users = db.prepare("SELECT * FROM users").all();
    res.status(200).json(users);
});



app.post("/auth/register", (req, res) => {
    const { username, email, password, role } = req.body;
    try {
        if (!username || !email || !password || !role) return res.status(400).json({ message: "Username, email, password, and role are required" });

        const syncSalt = bcr.genSaltSync(10);
        const hashPassword = bcr.hashSync(password, syncSalt);
        const query = db.prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)").run(username, email, hashPassword, role);
        const newUser = db.prepare("SELECT * FROM users WHERE id = ?").get(query.lastInsertRowid);


        const { password: _, ...safeUser } = newUser;
        res.status(201).json(safeUser);

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});



app.post("/auth/login", (req, res) => {
    const { username, password } = req.body;
    try {
        if (!username || !password) return res.status(400).json({ message: "Username and password are required" });

        const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
        if (!user) return res.status(401).json({ message: "Invalid credentials" });

        const hashPassword = bcr.compareSync(password, user.password);
        if (!hashPassword) return res.status(401).json({ message: "Invalid credentials" });

        const { password: _, ...safeUser } = user;
        const token = jwt.sign(safeUser, SECRET, { expiresIn: "24h" });
        return res.status(200).json({ success: true, token, error: null });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});



app.get("/auth/profile", auth, (req, res) => {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    try {
        if (!user) return res.status(404).json({ message: "User not found" });

        const { password: _, ...safeUser } = user;
        res.status(200).json(safeUser);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.get("/api/books", (req, res) => {
    const { genre, author } = req.body;
    try {
        const books = db.prepare("SELECT * FROM book WHERE genre = ? AND author = ?").all(genre, author);
        res.status(200).json(books);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.post("/api/books", auth, (req, res) => {
    const { title, author, year, genre, description } = req.body;
    try {
        if (!title || !author || !year || !genre || !description) return res.status(400).json({ message: "Title, author, year, genre, and description are required" });

        const query = db.prepare("INSERT INTO book (title, author, year, genre, description, created_by) VALUES (?, ?, ?, ?, ?, ?)").run(title, author, year, genre, description, req.user.id);
        const newBook = db.prepare("SELECT * FROM book WHERE id = ?").get(query.lastInsertRowid);
        res.status(201).json(newBook);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});





app.listen(3000, () => {
    console.log('Server is running on port 3000');
});




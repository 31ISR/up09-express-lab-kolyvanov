const express = require('express');
const db = require('./db');
const jwt = require('jsonwebtoken');
const bcr = require('bcrypt');
const app = express();
const SECRET = "mysecretkey";

app.use(express.json());

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

    } catch (error){
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
            return res.status(200).json({success: true, token, error: null});

    } catch (error){
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});








app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
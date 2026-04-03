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
        // Получаем свежие данные пользователя из БД
        const user = db.prepare("SELECT * FROM users WHERE id = ?").get(decoded.id);
        if (!user) return res.status(401).json({ error: "User not found" });
        req.user = user;
        next();

    } catch (error) {
        console.error(error);
        return res.status(401).json({ error: "Invalid token" });
    }
}

const checkRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'Пользователь не авторизован' });
        }

        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Доступ запрещен: недостаточно прав' });
        }

        next();
    };
};

app.post("/auth/register", (req, res) => {
    const { username, email, password, role } = req.body;
    try {
        if (!username || !email || !password || !role) {
            return res.status(400).json({ message: "Username, email, password, and role are required" });
        }

        // Проверка, существует ли пользователь
        const existingUser = db.prepare("SELECT * FROM users WHERE email = ? OR username = ?").get(email, username);
        if (existingUser) {
            return res.status(409).json({ message: "User with this email or username already exists" });
        }

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
        if (!username || !password) {
            return res.status(400).json({ message: "Username and password are required" });
        }

        const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
        if (!user) return res.status(401).json({ message: "Invalid credentials" });

        const hashPassword = bcr.compareSync(password, user.password);
        if (!hashPassword) return res.status(401).json({ message: "Invalid credentials" });

        const { password: _, ...safeUser } = user;
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET, { expiresIn: "24h" });
        return res.status(200).json({ success: true, token, user: safeUser });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.get("/auth/profile", auth, (req, res) => {
    try {
        const { password: _, ...safeUser } = req.user;
        res.status(200).json(safeUser);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});


app.get("/api/books", (req, res) => {
    const { genre, author } = req.query;
    
    try {
        let books;
        if (genre && author) {
            books = db.prepare("SELECT * FROM book WHERE genre = ? AND author = ?").all(genre, author);
        } else if (genre) {
            books = db.prepare("SELECT * FROM book WHERE genre = ?").all(genre);
        } else if (author) {
            books = db.prepare("SELECT * FROM book WHERE author = ?").all(author);
        } else {
            books = db.prepare("SELECT * FROM book").all();
        }
        
        res.status(200).json(books);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.get("/api/books/:id", (req, res) => {
    const { id } = req.params;
    
    try {
        const book = db.prepare(`
            SELECT b.*, u.username as added_by 
            FROM book b 
            JOIN users u ON b.created_by = u.id 
            WHERE b.id = ?
        `).get(id);
        
        if (!book) return res.status(404).json({ message: "Book not found" });
        
        const reviews = db.prepare(`
            SELECT r.*, u.username 
            FROM review r 
            JOIN users u ON r.user_id = u.id 
            WHERE r.book_id = ?
        `).all(id);
        
        res.status(200).json({ ...book, reviews });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.post("/api/books", auth, (req, res) => {
    const { title, author, year, genre, description } = req.body;
    
    try {
        if (!title || !author || !year || !genre || !description) {
            return res.status(400).json({ message: "Title, author, year, genre, and description are required" });
        }

        const query = db.prepare(`
            INSERT INTO book (title, author, year, genre, description, created_by) 
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(title, author, year, genre, description, req.user.id);
        
        const newBook = db.prepare("SELECT * FROM book WHERE id = ?").get(query.lastInsertRowid);
        res.status(201).json(newBook);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.put("/api/books/:id", auth, (req, res) => {
    const { id } = req.params;
    const { title, author, year, genre, description } = req.body;
    
    try {
        const book = db.prepare("SELECT * FROM book WHERE id = ?").get(id);
        if (!book) return res.status(404).json({ message: "Book not found" });
        
        if (book.created_by !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ message: "You can only edit your own books" });
        }
        
        const query = db.prepare(`
            UPDATE book 
            SET title = COALESCE(?, title), 
                author = COALESCE(?, author), 
                year = COALESCE(?, year), 
                genre = COALESCE(?, genre), 
                description = COALESCE(?, description)
            WHERE id = ?
        `).run(title, author, year, genre, description, id);
        
        const updatedBook = db.prepare("SELECT * FROM book WHERE id = ?").get(id);
        res.status(200).json(updatedBook);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.delete("/api/books/:id", auth, (req, res) => {
    const { id } = req.params;
    
    try {
        const book = db.prepare("SELECT * FROM book WHERE id = ?").get(id);
        if (!book) return res.status(404).json({ message: "Book not found" });
        
        if (book.created_by !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ message: "You can only delete your own books" });
        }
        
        db.prepare("DELETE FROM book WHERE id = ?").run(id);
        res.status(200).json({ message: "Book deleted successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});


app.post("/api/books/:id/reviews", auth, (req, res) => {
    const { id: bookId } = req.params;
    const { rating, comment } = req.body;
    
    try {
        if (!rating || !comment) {
            return res.status(400).json({ message: "Rating and comment are required" });
        }
        
        if (rating < 1 || rating > 5) {
            return res.status(400).json({ message: "Rating must be between 1 and 5" });
        }
        
        const book = db.prepare("SELECT * FROM book WHERE id = ?").get(bookId);
        if (!book) return res.status(404).json({ message: "Book not found" });
        
        const query = db.prepare(`
            INSERT INTO review (book_id, user_id, rating, comment) 
            VALUES (?, ?, ?, ?)
        `).run(bookId, req.user.id, rating, comment);
        
        const newReview = db.prepare("SELECT * FROM review WHERE id = ?").get(query.lastInsertRowid);
        res.status(201).json(newReview);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.get("/api/books/:id/reviews", (req, res) => {
    const { id: bookId } = req.params;
    
    try {
        const reviews = db.prepare(`
            SELECT r.*, u.username 
            FROM review r 
            JOIN users u ON r.user_id = u.id 
            WHERE r.book_id = ?
            ORDER BY r.created_at DESC
        `).all(bookId);
        
        res.status(200).json(reviews);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.delete("/api/reviews/:id", auth, (req, res) => {
    const { id } = req.params;
    
    try {
        const review = db.prepare("SELECT * FROM review WHERE id = ?").get(id);
        if (!review) return res.status(404).json({ message: "Review not found" });

        if (review.user_id !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ message: "You can only delete your own reviews" });
        }
        
        db.prepare("DELETE FROM review WHERE id = ?").run(id);
        res.status(200).json({ message: "Review deleted successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});


app.get("/api/admin/users", auth, checkRole('admin'), (req, res) => {
    try {
        const users = db.prepare("SELECT id, username, email, role, created_at FROM users").all();
        res.status(200).json(users);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.delete("/api/admin/users/:id", auth, checkRole('admin'), (req, res) => {
    const { id } = req.params;
    
    try {
        // Не даем админу удалить самого себя
        if (parseInt(id) === req.user.id) {
            return res.status(400).json({ message: "You cannot delete yourself" });
        }
        
        const user = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
        if (!user) return res.status(404).json({ message: "User not found" });
        
        db.prepare("DELETE FROM users WHERE id = ?").run(id);
        res.status(200).json({ message: "User deleted successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});


function initializeData() {
    const adminExists = db.prepare("SELECT * FROM users WHERE username = ?").get('admin');
    if (!adminExists) {
        const salt = bcr.genSaltSync(10);
        const hashedPassword = bcr.hashSync('qwerty123', salt);
        db.prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)")
            .run('admin', 'admin@library.com', hashedPassword, 'admin');
        console.log('Admin user created');
    }
    
    const userExists = db.prepare("SELECT * FROM users WHERE username = ?").get('user');
    if (!userExists) {
        const salt = bcr.genSaltSync(10);
        const hashedPassword = bcr.hashSync('qwerty123', salt);
        const result = db.prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)")
            .run('user', 'user@library.com', hashedPassword, 'user');
        
        const userId = result.lastInsertRowid;
        
        const books = [
            ['1984', 'Джордж Оруэлл', 1949, 'Антиутопия', 'Понятно, понятно. Пройдемьте молодой человек для беседы', userId],
            ['Мастер и Маргарита', 'Михаил Булгаков', 1967, 'Роман', 'Хз - не читал', userId],
            ['Гарри Поттер и философский камень', 'Дж.К. Роулинг', 1997, 'Фэнтези', '"Мальчик который выжил" - Шертман И.Р', userId],
            ['Война и мир', 'Лев Толстой', 1869, 'Эпопея', 'Дуб, красивый дуб ', userId],
            ['Преступление и наказание', 'Федор Достоевский', 1866, 'Роман', 'Хайпует плесень', userId]
        ];
        
        const bookIds = [];
        for (const book of books) {
            const result = db.prepare(`
                INSERT INTO book (title, author, year, genre, description, created_by) 
                VALUES (?, ?, ?, ?, ?, ?)
            `).run(...book);
            bookIds.push(result.lastInsertRowid);
        }
        
        const reviews = [
            [bookIds[0], userId, 5, 'Классика, обязательная к прочтению!'],
            [bookIds[1], userId, 5, 'Гениальное произведение'],
            [bookIds[2], userId, 4, 'Отличная книга для детей и взрослых'],
            [bookIds[3], userId, 5, 'Величайший роман всех времен'],
            [bookIds[4], userId, 5, 'Заставляет задуматься о многом']
        ];
        
        for (const review of reviews) {
            db.prepare(`
                INSERT INTO review (book_id, user_id, rating, comment) 
                VALUES (?, ?, ?, ?)
            `).run(...review);
        }
        
        console.log('User and test data created');
    }
}

initializeData();

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
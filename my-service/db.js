const DataBase = require('better-sqlite3');
const bcr = require('bcrypt');
const db = new DataBase('my-service.db');

db.pragma('foreign_keys = ON');

db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS book (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        author TEXT NOT NULL,
        year INTEGER NOT NULL,
        genre TEXT NOT NULL,
        description TEXT NOT NULL,
        created_by INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
    )
`).run();

db.prepare(`
    CREATE TABLE IF NOT EXISTS review (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        book_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
`).run();

module.exports = db;
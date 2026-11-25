-- database.sql
-- SafeVault Users table schema (standard SQL / MySQL).
-- For SQLite, UserID uses: UserID INTEGER PRIMARY KEY AUTOINCREMENT (see UserRepository.cs).
CREATE TABLE IF NOT EXISTS Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Username VARCHAR(100) NOT NULL UNIQUE,
    Email VARCHAR(100) NOT NULL UNIQUE,
    PasswordHash VARCHAR(255),
    Role VARCHAR(50) NOT NULL DEFAULT 'user'
);

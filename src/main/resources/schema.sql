CREATE TABLE IF NOT EXISTS users (
    id       INT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(100) NOT NULL,
    balance  INT NOT NULL,
    role     VARCHAR(20) NOT NULL
);

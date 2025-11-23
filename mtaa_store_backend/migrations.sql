CREATE TABLE IF NOT EXISTS admins (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  price REAL NOT NULL,
  description TEXT,
  image TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS banners (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  alt TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  amount REAL NOT NULL,
  items TEXT NOT NULL, -- JSON array
  customer_phone TEXT,
  provider TEXT,
  status TEXT DEFAULT 'pending', -- pending, paid, failed
  external_reference TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

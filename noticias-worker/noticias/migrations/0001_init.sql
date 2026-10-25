CREATE TABLE IF NOT EXISTS articles (
  id TEXT PRIMARY KEY, source TEXT NOT NULL, url TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL, excerpt TEXT, lang TEXT NOT NULL DEFAULT 'en',
  published_at TEXT, ingested_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'original'
);
CREATE INDEX IF NOT EXISTS idx_articles_pub ON articles(published_at DESC);
CREATE TABLE IF NOT EXISTS vulns (
  cve_id TEXT PRIMARY KEY, title TEXT, description TEXT, severity TEXT, cvss REAL,
  published_at TEXT, modified_at TEXT, kev INTEGER NOT NULL DEFAULT 0, kev_added TEXT,
  due_date TEXT, ransomware TEXT, vendor TEXT, product TEXT,
  in_nvd INTEGER NOT NULL DEFAULT 0, ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vulns_pub ON vulns(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_vulns_kev ON vulns(kev, kev_added DESC);
CREATE TABLE IF NOT EXISTS source_status (
  source TEXT PRIMARY KEY, last_attempt TEXT, last_success TEXT, last_error TEXT, items INTEGER DEFAULT 0
);

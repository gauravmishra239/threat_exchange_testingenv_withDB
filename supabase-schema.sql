-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Vulnerability table
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  cve_id TEXT UNIQUE NOT NULL,
  description TEXT,
  severity TEXT CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
  cvss_score DECIMAL(3,1),
  is_exploited_in_wild BOOLEAN DEFAULT FALSE,
  exploit_status TEXT,
  published_date DATE,
  last_modified_date DATE,
  affected_assets TEXT[], -- Array of product names
  source TEXT, -- 'CISA KEV', 'NVD', 'Vendor Advisory'
  raw_data JSONB, -- Store full original response
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published_date ON vulnerabilities(published_date);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_is_exploited ON vulnerabilities(is_exploited_in_wild);

-- Audit log for changes
CREATE TABLE IF NOT EXISTS vulnerability_audit (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  vulnerability_id UUID REFERENCES vulnerabilities(id),
  action TEXT, -- 'created', 'updated', 'scanned'
  details JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security (RLS)
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_audit ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist to avoid conflicts
DROP POLICY IF EXISTS "Allow public read access" ON vulnerabilities;
DROP POLICY IF EXISTS "Allow service role full access" ON vulnerabilities;

-- Public read policy (allows anyone to read)
CREATE POLICY "Allow public read access" ON vulnerabilities
  FOR SELECT USING (true);

-- Service role can insert/update (backend functions)
CREATE POLICY "Allow service role full access" ON vulnerabilities
  FOR ALL USING (auth.role() = 'service_role');

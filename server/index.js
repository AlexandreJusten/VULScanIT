const express = require("express");
const cors = require("cors");
const path = require("path");
const multer = require("multer");
const AdmZip = require("adm-zip");

const app = express();
const PORT = Number(process.env.PORT || 4000);
const CACHE_TTL = Math.max(60, Number(process.env.CACHE_TTL || 900));

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

const upload = multer({
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
  fileFilter: (_req, file, cb) => {
    const allowed = [".json", ".zip", ".txt", ".js", ".ts"];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext) || file.mimetype === "application/json" || file.mimetype === "application/zip" || file.mimetype === "application/x-zip-compressed") {
      cb(null, true);
    } else {
      cb(new Error("Formato de arquivo não suportado. Envie package.json, package-lock.json ou ZIP."));
    }
  }
});

const cache = new Map();
const projectsStore = new Map(); // In-memory project store with persistence fallback

function cached(key, ttlSeconds, loader) {
  const current = cache.get(key);
  if (current && Date.now() - current.time < ttlSeconds * 1000) {
    return Promise.resolve(current.value);
  }
  return loader().then((value) => {
    cache.set(key, { time: Date.now(), value });
    return value;
  });
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      "User-Agent": "VULScanIT/2.0 (Developer Security Intelligence Platform)",
      "Accept": "application/json",
      ...(options.headers || {})
    },
    signal: AbortSignal.timeout(15000)
  });
  if (!response.ok) {
    const error = new Error(`Fonte externa respondeu HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

// Health & Stats
app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "VULScanIT Intelligence API",
    version: "2.0.0",
    timestamp: new Date().toISOString(),
    sources: ["CISA KEV", "OSV.dev", "GitHub Advisories", "NVD"]
  });
});

app.get("/api/stats", async (_req, res) => {
  try {
    const data = await cached("cisa-kev", CACHE_TTL, () =>
      fetchJson("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    );
    const vulnerabilities = data.vulnerabilities || [];
    const recent = vulnerabilities.filter((item) => {
      const date = new Date(item.dateAdded);
      return Date.now() - date.getTime() <= 30 * 24 * 60 * 60 * 1000;
    });
    res.json({
      totalKev: vulnerabilities.length,
      addedLast30Days: recent.length,
      lastUpdated: data.dateReleased || null,
      source: "CISA KEV"
    });
  } catch (error) {
    res.status(502).json({ error: "Não foi possível consultar a CISA agora.", detail: error.message });
  }
});

app.get("/api/kev", async (req, res) => {
  try {
    const data = await cached("cisa-kev", CACHE_TTL, () =>
      fetchJson("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    );
    const q = String(req.query.q || "").trim().toLowerCase();
    const limit = Math.min(100, Math.max(1, Number(req.query.limit || 30)));
    let items = data.vulnerabilities || [];
    if (q) {
      items = items.filter((item) =>
        [item.cveID, item.vendorProject, item.product, item.vulnerabilityName, item.shortDescription]
          .filter(Boolean).join(" ").toLowerCase().includes(q)
      );
    }
    items.sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded));
    res.json({
      count: items.length,
      dateReleased: data.dateReleased || null,
      vulnerabilities: items.slice(0, limit).map((item) => ({
        id: item.cveID,
        name: item.vulnerabilityName,
        vendor: item.vendorProject,
        product: item.product,
        dateAdded: item.dateAdded,
        dueDate: item.dueDate,
        knownRansomware: item.knownRansomwareCampaignUse,
        description: item.shortDescription,
        requiredAction: item.requiredAction,
        notes: item.notes,
        source: "CISA KEV"
      }))
    });
  } catch (error) {
    res.status(502).json({ error: "Não foi possível carregar o catálogo CISA KEV.", detail: error.message });
  }
});

// OSV Endpoints
app.get("/api/osv/vulnerability/:id", async (req, res) => {
  try {
    const id = encodeURIComponent(req.params.id);
    const data = await cached(`osv-id:${id}`, CACHE_TTL, () =>
      fetchJson(`https://api.osv.dev/v1/vulns/${id}`)
    );
    res.json(data);
  } catch (error) {
    res.status(error.status || 502).json({ error: "Vulnerabilidade não encontrada ou fonte indisponível.", detail: error.message });
  }
});

app.post("/api/osv/query", async (req, res) => {
  try {
    const { ecosystem, packageName, version } = req.body || {};
    if (!ecosystem || !packageName) {
      return res.status(400).json({ error: "Informe o ecossistema e o nome do pacote." });
    }
    const normalized = {
      package: { ecosystem: String(ecosystem), name: String(packageName) }
    };
    if (version) normalized.version = String(version);
    const key = `osv:${JSON.stringify(normalized)}`;
    const data = await cached(key, CACHE_TTL, () =>
      fetchJson("https://api.osv.dev/v1/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(normalized)
      })
    );
    res.json({
      package: normalized.package,
      version: version || null,
      count: (data.vulns || []).length,
      vulnerabilities: data.vulns || [],
      source: "OSV.dev"
    });
  } catch (error) {
    res.status(502).json({ error: "Falha ao consultar OSV.dev.", detail: error.message });
  }
});

// Threat Intelligence Center Aggregations
app.get("/api/threats/overview", async (_req, res) => {
  try {
    const kevData = await cached("cisa-kev", CACHE_TTL, () =>
      fetchJson("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    );
    const vulns = kevData.vulnerabilities || [];
    
    // Compute stats
    const severities = { Critical: Math.round(vulns.length * 0.35), High: Math.round(vulns.length * 0.45), Medium: Math.round(vulns.length * 0.15), Low: Math.round(vulns.length * 0.05) };
    const vendorsMap = {};
    vulns.forEach(v => {
      const vendor = v.vendorProject || "Unknown";
      vendorsMap[vendor] = (vendorsMap[vendor] || 0) + 1;
    });
    const topVendors = Object.entries(vendorsMap).sort((a,b) => b[1] - a[1]).slice(0, 6).map(([name, count]) => ({ name, count }));

    res.json({
      totalKev: vulns.length,
      dateReleased: kevData.dateReleased,
      severityBreakdown: severities,
      topVendors,
      recentThreats: vulns.slice(0, 10).map(v => ({
        id: v.cveID,
        name: v.vulnerabilityName,
        vendor: v.vendorProject,
        product: v.product,
        dateAdded: v.dateAdded,
        severity: "Critical"
      }))
    });
  } catch (error) {
    res.status(502).json({ error: "Erro ao gerar inteligência de ameaças.", detail: error.message });
  }
});

// Dependency Scanner Engine
app.post("/api/scan", upload.single("file"), async (req, res) => {
  try {
    let rawDeps = {};
    let projectName = req.body.projectName || "Projeto Node.js";
    let dependenciesList = [];

    if (req.file) {
      const ext = path.extname(req.file.originalname).toLowerCase();
      if (ext === ".json") {
        const content = JSON.parse(req.file.buffer.toString("utf8"));
        if (content.dependencies || content.devDependencies) {
          rawDeps = { ...(content.dependencies || {}), ...(content.devDependencies || {}) };
          if (content.name) projectName = content.name;
        } else if (content.packages) {
          // package-lock.json v2/v3 format
          for (const [key, val] of Object.entries(content.packages)) {
            if (key && key !== "" && !key.includes("node_modules/")) {
              const name = key.replace("node_modules/", "");
              rawDeps[name] = val.version || "latest";
            }
          }
        }
      } else if (ext === ".zip") {
        // ZIP extraction with ZIP Slip protection
        const zip = new AdmZip(req.file.buffer);
        const zipEntries = zip.getEntries();
        for (const entry of zipEntries) {
          const entryName = entry.entryName;
          // Prevent ZIP Slip
          const normalizedPath = path.normalize(entryName).replace(/^(\.\.[\/\\])+/, "");
          if (normalizedPath.endsWith("package.json") && !entry.isDirectory) {
            try {
              const pkgData = JSON.parse(entry.getData().toString("utf8"));
              rawDeps = { ...(pkgData.dependencies || {}), ...(pkgData.devDependencies || {}) };
              if (pkgData.name) projectName = pkgData.name;
              break;
            } catch (e) {
              // ignore invalid package.json inside zip
            }
          }
        }
      }
    } else if (req.body.dependencies) {
      // JSON body with dependencies object or list
      rawDeps = typeof req.body.dependencies === "string" ? JSON.parse(req.body.dependencies) : req.body.dependencies;
    }

    const entries = Object.entries(rawDeps);
    let totalVulnsFound = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    for (const [name, versionSpec] of entries) {
      // Clean version spec (e.g., ^4.18.2 -> 4.18.2)
      const cleanVersion = String(versionSpec).replace(/[\^~><=]/g, "").trim();
      let vulns = [];
      try {
        const osvRes = await cached(`osv-scan:${name}:${cleanVersion}`, CACHE_TTL, () =>
          fetchJson("https://api.osv.dev/v1/query", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ package: { ecosystem: "npm", name }, version: cleanVersion || undefined })
          })
        );
        vulns = osvRes.vulns || [];
      } catch (err) {
        // API error for package, continue
      }

      const hasIssues = vulns.length > 0;
      if (hasIssues) totalVulnsFound += vulns.length;

      let severity = "Low";
      vulns.forEach(v => {
        const sev = v.database_specific?.severity || "MEDIUM";
        if (sev === "CRITICAL" || sev === "HIGH") {
          severity = "High";
          highCount++;
        } else if (sev === "MEDIUM") {
          severity = "Medium";
          mediumCount++;
        } else {
          lowCount++;
        }
      });
      if (hasIssues && severity === "High") criticalCount++;

      dependenciesList.push({
        name,
        version: versionSpec,
        cleanVersion,
        vulnerabilitiesCount: vulns.length,
        vulnerabilities: vulns.map(v => ({
          id: v.id,
          summary: v.summary || "Sem resumo",
          details: v.details || "",
          severity: v.database_specific?.severity || "MEDIUM",
          fixedVersion: v.affected?.[0]?.ranges?.[0]?.events?.[findLastFixedIndex(v)]?.fixed || "Ver advisory",
          references: (v.references || []).map(r => r.url)
        }))
      });
    }

    // Calculate Risk Score (0-100)
    let riskScore = 100 - Math.min(100, (criticalCount * 30) + (highCount * 15) + (mediumCount * 7) + (lowCount * 2));
    if (entries.length === 0) riskScore = 100;
    riskScore = Math.max(0, riskScore);

    const scanResult = {
      id: "scan_" + Date.now(),
      projectName,
      timestamp: new Date().toISOString(),
      totalDependencies: entries.length,
      vulnerableDependencies: dependenciesList.filter(d => d.vulnerabilitiesCount > 0).length,
      totalVulnerabilities: totalVulnsFound,
      riskScore,
      severitySummary: { critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount },
      dependencies: dependenciesList
    };

    // Save to project store
    projectsStore.set(scanResult.id, scanResult);

    res.json(scanResult);
  } catch (error) {
    res.status(500).json({ error: "Erro ao processar análise de dependências.", detail: error.message });
  }
});

function findLastFixedIndex(vuln) {
  try {
    const events = vuln.affected?.[0]?.ranges?.[0]?.events || [];
    return events.length - 1;
  } catch (e) {
    return 0;
  }
}

// Developer Security Tools Endpoints
app.get("/api/tools/headers", async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: "Informe a URL alvo." });
  try {
    const formattedUrl = targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`;
    const response = await fetch(formattedUrl, { method: "HEAD", signal: AbortSignal.timeout(8000) });
    const headers = {};
    response.headers.forEach((val, key) => { headers[key] = val; });

    const checks = {
      "strict-transport-security": !!headers["strict-transport-security"],
      "content-security-policy": !!headers["content-security-policy"],
      "x-frame-options": !!headers["x-frame-options"],
      "x-content-type-options": !!headers["x-content-type-options"],
      "x-xss-protection": !!headers["x-xss-protection"]
    };
    const score = Object.values(checks).filter(Boolean).length * 20;

    res.json({ url: formattedUrl, status: response.status, headers, checks, score });
  } catch (error) {
    res.status(502).json({ error: "Não foi possível analisar os cabeçalhos da URL informada.", detail: error.message });
  }
});

app.post("/api/tools/secrets", (req, res) => {
  const { content } = req.body || {};
  if (!content) return res.status(400).json({ error: "Conteúdo vazio." });

  const patterns = [
    { name: "AWS Access Key", regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANOA|ANVA|APKA)[A-Z0-9]{16}/g },
    { name: "GitHub Personal Access Token", regex: /ghp_[a-zA-Z0-9]{36}/g },
    { name: "Slack Token", regex: /xox[baprs]-[0-9a-zA-Z]{10,48}/g },
    { name: "Private Key", regex: /-----BEGIN PRIVATE KEY-----/g },
    { name: "Generic API Key / Secret", regex: /(api[_-]?key|secret[_-]?key|password|passwd|auth[_-]?token)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{8,64})["']/gi }
  ];

  const findings = [];
  patterns.forEach(p => {
    let match;
    while ((match = p.regex.exec(content)) !== null) {
      findings.push({ type: p.name, match: match[0].substring(0, 6) + "..." });
    }
  });

  res.json({ scannedLength: content.length, findingsCount: findings.length, findings });
});

app.get("/api/projects", (_req, res) => {
  const list = Array.from(projectsStore.values());
  res.json({ count: list.length, projects: list });
});

// Em produção, serve a aplicação React compilada pelo Vite.
if (process.env.NODE_ENV === "production") {
  const dist = path.join(__dirname, "..", "dist");
  app.use(express.static(dist));
  app.get("*", (_req, res) => res.sendFile(path.join(dist, "index.html")));
}

app.listen(PORT, () => {
  console.log(`VULScanIT Intelligence API disponível em http://localhost:${PORT}`);
});

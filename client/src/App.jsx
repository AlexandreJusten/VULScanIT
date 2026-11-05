import React, { useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, ArrowUpRight, BookOpen, Bug, CheckCircle2,
  ChevronRight, Clock3, Code2, ExternalLink, Github, Globe2, Layers3,
  Menu, Package, RefreshCw, Search, Shield, ShieldAlert, Terminal,
  TrendingUp, X, Languages, Upload, Lock, FileCode, Check, Download, History
} from "lucide-react";
import { translations } from "./translations";

const API = "/api";

function App() {
  const [lang, setLang] = useState("pt");
  const t = translations[lang];

  const [active, setActive] = useState("overview");
  const [stats, setStats] = useState(null);
  const [kev, setKev] = useState([]);
  const [kevLoading, setKevLoading] = useState(true);
  const [kevError, setKevError] = useState("");
  const [filter, setFilter] = useState("");

  // Scanner state
  const [scanFile, setScanFile] = useState(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState("");

  // Package Checker state
  const [ecosystem, setEcosystem] = useState("npm");
  const [packageName, setPackageName] = useState("express");
  const [version, setVersion] = useState("");
  const [packageResult, setPackageResult] = useState(null);
  const [packageLoading, setPackageLoading] = useState(false);
  const [packageError, setPackageError] = useState("");

  // Tools state
  const [headerUrl, setHeaderUrl] = useState("https://github.com");
  const [headerResult, setHeaderResult] = useState(null);
  const [headerLoading, setHeaderLoading] = useState(false);

  const [secretText, setSecretText] = useState("");
  const [secretResult, setSecretResult] = useState(null);

  const [jwtToken, setJwtToken] = useState("");
  const [jwtResult, setJwtResult] = useState(null);

  const [hashText, setHashText] = useState("");
  const [hashResult, setHashResult] = useState(null);

  const [projectsList, setProjectsList] = useState([]);

  // Modal & Mobile menu
  const [selected, setSelected] = useState(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  async function loadData() {
    setKevLoading(true);
    setKevError("");
    try {
      const [statsResponse, kevResponse, projResponse] = await Promise.all([
        fetch(`${API}/stats`),
        fetch(`${API}/kev?limit=40`),
        fetch(`${API}/projects`)
      ]);
      if (statsResponse.ok) setStats(await statsResponse.json());
      if (kevResponse.ok) {
        const data = await kevResponse.json();
        setKev(data.vulnerabilities || []);
      }
      if (projResponse.ok) {
        const pData = await projResponse.json();
        setProjectsList(pData.projects || []);
      }
    } catch (error) {
      setKevError(lang === "en" ? "Unable to load live data." : "Não foi possível carregar os dados ao vivo.");
    } finally {
      setKevLoading(false);
    }
  }

  useEffect(() => { loadData(); }, []);

  const visibleKev = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return kev;
    return kev.filter((item) =>
      [item.id, item.name, item.vendor, item.product, item.description].filter(Boolean).join(" ").toLowerCase().includes(q)
    );
  }, [kev, filter]);

  async function runScan(e) {
    e?.preventDefault();
    if (!scanFile && !packageName) return;
    setScanLoading(true);
    setScanError("");
    try {
      const formData = new FormData();
      if (scanFile) formData.append("file", scanFile);
      else {
        formData.append("dependencies", JSON.stringify({ express: "^4.18.2", lodash: "4.17.20", axios: "0.21.1" }));
      }
      const res = await fetch(`${API}/scan`, { method: "POST", body: formData });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Scan failed");
      setScanResult(data);
      setActive("scanner");
      loadData();
    } catch (err) {
      setScanError(err.message || "Erro no scan de dependências.");
    } finally {
      setScanLoading(false);
    }
  }

  async function searchPackage(event) {
    event?.preventDefault();
    if (!packageName.trim()) return;
    setPackageLoading(true);
    setPackageError("");
    setPackageResult(null);
    try {
      const response = await fetch(`${API}/osv/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ecosystem, packageName: packageName.trim(), version: version.trim() || undefined })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Error querying package.");
      setPackageResult(data);
    } catch (error) {
      setPackageError(error.message || "Unable to query OSV.dev.");
    } finally {
      setPackageLoading(false);
    }
  }

  async function checkHeaders() {
    if (!headerUrl) return;
    setHeaderLoading(true);
    try {
      const res = await fetch(`${API}/tools/headers?url=${encodeURIComponent(headerUrl)}`);
      const data = await res.json();
      setHeaderResult(data);
    } catch (e) {
      setHeaderResult({ error: "Erro ao verificar headers." });
    } finally {
      setHeaderLoading(false);
    }
  }

  function scanSecrets() {
    if (!secretText) return;
    fetch(`${API}/tools/secrets`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: secretText })
    })
      .then(r => r.json())
      .then(d => setSecretResult(d));
  }

  function decodeJwt() {
    if (!jwtToken) return;
    try {
      const parts = jwtToken.split(".");
      if (parts.length !== 3) throw new Error("JWT inválido");
      const header = JSON.parse(atob(parts[0]));
      const payload = JSON.parse(atob(parts[1]));
      setJwtResult({ header, payload });
    } catch (e) {
      setJwtResult({ error: "Falha ao decodificar JWT. Verifique se o token é válido." });
    }
  }

  async function computeHashes() {
    if (!hashText) return;
    const encoder = new TextEncoder();
    const data = encoder.encode(hashText);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const sha256 = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
    setHashResult({ sha256, length: hashText.length });
  }

  const nav = [
    { id: "overview", label: t.nav.overview, icon: Activity },
    { id: "scanner", label: t.nav.scanner, icon: Shield },
    { id: "threats", label: t.nav.threats, icon: ShieldAlert },
    { id: "tools", label: t.nav.tools, icon: Terminal },
    { id: "packages", label: t.nav.packages, icon: Package },
    { id: "projects", label: t.nav.projects, icon: History },
    { id: "about", label: t.nav.about, icon: Code2 }
  ];

  function changePage(id) {
    setActive(id);
    setSelected(null);
    setMobileMenuOpen(false);
  }

  function toggleLang() {
    setLang(prev => prev === "pt" ? "en" : "pt");
  }

  return (
    <div className="app-shell">
      <header className="topnav">
        <div className="topnav-left">
          <div className="brand-compact">
            <span className="brand-name">VULScanIT<span>.</span></span>
          </div>
          <nav className={`topnav-items ${mobileMenuOpen ? "open" : ""}`}>
            {nav.map(item => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  className={`topnav-item ${active === item.id ? "active" : ""}`}
                  onClick={() => changePage(item.id)}
                >
                  <Icon size={15}/>
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
        <div className="topnav-right">
          <button className="secondary-btn compact lang-btn" onClick={toggleLang} title="Mudar idioma / Change language">
            <Languages size={14}/> <span>{lang.toUpperCase()}</span>
          </button>
          <button className="icon-btn refresh-btn" onClick={loadData} title={t.refreshTitle}>
            <RefreshCw size={15}/>
          </button>
          <a className="github-link" href="https://github.com/" target="_blank" rel="noreferrer">
            <Github size={15}/><span>{t.github}</span>
          </a>
          <button className="icon-btn mobile-menu-btn" onClick={() => setMobileMenuOpen(!mobileMenuOpen)}>
            <Menu size={18}/>
          </button>
        </div>
      </header>

      <main className="main-area">
        <div className="content">
          {active === "overview" && <>
            <section className="hero">
              <div className="eyebrow"><span className="eyebrow-line"/> {t.heroEyebrow}</div>
              <h1>{t.heroTitleLine1}<br/><span>{t.heroTitleLine2}</span></h1>
              <p>{t.heroSubtitle}</p>
              <div className="hero-actions">
                <button className="primary-btn" onClick={() => changePage("scanner")}><Shield size={16}/> {t.exploreVulnsBtn} <ChevronRight size={16}/></button>
                <button className="secondary-btn" onClick={() => changePage("threats")}><Terminal size={16}/> {t.checkPackageBtn}</button>
              </div>
            </section>

            <section className="stats-grid">
              <StatCard icon={ShieldAlert} label={t.statsKevLabel} value={stats ? stats.totalKev.toLocaleString(lang === "en" ? "en-US" : "pt-BR") : "—"} note={t.statsKevNote} tone="blue"/>
              <StatCard icon={Clock3} label={t.statsAddedLabel} value={stats ? stats.addedLast30Days.toLocaleString(lang === "en" ? "en-US" : "pt-BR") : "—"} note={t.statsAddedNote} tone="purple"/>
              <StatCard icon={Globe2} label={t.statsSourcesLabel} value="03" note={t.statsSourcesNote} tone="green"/>
              <StatCard icon={Activity} label={t.statsUpdatedLabel} value={stats?.lastUpdated ? new Date(stats.lastUpdated).toLocaleDateString(lang === "en" ? "en-US" : "pt-BR") : "—"} note={t.statsUpdatedNote} tone="orange"/>
            </section>

            <div className="section-heading">
              <div><div className="eyebrow">{t.threatLandscape}</div><h2>{t.threatTitle}</h2><p>{t.threatSubtitle}</p></div>
              <button className="text-link" onClick={() => changePage("threats")}>{t.viewCatalog} <ArrowUpRight size={15}/></button>
            </div>
            <VulnerabilityTable items={kev.slice(0, 6)} loading={kevLoading} error={kevError} onSelect={setSelected} t={t} lang={lang}/>

            <section className="bottom-grid">
              <div className="info-card">
                <div className="info-icon"><Package size={19}/></div>
                <div><h3>{t.checkDepsCardTitle}</h3><p>{t.checkDepsCardDesc}</p><button className="text-link" onClick={() => changePage("scanner")}>{t.checkDepsCardLink} <ChevronRight size={14}/></button></div>
              </div>
              <div className="info-card">
                <div className="info-icon purple"><BookOpen size={19}/></div>
                <div><h3>{t.transparentDataTitle}</h3><p>{t.transparentDataDesc}</p><button className="text-link" onClick={() => changePage("tools")}>{t.transparentDataLink} <ChevronRight size={14}/></button></div>
              </div>
            </section>
          </>}

          {active === "scanner" && <section>
            <PageTitle eyebrow={t.scannerEyebrow} title={t.scannerTitle} subtitle={t.scannerSubtitle}/>
            <div className="panel package-form" style={{ marginBottom: "20px" }}>
              <form onSubmit={runScan} style={{ display: "grid", gap: "15px" }}>
                <div style={{ border: "2px dashed #30363d", borderRadius: "8px", padding: "30px", textAlign: "center", backgroundColor: "#ffffff" }}>
                  <Upload size={32} style={{ color: "#58a6ff", marginBottom: "10px" }}/>
                  <div style={{ fontWeight: 600, color: "#f0f6fc", marginBottom: "5px" }}>{t.dropzoneText}</div>
                  <div style={{ fontSize: "12px", color: "#8b949e", marginBottom: "15px" }}>{t.dropzoneSub}</div>
                  <input type="file" onChange={e => setScanFile(e.target.files?.[0])} accept=".json,.zip" style={{ fontSize: "12px", color: "#c9d1d9" }}/>
                </div>
                {scanError && <div className="error-box"><AlertTriangle size={17}/>{scanError}</div>}
                <div style={{ display: "flex", justifyContent: "flex-end" }}>
                  <button className="primary-btn" type="submit" disabled={scanLoading}>
                    {scanLoading ? <RefreshCw className="spin" size={16}/> : <Shield size={16}/>}
                    {scanLoading ? t.scanning : t.scanBtn}
                  </button>
                </div>
              </form>
            </div>

            {scanResult && (
              <div className="panel" style={{ padding: "24px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid #30363d", paddingBottom: "16px", marginBottom: "20px" }}>
                  <div>
                    <div className="eyebrow">RELATÓRIO DE AUDITORIA</div>
                    <h2 style={{ margin: "4px 0 0", fontSize: "20px", color: "#f0f6fc" }}>{scanResult.projectName}</h2>
                    <small style={{ color: "#8b949e" }}>Analisado em: {new Date(scanResult.timestamp).toLocaleString()}</small>
                  </div>
                  <div style={{ textAlign: "right" }}>
                    <div style={{ fontSize: "11px", color: "#8b949e" }}>{t.riskScoreLabel}</div>
                    <div style={{ font: "700 28px Inter", color: scanResult.riskScore > 80 ? "#3fb950" : scanResult.riskScore > 50 ? "#d29922" : "#f85149" }}>
                      {scanResult.riskScore}/100
                    </div>
                  </div>
                </div>

                <div className="stats-grid" style={{ marginBottom: "20px" }}>
                  <StatCard icon={Package} label={t.totalDeps} value={scanResult.totalDependencies} note="Diretas e transitivas" tone="blue"/>
                  <StatCard icon={AlertTriangle} label={t.vulnerableDeps} value={scanResult.vulnerableDependencies} note="Requer atenção" tone="orange"/>
                  <StatCard icon={ShieldAlert} label={t.totalVulns} value={scanResult.totalVulnerabilities} note="CVEs mapeados" tone="purple"/>
                  <StatCard icon={CheckCircle2} label="Status" value={scanResult.riskScore > 80 ? "Seguro" : "Crítico"} note="Avaliação OSV" tone="green"/>
                </div>

                <h3 style={{ font: "600 16px Inter", margin: "20px 0 12px", color: "#f0f6fc" }}>{t.dependencyTreeTitle}</h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>PACOTE</th>
                        <th>VERSÃO</th>
                        <th>VULNERABILIDADES</th>
                        <th>AÇÃO / CORREÇÃO</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanResult.dependencies.map((dep, i) => (
                        <tr key={i}>
                          <td><strong>{dep.name}</strong></td>
                          <td><code>{dep.version}</code></td>
                          <td>
                            {dep.vulnerabilitiesCount === 0 ? (
                              <span style={{ color: "#3fb950" }}>Seguro</span>
                            ) : (
                              <span style={{ color: "#d29922", fontWeight: 600 }}>{dep.vulnerabilitiesCount} CVE(s)</span>
                            )}
                          </td>
                          <td>
                            {dep.vulnerabilitiesCount > 0 ? (
                              <span style={{ color: "#f85149" }}>Atualizar para &ge; {dep.vulnerabilities[0]?.fixedVersion}</span>
                            ) : (
                              <span style={{ color: "#8b949e" }}>N/A</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </section>}

          {active === "threats" && <section>
            <PageTitle eyebrow={t.vulnPageEyebrow} title={t.vulnPageTitle} subtitle={t.vulnPageSubtitle}/>
            <div className="toolbar">
              <div className="search-box"><Search size={17}/><input value={filter} onChange={e => setFilter(e.target.value)} placeholder={t.searchPlaceholder}/>{filter && <button onClick={() => setFilter("")}><X size={15}/></button>}</div>
              <button className="secondary-btn compact" onClick={loadData}><RefreshCw size={15}/> {t.refreshTitle}</button>
            </div>
            <div className="result-meta">{visibleKev.length} {t.resultsExhibited} <span>·</span> {t.sourceCisa}</div>
            <VulnerabilityTable items={visibleKev} loading={kevLoading} error={kevError} onSelect={setSelected} t={t} lang={lang}/>
          </section>}

          {active === "tools" && <section>
            <PageTitle eyebrow="DEVELOPER SECURITY UTILITIES" title={t.toolsTitle} subtitle={t.toolsSubtitle}/>
            <div className="source-grid" style={{ gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
              
              {/* Tool 1: Security Headers */}
              <div className="panel source-card">
                <h3>{t.toolHeadersTitle}</h3>
                <p>{t.toolHeadersDesc}</p>
                <div style={{ display: "flex", gap: "8px", marginTop: "12px" }}>
                  <input style={{ flex: 1, height: "36px", backgroundColor: "#ffffff", border: "1px solid #d0d7de", borderRadius: "6px", padding: "0 10px", color: "#24292f", fontSize: "13px" }} value={headerUrl} onChange={e => setHeaderUrl(e.target.value)} placeholder="https://exemplo.com"/>
                  <button className="primary-btn compact" onClick={checkHeaders} disabled={headerLoading}>{headerLoading ? <RefreshCw className="spin" size={14}/> : <Check size={14}/>} {t.checkBtn}</button>
                </div>
                {headerResult && !headerResult.error && (
                  <div style={{ marginTop: "12px", fontSize: "12px", backgroundColor: "#ffffff", padding: "10px", borderRadius: "6px", border: "1px solid #d0d7de" }}>
                    <div><strong>Score:</strong> {headerResult.score}/100</div>
                    <div><strong>HSTS:</strong> {headerResult.checks["strict-transport-security"] ? "Sim" : "Não"}</div>
                    <div><strong>CSP:</strong> {headerResult.checks["content-security-policy"] ? "Sim" : "Não"}</div>
                  </div>
                )}
              </div>

              {/* Tool 2: Secrets Scanner */}
              <div className="panel source-card">
                <h3>{t.toolSecretsTitle}</h3>
                <p>{t.toolSecretsDesc}</p>
                <textarea style={{ width: "100%", height: "70px", backgroundColor: "#ffffff", border: "1px solid #d0d7de", borderRadius: "6px", padding: "8px", color: "#24292f", fontSize: "13px", margin: "10px 0" }} value={secretText} onChange={e => setSecretText(e.target.value)} placeholder="Cole o código ou config aqui para auditar chaves..."/>
                <button className="primary-btn compact" onClick={scanSecrets}><Search size={14}/> {t.analyzeBtn}</button>
                {secretResult && (
                  <div style={{ marginTop: "10px", fontSize: "12px" }}>
                    Encontrados: <strong>{secretResult.findingsCount}</strong> segredo(s) potencial(is).
                  </div>
                )}
              </div>

              {/* Tool 3: JWT Decoder */}
              <div className="panel source-card">
                <h3>{t.toolJwtTitle}</h3>
                <p>{t.toolJwtDesc}</p>
                <input style={{ width: "100%", height: "36px", backgroundColor: "#ffffff", border: "1px solid #d0d7de", borderRadius: "6px", padding: "0 10px", color: "#24292f", fontSize: "13px", margin: "10px 0" }} value={jwtToken} onChange={e => setJwtToken(e.target.value)} placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."/>
                <button className="primary-btn compact" onClick={decodeJwt}><Lock size={14}/> {t.decodeBtn}</button>
                {jwtResult && !jwtResult.error && (
                  <pre style={{ marginTop: "10px", fontSize: "11px", backgroundColor: "#ffffff", padding: "8px", borderRadius: "6px", overflow: "auto", maxHeight: "100px", border: "1px solid #d0d7de" }}>
                    {JSON.stringify(jwtResult.payload, null, 2)}
                  </pre>
                )}
              </div>

              {/* Tool 4: Hash Analyzer */}
              <div className="panel source-card">
                <h3>{t.toolHashTitle}</h3>
                <p>{t.toolHashDesc}</p>
                <input style={{ width: "100%", height: "36px", backgroundColor: "#ffffff", border: "1px solid #d0d7de", borderRadius: "6px", padding: "0 10px", color: "#24292f", fontSize: "13px", margin: "10px 0" }} value={hashText} onChange={e => setHashText(e.target.value)} placeholder="Digite um texto para gerar hash..."/>
                <button className="primary-btn compact" onClick={computeHashes}><FileCode size={14}/> {t.analyzeBtn}</button>
                {hashResult && (
                  <div style={{ marginTop: "10px", fontSize: "12px", wordBreak: "break-all" }}>
                    <strong>SHA-256:</strong> <code>{hashResult.sha256}</code>
                  </div>
                )}
              </div>

            </div>
          </section>}

          {active === "packages" && <section>
            <PageTitle eyebrow="OSV.DEV · PACKAGE INTELLIGENCE" title="Verificador de dependências" subtitle="Descubra vulnerabilidades conhecidas em uma biblioteca e, opcionalmente, em uma versão específica."/>
            <form className="package-form panel" onSubmit={searchPackage}>
              <div className="form-grid">
                <label>ECOSSISTEMA<select value={ecosystem} onChange={e => setEcosystem(e.target.value)}>
                  <option value="npm">npm</option><option value="PyPI">PyPI</option><option value="Maven">Maven</option><option value="Go">Go</option><option value="crates.io">crates.io (Rust)</option><option value="NuGet">NuGet</option><option value="Packagist">Packagist</option><option value="RubyGems">RubyGems</option>
                </select></label>
                <label>NOME DO PACOTE<input value={packageName} onChange={e => setPackageName(e.target.value)} placeholder="ex.: express" required/></label>
                <label>VERSÃO <span className="optional">(opcional)</span><input value={version} onChange={e => setVersion(e.target.value)} placeholder="ex.: 4.18.2"/></label>
              </div>
              <div className="form-footer"><span><Shield size={14}/> Consulta pública via OSV.dev</span><button className="primary-btn" type="submit" disabled={packageLoading}>{packageLoading ? <RefreshCw className="spin" size={16}/> : <Search size={16}/>} {packageLoading ? "Consultando..." : "Verificar pacote"}</button></div>
            </form>
            {packageError && <div className="error-box"><AlertTriangle size={17}/>{packageError}</div>}
            {packageResult && <div className="package-results">
              <div className="result-summary panel"><div><div className="eyebrow">RESULTADO DA ANÁLISE</div><h2>{packageResult.package.name}</h2><p>{packageResult.package.ecosystem}{packageResult.version ? ` · versão ${packageResult.version}` : " · todas as versões"}</p></div><div className={`result-count ${packageResult.count ? "has-issues" : ""}`}><strong>{packageResult.count}</strong><span>vulnerabilidade(s)</span></div></div>
              {packageResult.count === 0 ? <div className="empty-state"><CheckCircle2 size={30}/><h3>Nenhuma vulnerabilidade retornada</h3><p>Isso não garante que o pacote seja seguro. Significa apenas que a OSV não retornou registros para esta consulta.</p></div> :
                <div className="vuln-cards">{packageResult.vulnerabilities.map(v => <div className="vuln-card panel" key={v.id}><div className="vuln-card-top"><strong>{v.id}</strong><span>{v.database_specific?.severity || "Severidade não informada"}</span></div><h3>{v.summary || "Sem resumo disponível"}</h3><p>{v.details?.slice(0, 420) || "Consulte a fonte para detalhes."}</p><a href={`https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`} target="_blank" rel="noreferrer">Ver detalhes na OSV <ExternalLink size={13}/></a></div>)}</div>}
            </div>}
          </section>}

          {active === "projects" && <section>
            <PageTitle eyebrow="PROJECTS & SCAN HISTORY" title={t.projectsTitle} subtitle={t.projectsSubtitle}/>
            {projectsList.length === 0 ? (
              <div className="empty-state panel" style={{ padding: "60px" }}>
                <History size={36} style={{ color: "#58a6ff", marginBottom: "12px" }}/>
                <h3>{t.noProjects}</h3>
                <p>Execute um scan de dependências para registrar projetos aqui.</p>
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>PROJETO</th>
                      <th>DATA</th>
                      <th>DEPENDÊNCIAS</th>
                      <th>RISK SCORE</th>
                      <th>VULNERABILIDADES</th>
                    </tr>
                  </thead>
                  <tbody>
                    {projectsList.map(proj => (
                      <tr key={proj.id} onClick={() => { setScanResult(proj); setActive("scanner"); }}>
                        <td><strong>{proj.projectName}</strong></td>
                        <td><span className="date-cell">{new Date(proj.timestamp).toLocaleString()}</span></td>
                        <td>{proj.totalDependencies}</td>
                        <td><span style={{ fontWeight: 700, color: proj.riskScore > 80 ? "#3fb950" : "#f85149" }}>{proj.riskScore}/100</span></td>
                        <td>{proj.totalVulnerabilities}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>}

          {active === "about" && <section>
            <PageTitle eyebrow={t.aboutPageEyebrow} title={t.aboutPageTitle} subtitle={t.aboutPageSubtitle}/>
            <div className="source-grid">
              <SourceCard name="CISA KEV" category="Vulnerabilidades exploradas" description="Catálogo oficial de vulnerabilidades conhecidas por serem exploradas." url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" status={t.integrated} documentationText={t.documentation} />
              <SourceCard name="OSV.dev" category="Vulnerabilidades de pacotes" description="Banco aberto de vulnerabilidades em ecossistemas open source." url="https://osv.dev/" status={t.integrated} documentationText={t.documentation} />
              <SourceCard name="NVD / NIST" category="Base de vulnerabilidades" description="Fonte adicional de CVEs com CVSS, CWE e referências." url="https://nvd.nist.gov/developers" status={t.integrated} documentationText={t.documentation} />
              <SourceCard name="GitHub Advisory" category="Advisories de pacotes" description="Avisos de segurança para ecossistemas de desenvolvimento." url="https://github.com/advisories" status={t.integrated} documentationText={t.documentation} />
            </div>
            <div className="panel api-panel"><div className="eyebrow">{t.localApiTitle}</div><h2>{t.endpointsAvailable}</h2><ApiEndpoint method="GET" path="/api/health" desc="Status do serviço"/><ApiEndpoint method="GET" path="/api/stats" desc="Estatísticas do catálogo CISA"/><ApiEndpoint method="POST" path="/api/scan" desc="Scanner estático de dependências"/><ApiEndpoint method="GET" path="/api/tools/headers" desc="Security Headers Checker"/><ApiEndpoint method="POST" path="/api/tools/secrets" desc="Secrets Scanner local"/></div>
            <div className="notice"><AlertTriangle size={17}/><div><strong>{t.responsibleUseTitle}</strong><p>{t.responsibleUseDesc}</p></div></div>
          </section>}
        </div>
        <footer className="footer"><div>© {new Date().getFullYear()} <strong>VULScanIT</strong> <span>· {t.footerRights}</span></div><div>{t.thirdPartyData} · <a href="https://www.cisa.gov/" target="_blank" rel="noreferrer">CISA</a> · <a href="https://osv.dev/" target="_blank" rel="noreferrer">OSV.dev</a></div></footer>
      </main>

      {selected && <div className="modal-backdrop" onClick={() => setSelected(null)}><div className="detail-modal" onClick={e => e.stopPropagation()}><div className="modal-head"><div><div className="eyebrow">{t.cisaKevModal}<h2>{selected.id}</h2></div></div><button className="icon-btn" onClick={() => setSelected(null)}><X size={18}/></button></div><h3>{selected.name}</h3><p>{selected.description}</p><div className="detail-grid"><div><small>{t.vendor}</small><strong>{selected.vendor}</strong></div><div><small>{t.product}</small><strong>{selected.product}</strong></div><div><small>{t.dateAdded}</small><strong>{selected.dateAdded}</strong></div><div><small>{t.cisaDeadline}</small><strong>{selected.dueDate || t.notInformed}</strong></div></div><div className="notice"><ShieldAlert size={17}/><div><strong>{t.recommendedAction}</strong><p>{selected.requiredAction || t.defaultActionDesc}</p></div></div><a className="primary-btn modal-link" href={`https://nvd.nist.gov/vuln/detail/${selected.id}`} target="_blank" rel="noreferrer">{t.consultNvd} <ExternalLink size={14}/></a></div></div>}
    </div>
  );
}

function StatCard({ icon: Icon, label, value, note, tone }) {
  return <div className="stat-card"><div className={`stat-icon ${tone}`}><Icon size={18}/></div><div className="stat-label">{label}</div><div className="stat-value">{value}</div><div className="stat-note">{note}</div></div>;
}
function PageTitle({ eyebrow, title, subtitle }) {
  return <div className="page-title"><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{subtitle}</p></div>;
}
function VulnerabilityTable({ items, loading, error, onSelect, t, lang }) {
  if (loading) return <div className="loading-state"><RefreshCw className="spin" size={20}/> {t.loadingCisa}</div>;
  if (error) return <div className="error-box"><AlertTriangle size={17}/>{error}</div>;
  if (!items.length) return <div className="empty-state"><Search size={26}/><h3>{t.noResults}</h3><p>{t.tryOtherTerm}</p></div>;
  return <div className="table-wrap"><table><thead><tr><th>{t.tableHeaderId}</th><th>{t.tableHeaderVuln}</th><th>{t.tableHeaderVendor}</th><th>{t.tableHeaderAdded}</th><th></th></tr></thead><tbody>
    {items.map(item => <tr key={item.id} onClick={() => onSelect(item)}><td><span className="cve-id">{item.id}</span></td><td><strong>{item.name}</strong><small>{item.description}</small></td><td><span>{item.vendor}</span><small>{item.product}</small></td><td><span className="date-cell">{item.dateAdded}</span></td><td><ChevronRight size={16}/></td></tr>)}
  </tbody></table></div>;
}
function SourceCard({ name, category, description, url, status, documentationText }) {
  return <div className="source-card panel"><div className="source-card-top"><div className="source-logo"><Layers3 size={18}/></div><span className={`source-badge ${status === "Integrada" || status === "Integrated" ? "done" : ""}`}>{status}</span></div><h3>{name}</h3><div className="source-category">{category}</div><p>{description}</p><a href={url} target="_blank" rel="noreferrer">{documentationText} <ExternalLink size={13}/></a></div>;
}
function ApiEndpoint({ method, path, desc }) {
  return <div className="endpoint"><span className={`method ${method.toLowerCase()}`}>{method}</span><code>{path}</code><span>{desc}</span></div>;
}

export default App;

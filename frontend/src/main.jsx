import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import {
  ShieldCheck, Search, AlertTriangle, Info, LockKeyhole,
  Server, Cookie, ExternalLink, ChevronDown, RefreshCw
} from "lucide-react";
import "./styles.css";

const API = "http://127.0.0.1:8000";

const severityOrder = ["Critical", "High", "Medium", "Low", "Informational"];

function SeverityBadge({ severity }) {
  return <span className={`badge ${severity.toLowerCase()}`}>{severity}</span>;
}

function Stat({ label, value, tone }) {
  return (
    <div className="stat">
      <div className={`stat-dot ${tone || ""}`}></div>
      <div>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

function FindingCard({ finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="finding">
      <button className="finding-head" onClick={() => setOpen(!open)}>
        <div className="finding-main">
          <div className="finding-icon"><AlertTriangle size={17} /></div>
          <div>
            <div className="finding-title">{finding.title}</div>
            <div className="finding-meta">{finding.category} · Confidence: {finding.confidence}</div>
          </div>
        </div>
        <div className="finding-right">
          <SeverityBadge severity={finding.severity} />
          <ChevronDown className={open ? "rotated" : ""} size={18} />
        </div>
      </button>

      {open && (
        <div className="finding-body">
          <div className="detail-grid">
            <div><span>Evidence</span><p>{finding.evidence}</p></div>
            <div><span>Description</span><p>{finding.description}</p></div>
            <div><span>Impact</span><p>{finding.impact}</p></div>
            <div><span>Recommendation</span><p>{finding.recommendation}</p></div>
          </div>
        </div>
      )}
    </div>
  );
}

function App() {
  const [url, setUrl] = useState("https://example.com");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function runScan(e) {
    e.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Scan failed.");
      setResult(data);
    } catch (err) {
      setError(err.message || "Could not connect to the SecureScan backend.");
    } finally {
      setLoading(false);
    }
  }

  const counts = result?.summary || {};
  const findings = result?.findings || [];

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={21} /></div>
          <div>
            <div className="brand-name">SecureScan</div>
            <div className="brand-sub">Passive web security assessment</div>
          </div>
        </div>
        <div className="mode-pill"><span></span> Passive mode</div>
      </header>

      <main className="container">
        <section className="hero">
          <div className="eyebrow">SECURITY ASSESSMENT</div>
          <h1>See what your web server is exposing.</h1>
          <p>Analyze HTTP responses, security headers, cookies, redirects, and technology disclosure without destructive testing.</p>

          <form className="scan-form" onSubmit={runScan}>
            <div className="url-wrap">
              <Search size={19} />
              <input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                aria-label="Target URL"
              />
            </div>
            <button className="scan-btn" disabled={loading || !url.trim()}>
              {loading ? <><RefreshCw size={17} className="spin" /> Scanning...</> : <><Search size={17} /> Run scan</>}
            </button>
          </form>

          {error && <div className="error"><AlertTriangle size={18} /> {error}</div>}
          <div className="scope-note"><LockKeyhole size={14} /> Scan only systems you own or are explicitly authorized to assess.</div>
        </section>

        {!result && !loading && (
          <section className="empty">
            <div className="empty-icon"><ShieldCheck size={30} /></div>
            <h2>Ready to assess</h2>
            <p>Enter an authorized target above. SecureScan reports observations and evidence rather than claiming that a missing control automatically proves an exploit.</p>
          </section>
        )}

        {loading && (
          <section className="empty">
            <div className="loader-ring"></div>
            <h2>Analyzing response</h2>
            <p>Collecting headers, cookies, redirects, and other passive evidence.</p>
          </section>
        )}

        {result && !loading && (
          <>
            <section className="target-card">
              <div className="target-left">
                <div className="target-icon"><ExternalLink size={18} /></div>
                <div>
                  <div className="target-label">TARGET</div>
                  <div className="target-url">{result.final_url}</div>
                </div>
              </div>
              <div className="target-facts">
                <div><span>Status</span><strong>{result.status_code}</strong></div>
                <div><span>HTTPS</span><strong>{result.https ? "Yes" : "No"}</strong></div>
                <div><span>Redirects</span><strong>{result.redirect_count}</strong></div>
              </div>
            </section>

            <section className="stats">
              <Stat label="Critical" value={counts.Critical || 0} tone="critical" />
              <Stat label="High" value={counts.High || 0} tone="high" />
              <Stat label="Medium" value={counts.Medium || 0} tone="medium" />
              <Stat label="Low" value={counts.Low || 0} tone="low" />
              <Stat label="Informational" value={counts.Informational || 0} tone="info" />
            </section>

            <section className="section-head">
              <div>
                <div className="eyebrow">FINDINGS</div>
                <h2>{findings.length} observations</h2>
              </div>
              <div className="server-fact">
                <Server size={16} />
                <span>Server: {result.server || "Not disclosed"}</span>
              </div>
            </section>

            {findings.length === 0 ? (
              <div className="clean">
                <ShieldCheck size={27} />
                <div>
                  <strong>No findings from the current rules.</strong>
                  <p>This does not prove the target is secure; it means the current passive checks found nothing to report.</p>
                </div>
              </div>
            ) : (
              <div className="findings">
                {severityOrder.flatMap(sev =>
                  findings.filter(f => f.severity === sev).map(f => <FindingCard key={f.id} finding={f} />)
                )}
              </div>
            )}

            <div className="method-note">
              <Info size={17} />
              <div><strong>Assessment scope</strong><p>SecureScan currently performs passive, non-destructive checks. Findings may require manual validation and do not guarantee the presence or absence of exploitable vulnerabilities.</p></div>
            </div>
          </>
        )}
      </main>

      <footer>SecureScan · Passive assessment MVP</footer>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);

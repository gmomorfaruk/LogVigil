import { useEffect, useRef, useState } from "react";

/**
 * Generates a clean, futuristic synthesizer sound using the browser's Web Audio API.
 * This runs entirely locally and doesn't require any external audio assets.
 */
const playAlertSound = (severity = "warning") => {
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    
    // Resume audio context if it was suspended (browser autoplay policy)
    if (audioCtx.state === "suspended") {
      audioCtx.resume();
    }

    if (severity === "critical") {
      // High-pitched dual-tone synthesizer alarm sweep
      const osc1 = audioCtx.createOscillator();
      const osc2 = audioCtx.createOscillator();
      const gainNode = audioCtx.createGain();

      osc1.type = "sawtooth";
      osc1.frequency.setValueAtTime(880, audioCtx.currentTime); // A5
      osc1.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.4);

      osc2.type = "sine";
      osc2.frequency.setValueAtTime(885, audioCtx.currentTime);
      osc2.frequency.exponentialRampToValueAtTime(445, audioCtx.currentTime + 0.4);

      gainNode.gain.setValueAtTime(0.12, audioCtx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.4);

      osc1.connect(gainNode);
      osc2.connect(gainNode);
      gainNode.connect(audioCtx.destination);

      osc1.start();
      osc2.start();
      osc1.stop(audioCtx.currentTime + 0.4);
      osc2.stop(audioCtx.currentTime + 0.4);
    } else {
      // Shorter, gentler warning dual-chime
      const osc = audioCtx.createOscillator();
      const gainNode = audioCtx.createGain();

      osc.type = "sine";
      osc.frequency.setValueAtTime(587.33, audioCtx.currentTime); // D5
      osc.frequency.setValueAtTime(880, audioCtx.currentTime + 0.08); // A5

      gainNode.gain.setValueAtTime(0.08, audioCtx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.3);

      osc.connect(gainNode);
      gainNode.connect(audioCtx.destination);

      osc.start();
      osc.stop(audioCtx.currentTime + 0.3);
    }
  } catch (err) {
    console.warn("Web Audio API not supported or blocked by user interaction gesture requirement:", err);
  }
};

/**
 * LiveMonitor — radar-style live security monitor.
 */
export default function LiveMonitor({
  alerts = [],
  status = "secure",
  pingLifetimeMs = 6000,
}) {
  const [pings, setPings] = useState([]);
  const [flash, setFlash] = useState(false);
  const [muted, setMuted] = useState(() => {
    try {
      return localStorage.getItem("radar_muted") === "true";
    } catch {
      return false;
    }
  });

  const mutedRef = useRef(muted);

  // Sync mute state to ref and localStorage
  useEffect(() => {
    mutedRef.current = muted;
    try {
      localStorage.setItem("radar_muted", muted ? "true" : "false");
    } catch {}
  }, [muted]);

  // Serialize alerts to avoid infinite loops from parent render reference changes
  const alertsKey = JSON.stringify(
    alerts.map((a) => ({ id: a.id, severity: a.severity }))
  );

  // Turn incoming alerts into rendered pings, updating or adding them.
  useEffect(() => {
    setPings((prevPings) => {
      const prevMap = new Map(prevPings.map((p) => [p.id, p]));
      let hasNewAlerts = false;
      let highestSeverity = "warning";

      // 1. Keep track of all current alert IDs
      const currentAlertIds = new Set(alerts.map((a) => a.id));

      // 2. Map current alerts to pings (keeping existing coordinates/createdAt)
      const activePings = alerts.map((a) => {
        const existing = prevMap.get(a.id);
        if (existing) {
          return {
            ...existing,
            severity: a.severity ?? existing.severity,
          };
        } else {
          hasNewAlerts = true;
          const sev = a.severity ?? "critical";
          if (sev === "critical") {
            highestSeverity = "critical";
          }
          return {
            id: a.id,
            angle: a.angle ?? Math.random() * 360,
            distance: a.distance ?? 20 + Math.random() * 75, // % of radius
            severity: sev,
            createdAt: Date.now(),
          };
        }
      });

      // 3. Keep recently removed/transient pings that are still within pingLifetimeMs
      const now = Date.now();
      const lingeringPings = prevPings.filter((p) => {
        const isStillAlert = currentAlertIds.has(p.id);
        const isWithinLifetime = now - p.createdAt < pingLifetimeMs;
        return !isStillAlert && isWithinLifetime;
      });

      // Trigger audio & visual alert effects on arrival
      if (hasNewAlerts) {
        setTimeout(() => setFlash(true), 0);
        if (!mutedRef.current) {
          playAlertSound(highestSeverity);
        }
      }

      return [...activePings, ...lingeringPings];
    });
  }, [alertsKey, pingLifetimeMs]);

  // Handle flash resetting
  useEffect(() => {
    if (flash) {
      const flashTimer = setTimeout(() => setFlash(false), 1800);
      return () => clearTimeout(flashTimer);
    }
  }, [flash]);

  // Expire lingering pings that are no longer in alerts and older than pingLifetimeMs
  useEffect(() => {
    if (pings.length === 0) return;

    const timer = setInterval(() => {
      const now = Date.now();
      const currentAlertIds = new Set(alerts.map((a) => a.id));

      setPings((prev) => {
        const next = prev.filter((p) => {
          const isStillAlert = currentAlertIds.has(p.id);
          const isWithinLifetime = now - p.createdAt < pingLifetimeMs;
          return isStillAlert || isWithinLifetime;
        });

        if (next.length === prev.length) return prev;
        return next;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [alertsKey, pingLifetimeMs, pings.length > 0]);

  const center = 140;
  const radiusMax = 120;

  // Count warning pings to determine if there is "so much yellow"
  const warningCount = pings.filter((p) => p.severity === "warning").length;
  const isSoMuchYellow = warningCount >= 4;

  return (
    <div className={`cyber-widget radar-widget${flash ? " widget-alert" : ""}`}>
      <div className="widget-title" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span>Live Monitor</span>
          <button
            onClick={() => setMuted(!muted)}
            style={{
              background: "none",
              border: "none",
              cursor: "pointer",
              fontSize: "14px",
              padding: "2px",
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              opacity: 0.8,
              transition: "opacity 0.2s",
            }}
            onMouseEnter={(e) => (e.currentTarget.style.opacity = "1")}
            onMouseLeave={(e) => (e.currentTarget.style.opacity = "0.8")}
            title={muted ? "Unmute sound alerts" : "Mute sound alerts"}
          >
            {muted ? "🔇" : "🔊"}
          </button>
        </div>
        <span className={`status-badge ${status}`}>
          <span className="dot" />
          {status === "secure" ? "Secure" : status === "warning" ? "Warning" : "Alert"}
        </span>
      </div>

      <div className="radar-wrap">
        <svg className="radar-face" viewBox="0 0 280 280">
          <circle className="radar-ring" cx={center} cy={center} r="120" />
          <circle className="radar-ring" cx={center} cy={center} r="85" />
          <circle className="radar-ring" cx={center} cy={center} r="50" />
          <circle className="radar-ring" cx={center} cy={center} r="15" />
          <line className="radar-crosshair" x1="20" y1={center} x2="260" y2={center} />
          <line className="radar-crosshair" x1={center} y1="20" x2={center} y2="260" />

          <g className="radar-sweep-group">
            <defs>
              <linearGradient id="sweepGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#35e6ff" stopOpacity="0" />
                <stop offset="100%" stopColor="#35e6ff" stopOpacity="0.55" />
              </linearGradient>
              <path
                id="sweepArc"
                d={`M${center},${center} L${center},20 A120,120 0 0,1 244,80 Z`}
              />
            </defs>
            <use href="#sweepArc" fill="url(#sweepGrad)" />
            <line x1={center} y1={center} x2={center} y2="20" stroke="#35e6ff" strokeWidth="1.5" />
          </g>

          <circle cx={center} cy={center} r="3" fill="#35e6ff" />

          {/* Sort pings so warning/yellow dots are rendered first, critical/red dots last (on top) */}
          {[...pings]
            .sort((a, b) => {
              if (a.severity === "warning" && b.severity === "critical") return -1;
              if (a.severity === "critical" && b.severity === "warning") return 1;
              return 0;
            })
            .map((p) => {
              const rad = (p.angle * Math.PI) / 180;
              const r = (p.distance / 100) * radiusMax;
              const cx = center + Math.cos(rad) * r;
              const cy = center + Math.sin(rad) * r;

              const isWarning = p.severity === "warning";
              const coreRadius = isWarning
                ? (isSoMuchYellow ? 2.0 : 3.5)
                : 3.8; // Critical dots are slightly larger for prominence
              const ringRadius = isWarning
                ? (isSoMuchYellow ? 5.0 : 8.0)
                : 9.0;

              return (
                <g key={p.id} className={`alert-ping severity-${p.severity}`}>
                  <circle className="ping-ring" cx={cx} cy={cy} r={ringRadius} />
                  <circle className="ping-core" cx={cx} cy={cy} r={coreRadius} />
                </g>
              );
            })}
        </svg>
      </div>

      <div className="radar-caption">
        {pings.length > 0
          ? `${pings.length} ACTIVE SIGNAL${pings.length > 1 ? "S" : ""}`
          : "NO THREATS DETECTED"}
      </div>
    </div>
  );
}

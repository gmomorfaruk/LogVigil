import React, { useEffect, useRef, useState } from 'react';
import './LoginLogo.css';


/* ─────────────────────────────────────────────────────────────
   LoginLogo — Animated surveillance-eye logo (login page only)
   All animations are CSS-keyframe driven. SVG pupil uses a tiny
   React state for idle scan offsets. Hover triggers focus-snap.
   prefers-reduced-motion is respected.
───────────────────────────────────────────────────────────── */

const PHASES = ['dark', 'awakening', 'active'];

// Idle scan patterns (pupil translateX offset in px, capped to feel natural)
const SCAN_SEQUENCES = [
  [-6, 0],
  [7, 0],
  [-5, 0, 6, 0],
  [0],           // micro-hold — just a brief glow pulse
];

function useReducedMotion() {
  const [reduced, setReduced] = useState(
    () => typeof window !== 'undefined'
      && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const handler = (e) => setReduced(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);
  return reduced;
}

export default function LoginLogo({ onLoginClick, scanning = false }) {
  const reducedMotion = useReducedMotion();
  const [phase, setPhase] = useState('dark');
  const [pupilX, setPupilX] = useState(0);
  const [scanLine, setScanLine] = useState(false);
  const [hovered, setHovered] = useState(false);
  const [statusIdx, setStatusIdx] = useState(0);
  const idleTimer = useRef(null);
  const scanRef = useRef(null);

  const STATUS_MESSAGES = [
    'INITIALIZING VIGIL SYSTEM...',
    'LOADING SECURITY PROTOCOLS...',
    'SCANNING ENVIRONMENT...',
    '● VIGIL ACTIVE',
  ];

  // ── startup sequence ────────────────────────────────────────
  useEffect(() => {
    if (reducedMotion) { setPhase('active'); setStatusIdx(3); return; }

    // Phase 1: awakening glow (500ms)
    const t1 = setTimeout(() => setPhase('awakening'), 100);
    // Phase 2: eye activates — scan line flash
    const t2 = setTimeout(() => {
      setScanLine(true);
      setTimeout(() => setScanLine(false), 600);
    }, 800);
    // Phase 3: fully active
    const t3 = setTimeout(() => setPhase('active'), 1400);

    // Status text ticker
    const intervals = [0, 900, 1600, 2300].map((delay, i) =>
      setTimeout(() => setStatusIdx(i), delay)
    );

    return () => {
      [t1, t2, t3, ...intervals].forEach(clearTimeout);
    };
  }, [reducedMotion]);

  // ── idle scanning ───────────────────────────────────────────
  useEffect(() => {
    if (phase !== 'active' || reducedMotion) return;

    function scheduleNext() {
      const delay = 8000 + Math.random() * 7000; // 8–15 s
      idleTimer.current = setTimeout(async () => {
        const seq = SCAN_SEQUENCES[Math.floor(Math.random() * SCAN_SEQUENCES.length)];
        for (const x of seq) {
          setPupilX(x);
          await new Promise(r => setTimeout(r, x === 0 ? 500 : 900));
        }
        scheduleNext();
      }, delay);
    }

    scheduleNext();
    return () => clearTimeout(idleTimer.current);
  }, [phase, reducedMotion]);

  // ── login-button scan ───────────────────────────────────────
  useEffect(() => {
    if (!scanning || reducedMotion) return;
    clearTimeout(idleTimer.current);
    (async () => {
      setScanLine(true);
      setPupilX(0);
      await new Promise(r => setTimeout(r, 200));
      setScanLine(false);
      setPupilX(-7);
      await new Promise(r => setTimeout(r, 350));
      setPupilX(7);
      await new Promise(r => setTimeout(r, 350));
      setPupilX(0);
    })();
  }, [scanning, reducedMotion]);

  // ── hover ───────────────────────────────────────────────────
  const handleMouseEnter = () => { setHovered(true); if (!reducedMotion) setPupilX(0); };
  const handleMouseLeave = () => { setHovered(false); };

  const glowIntensity = hovered ? 1.3 : phase === 'active' ? 1 : phase === 'awakening' ? 0.5 : 0;

  return (
    <div className="lv-logo-wrapper" onMouseEnter={handleMouseEnter} onMouseLeave={handleMouseLeave}>
      {/* ── Shield SVG with animated eye ── */}
      <div
        className={`lv-shield-container lv-phase-${phase} ${hovered ? 'lv-hovered' : ''}`}
        style={{ '--glow': glowIntensity }}
      >
        {/* The actual logo image as the base */}
        <img
          src={new URL('../assets/logvigil_logo.jpg', import.meta.url).href}
          alt="LogVigil"
          className="lv-base-img"
          draggable={false}
        />

        {/* SVG overlay: animated pupil + scan line, sits on top of the image */}
        <svg
          className="lv-eye-overlay"
          viewBox="0 0 100 100"
          xmlns="http://www.w3.org/2000/svg"
          aria-hidden="true"
        >
          <defs>
            <radialGradient id="irisGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#00f0ff" stopOpacity="0" />
            </radialGradient>
            <filter id="eyeBlur">
              <feGaussianBlur stdDeviation="1.2" />
            </filter>
          </defs>

          {/* Iris ambient glow — brightens on activation */}
          <ellipse
            cx="50" cy="50" rx="18" ry="12"
            fill="url(#irisGlow)"
            className={`lv-iris-glow ${phase === 'active' ? 'lv-iris-active' : ''}`}
            filter="url(#eyeBlur)"
          />

          {/* Pupil — translateX driven by React state */}
          <g
            style={{
              transform: `translateX(${reducedMotion ? 0 : pupilX * 0.38}px)`,
              transition: 'transform 0.7s cubic-bezier(0.25,0.46,0.45,0.94)',
            }}
          >
            {/* Pupil vertical slit */}
            <ellipse
              cx="50" cy="50" rx="3.5" ry="7"
              fill="#001a1f"
              className="lv-pupil"
            />
            {/* Tiny specular highlight */}
            <ellipse
              cx="51.5" cy="47" rx="1.1" ry="1.8"
              fill="rgba(0,240,255,0.55)"
              className="lv-highlight"
            />
          </g>

          {/* Scan line — horizontal swipe across eye on activation */}
          {scanLine && (
            <rect
              x="30" y="49" width="40" height="1.5"
              fill="#00f0ff"
              opacity="0"
              className="lv-scanline"
            />
          )}
        </svg>

        {/* Outer glow ring — pulses when active */}
        <div className={`lv-glow-ring ${phase === 'active' ? 'lv-ring-active' : ''} ${hovered ? 'lv-ring-hover' : ''}`} />
      </div>

      {/* ── Status text ── */}
      <div className={`lv-status-text ${phase !== 'dark' ? 'lv-status-visible' : ''}`}>
        <span className={statusIdx === 3 ? 'lv-status-final' : 'lv-status-loading'}>
          {STATUS_MESSAGES[statusIdx]}
        </span>
      </div>
    </div>
  );
}

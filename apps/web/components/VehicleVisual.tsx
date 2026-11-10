"use client";

import { useEffect, useRef, useState } from "react";

/**
 * Decorative top-down car. It only reflects `lockState`, which callers must take from the backend.
 * It is not evidence of anything: the decision text and trace are the source of truth (design guardrail).
 * A short light flash plays when the backend-reported state changes, and is skipped under reduced motion.
 */
export function VehicleVisual({ lockState }: { lockState: "locked" | "unlocked" | undefined }) {
  const prev = useRef(lockState);
  const [flash, setFlash] = useState(0);

  useEffect(() => {
    if (prev.current && lockState && prev.current !== lockState) {
      // Re-key the flash animation each time the backend reports a new state.
      setFlash((n) => n + 1);
    }
    prev.current = lockState;
  }, [lockState]);

  const unlocked = lockState === "unlocked";
  return (
    <svg viewBox="0 0 240 120" role="img" aria-hidden="true" className="h-auto w-full max-w-sm">
      <style>{`
        .kg-flash { animation: kg-flash 0.9s ease-out 2; }
        @keyframes kg-flash { 0%,100% { opacity: 0.15 } 40% { opacity: 1 } }
        .kg-shackle { transition: transform 0.35s ease; }
        @media (prefers-reduced-motion: reduce) { .kg-flash { animation: none } .kg-shackle { transition: none } }
      `}</style>
      {/* body */}
      <rect x="20" y="22" width="200" height="76" rx="30" fill="var(--panel)" stroke="var(--line)" strokeWidth="2" />
      <rect x="70" y="32" width="100" height="56" rx="14" fill="var(--bg)" stroke="var(--line)" />
      <line x1="120" y1="32" x2="120" y2="88" stroke="var(--line)" />
      {/* wheels */}
      {[38, 182].map((x) => (
        <g key={x}>
          <rect x={x - 12} y="14" width="24" height="10" rx="4" fill="var(--line)" />
          <rect x={x - 12} y="96" width="24" height="10" rx="4" fill="var(--line)" />
        </g>
      ))}
      {/* lights: flash only when the backend reported a change */}
      <g key={flash} className={flash ? "kg-flash" : undefined} opacity={0.15}>
        {[38, 82].map((y) => (
          <rect key={`f${y}`} x="210" y={y - 6} width="8" height="12" rx="3" fill="var(--warn-fg)" />
        ))}
        {[38, 82].map((y) => (
          <rect key={`r${y}`} x="22" y={y - 6} width="8" height="12" rx="3" fill="var(--deny)" />
        ))}
      </g>
      {/* lock glyph */}
      <g transform="translate(108 46)">
        <path
          className="kg-shackle"
          style={{ transform: unlocked ? "translate(6px,-4px)" : "none" }}
          d="M4 12 V8 a8 8 0 0 1 16 0 V12"
          fill="none"
          stroke={unlocked ? "var(--allow)" : "var(--muted)"}
          strokeWidth="3"
        />
        <rect x="0" y="12" width="24" height="18" rx="3" fill={unlocked ? "var(--allow)" : "var(--muted)"} />
      </g>
    </svg>
  );
}

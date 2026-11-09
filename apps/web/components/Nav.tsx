"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV = [
  { href: "/", label: "Garage" },
  { href: "/keys", label: "Digital Keys" },
  { href: "/inspector", label: "Inspector" },
  { href: "/lab", label: "Attack Lab" },
  { label: "Analytics", sprint: 7 },
] as const;

export function Nav() {
  const pathname = usePathname();
  return (
    <nav aria-label="Primary">
      <ul className="flex flex-wrap gap-5 text-sm">
        {NAV.map((item) =>
          "href" in item ? (
            <li key={item.label}>
              <Link
                href={item.href}
                aria-current={pathname === item.href ? "page" : undefined}
                className="text-muted hover:text-fg aria-[current=page]:text-fg aria-[current=page]:underline underline-offset-8"
              >
                {item.label}
              </Link>
            </li>
          ) : (
            <li key={item.label} className="text-muted/60">
              {item.label} <span className="text-xs">(Sprint {item.sprint})</span>
            </li>
          ),
        )}
      </ul>
    </nav>
  );
}

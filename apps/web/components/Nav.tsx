"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV = [
  { href: "/", label: "Garage" },
  { href: "/keys", label: "Digital Keys" },
  { href: "/inspector", label: "Inspector" },
  { href: "/lab", label: "Attack Lab" },
  { href: "/proximity", label: "Proximity" },
  { href: "/analytics", label: "Analytics" },
  { href: "/account", label: "Account" },
] as const;

export function Nav() {
  const pathname = usePathname();
  return (
    <nav aria-label="Primary">
      <ul className="flex flex-wrap gap-5 text-sm">
        {NAV.map((item) => (
          <li key={item.label}>
            <Link
              href={item.href}
              aria-current={pathname === item.href ? "page" : undefined}
              className="text-muted hover:text-fg aria-[current=page]:text-fg aria-[current=page]:underline underline-offset-8"
            >
              {item.label}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}

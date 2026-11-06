import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "KeyGuard",
  description: "Educational digital vehicle access security lab. Fictional vehicles only.",
};

const NAV = [
  { href: "/", label: "Garage", ready: true },
  { href: "#", label: "Digital Keys", ready: false, sprint: 2 },
  { href: "#", label: "Inspector", ready: false, sprint: 6 },
  { href: "#", label: "Attack Lab", ready: false, sprint: 5 },
  { href: "#", label: "Analytics", ready: false, sprint: 7 },
];

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">
        <header className="border-b border-line">
          <div className="mx-auto flex max-w-5xl items-center gap-8 px-6 py-4">
            <span className="font-semibold tracking-wide">KEYGUARD</span>
            <nav aria-label="Primary">
              <ul className="flex flex-wrap gap-5 text-sm">
                {NAV.map((item) =>
                  item.ready ? (
                    <li key={item.label}>
                      <Link href={item.href} className="text-fg hover:text-accent" aria-current="page">
                        {item.label}
                      </Link>
                    </li>
                  ) : (
                    <li key={item.label} className="text-muted">
                      {item.label} <span className="text-xs">(not built yet, Sprint {item.sprint})</span>
                    </li>
                  ),
                )}
              </ul>
            </nav>
          </div>
        </header>
        <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">{children}</main>
        <footer className="border-t border-line px-6 py-4 text-center text-xs text-muted">
          Educational simulator. Fictional vehicles and simulated credentials only. No real vehicle integration.
        </footer>
      </body>
    </html>
  );
}

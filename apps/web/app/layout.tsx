import type { Metadata } from "next";
import { Nav } from "@/components/Nav";
import "./globals.css";

export const metadata: Metadata = {
  title: "KeyGuard",
  description: "Educational digital vehicle access security lab. Fictional vehicles only.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">
        <header className="border-b border-line">
          <div className="mx-auto flex max-w-5xl items-center gap-8 px-6 py-4">
            <span className="font-semibold tracking-wide">KEYGUARD</span>
            <Nav />
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

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App } from "./App";
import "./index.css";

// Set the theme before first paint (no inline script: CSP forbids it).
const stored = localStorage.getItem("theme");
if (stored ? stored === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches) document.documentElement.classList.add("dark");

const client = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 5_000, refetchOnWindowFocus: false } } });
const root = document.getElementById("root");
if (!root) throw new Error("#root missing");
createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);

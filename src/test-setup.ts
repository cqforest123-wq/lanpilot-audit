import "@testing-library/jest-dom/vitest";

const originalWarn = console.warn.bind(console);
console.warn = (...args: unknown[]) => {
  const message = args.map(String).join(" ");
  if (/Missing(?:\s+\S+)?\s+translation/i.test(message)) {
    throw new Error(`Translation warning is not allowed in tests: ${message}`);
  }
  originalWarn(...args);
};

const storage = new Map<string, string>();
Object.defineProperty(globalThis, "localStorage", {
  value: {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, value),
    removeItem: (key: string) => storage.delete(key),
    clear: () => storage.clear(),
  },
  configurable: true,
});

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { QuickCheckPanel } from "./QuickCheckPanel";
import { I18nProvider } from "./i18n";

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));

vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn().mockResolvedValue(() => undefined) }));

const network = (overrides: Record<string, unknown> = {}) => ({
  interfaces: [
    { name: "en0", kind: "physical", ipv4: "192.168.2.10", netmask: "255.255.255.0", prefix: 24, isUp: true, carriesFakeIp: false },
  ],
  dnsServers: ["1.1.1.1"],
  gateway: "192.168.2.1",
  tunnels: [],
  sandboxed: false,
  ...overrides,
});

// A default parameter would swallow an explicit `undefined`, which is exactly
// the "no report supplied" case one of the tests needs.
const renderPanel = (...args: [] | [React.ReactNode]) =>
  render(
    <I18nProvider>
      <QuickCheckPanel deepReport={args.length === 0 ? <div>deep report body</div> : args[0]} />
    </I18nProvider>,
  );

afterEach(() => {
  cleanup();
  invokeMock.mockReset();
});

describe("Quick Check panel", () => {
  it("offers the full-path tab when the app is not sandboxed", async () => {
    invokeMock.mockResolvedValue(network({ sandboxed: false }));
    renderPanel();
    expect(await screen.findByRole("tab", { name: "Full path" })).toBeVisible();
  });

  it("hides the full-path tab under App Sandbox", async () => {
    // That report shells out, which the sandbox forbids; a tab that can only
    // fail is worse than no tab.
    invokeMock.mockResolvedValue(network({ sandboxed: true }));
    renderPanel();
    await screen.findByRole("tab", { name: "Reachability" });
    expect(screen.queryByRole("tab", { name: "Full path" })).not.toBeInTheDocument();
  });

  it("hides the full-path tab when no report is supplied", async () => {
    invokeMock.mockResolvedValue(network());
    renderPanel(undefined as React.ReactNode);
    await screen.findByRole("tab", { name: "Reachability" });
    expect(screen.queryByRole("tab", { name: "Full path" })).not.toBeInTheDocument();
  });

  it("keeps the tools usable when the overview cannot be read", async () => {
    // A failed overview must not take the panel down with it.
    invokeMock.mockRejectedValue(new Error("bridge unavailable"));
    renderPanel();
    expect(await screen.findByRole("tab", { name: "Reachability" })).toBeVisible();
    expect(screen.getByRole("tab", { name: "Port" })).toBeVisible();
  });

  it("survives a malformed overview payload", async () => {
    invokeMock.mockResolvedValue({ unexpected: true });
    renderPanel();
    expect(await screen.findByRole("tab", { name: "Reachability" })).toBeVisible();
  });

  it("warns when an interface carries a proxy's synthetic address", async () => {
    invokeMock.mockResolvedValue(
      network({
        interfaces: [
          { name: "utun4", kind: "tunnel", ipv4: "198.18.0.1", netmask: "255.255.0.0", prefix: 16, isUp: true, carriesFakeIp: true },
        ],
        tunnels: ["utun4"],
      }),
    );
    renderPanel();
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("utun4 (198.18.0.1)"),
    );
  });
});

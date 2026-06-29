import { describe, expect, it } from "vitest";
import {
  diagnoseNetworkDoctor,
  normalizeNetworkDoctorEvidence,
  scoreState,
  type DiagnosticDomain,
  type NetworkDoctorEvidence,
} from "./network-doctor";

type FixtureCase = NetworkDoctorEvidence & {
  expectedPrimaryFaultDomain?: DiagnosticDomain;
  abnormal?: boolean;
};

const modules = import.meta.glob("../tests/fixtures/network-doctor/*.json", { eager: true, import: "default" }) as Record<string, FixtureCase>;
const fixtures = Object.entries(modules).map(([path, fixture]) => ({
  name: path.split("/").pop() ?? path,
  fixture,
}));

describe("Network Doctor evidence-based diagnosis", () => {
  it("loads all required public fixtures", () => {
    expect(fixtures.map((item) => item.name).sort()).toEqual([
      "application-slow-ttfb.json",
      "dhcp-self-assigned.json",
      "gateway-high-jitter.json",
      "gateway-packet-loss.json",
      "healthy-direct-ethernet.json",
      "healthy-wifi.json",
      "local-dns-slow.json",
      "multiple-overlay-conflict.json",
      "router-healthy.json",
      "router-high-conntrack.json",
      "router-memory-pressure.json",
      "stash-proxy-exit-slow.json",
      "stash-tun-healthy.json",
      "system-dns-overlay-slow.json",
      "tailscale-exit-node-failed.json",
      "tailscale-remote-access-only.json",
      "tcp-refused.json",
      "tcp-timeout.json",
      "tls-certificate-invalid.json",
      "tls-handshake-failed.json",
      "wifi-dfs-channel-risk.json",
      "wifi-high-jitter.json",
      "wifi-wide-channel-compatibility-risk.json",
    ]);
  });

  it("returns graph, layer mapping, candidates, advice, and retest plan for every abnormal fixture", () => {
    for (const { name, fixture } of fixtures.filter((item) => item.fixture.abnormal)) {
      const report = diagnoseNetworkDoctor(fixture);
      expect(report.primaryFaultDomain, name).toBe(fixture.expectedPrimaryFaultDomain);
      expect(report.osiLayerMapping.length, name).toBeGreaterThanOrEqual(1);
      expect(report.rootCauseCandidates.length, name).toBeGreaterThanOrEqual(2);
      expect(report.graph.nodes.length, name).toBeGreaterThanOrEqual(8);
      expect(report.graph.edges.length, name).toBeGreaterThanOrEqual(7);
      for (const candidate of report.rootCauseCandidates.slice(0, 2)) {
        expect(candidate.probability, name).toBeGreaterThan(0);
        expect(candidate.confidence, name).toMatch(/High|Medium|Low/);
        expect(candidate.evidenceFor.length, name).toBeGreaterThanOrEqual(1);
        expect(candidate.evidenceAgainst.length, name).toBeGreaterThanOrEqual(1);
        expect(candidate.remediationAdvice.length, name).toBeGreaterThanOrEqual(2);
        expect(candidate.retestPlan.length, name).toBeGreaterThanOrEqual(1);
      }
    }
  });

  it("does not mark DNS unavailable when ICMP is blocked but DNS queries work", () => {
    const fixture = modules["../tests/fixtures/network-doctor/healthy-direct-ethernet.json"];
    const report = diagnoseNetworkDoctor({
      ...fixture,
      observations: {
        ...fixture.observations,
        dns: {
          resolverChecks: [
            { name: "114DNS", address: "114.114.114.114", icmpReachable: false, queryStatus: "ok", responseMs: 28, resolvedIp: "203.0.113.10", viaOverlay: false },
          ],
        },
      },
    });
    expect(report.primaryFaultDomain).not.toBe("local_dns");
    expect(report.domainStatuses.find((item) => item.domain === "local_dns")?.status).toBe("healthy");
  });

  it("does not treat a healthy Stash TUN path as a gateway failure", () => {
    const report = diagnoseNetworkDoctor(modules["../tests/fixtures/network-doctor/stash-tun-healthy.json"]);
    expect(report.primaryFaultDomain).not.toBe("gateway");
    expect(report.domainStatuses.find((item) => item.domain === "gateway")?.status).toBe("healthy");
  });

  it("does not treat Tailscale remote-access-only state as an active exit path", () => {
    const report = diagnoseNetworkDoctor(modules["../tests/fixtures/network-doctor/tailscale-remote-access-only.json"]);
    expect(report.primaryFaultDomain).not.toBe("tailscale");
    expect(report.domainStatuses.find((item) => item.domain === "tailscale")?.status).toBe("healthy");
  });

  it("keeps Wi-Fi 160 MHz as a compatibility risk instead of a direct failure", () => {
    const report = diagnoseNetworkDoctor(modules["../tests/fixtures/network-doctor/wifi-wide-channel-compatibility-risk.json"]);
    expect(report.primaryFaultDomain).toBe("wifi_radio");
    expect(report.rootCauseCandidates[0].confidence).not.toBe("High");
    expect(report.overallStatus).toBe("healthy");
  });

  it("keeps refused, timeout, TLS handshake, and certificate cases separate", () => {
    expect(diagnoseNetworkDoctor(modules["../tests/fixtures/network-doctor/tcp-refused.json"]).primaryFaultDomain).toBe("transport_tcp");
    expect(diagnoseNetworkDoctor(modules["../tests/fixtures/network-doctor/tcp-timeout.json"]).primaryFaultDomain).toBe("transport_tcp");
    expect(diagnoseNetworkDoctor(modules["../tests/fixtures/network-doctor/tls-handshake-failed.json"]).primaryFaultDomain).toBe("tls");
    expect(diagnoseNetworkDoctor(modules["../tests/fixtures/network-doctor/tls-certificate-invalid.json"]).primaryFaultDomain).toBe("tls");
  });

  it("does not blame the router for an external slow path without router evidence", () => {
    const report = diagnoseNetworkDoctor(modules["../tests/fixtures/network-doctor/application-slow-ttfb.json"]);
    expect(report.primaryFaultDomain).not.toBe("router_health");
    expect(report.domainStatuses.find((item) => item.domain === "router_health")?.status).toBe("unknown");
  });

  it("lowers confidence when one gateway sample is noisy", () => {
    const report = diagnoseNetworkDoctor({
      profile: "One noisy sample",
      observations: {
        gateway: { sampleCount: 1, avgMs: 90, jitterMs: 0, lossPct: 0 },
      },
    });
    expect(report.primaryFaultDomain).toBe("gateway");
    expect(report.rootCauseCandidates[0].confidence).toBe("Low");
  });

  it("supports Quick Check and Deep Diagnosis sample targets", () => {
    const quick = diagnoseNetworkDoctor(modules["../tests/fixtures/network-doctor/healthy-direct-ethernet.json"], "quick");
    const deep = diagnoseNetworkDoctor(modules["../tests/fixtures/network-doctor/gateway-high-jitter.json"], "deep");
    expect(quick.modeProfile.targetDurationSeconds).toEqual([20, 30]);
    expect(quick.modeProfile.gatewaySampleTarget).toEqual([10, 20]);
    expect(deep.modeProfile.targetDurationSeconds).toEqual([120, 300]);
    expect(deep.modeProfile.gatewaySampleTarget).toEqual([100, 200]);
    expect(normalizeNetworkDoctorEvidence(modules["../tests/fixtures/network-doctor/gateway-high-jitter.json"]).observations.gateway.sampleCount).toBeGreaterThanOrEqual(100);
  });

  it("keeps unknown unmapped from L7 for healthy ambiguous runs", () => {
    const report = diagnoseNetworkDoctor(modules["../tests/fixtures/network-doctor/healthy-direct-ethernet.json"]);
    expect(report.primaryFaultDomain).toBe("unknown");
    expect(report.osiLayerMapping[0].layers).toEqual([]);
  });

  it("treats 220 ms system DNS as warning and labels mid scores acceptable", () => {
    const report = diagnoseNetworkDoctor({
      profile: "Slow system DNS",
      observations: {
        dns: {
          resolverChecks: [
            { name: "System DNS", address: "203.0.113.53", queryStatus: "ok", responseMs: 220, viaOverlay: true },
          ],
        },
      },
    });
    expect(report.domainStatuses.find((item) => item.domain === "system_dns")?.status).toBe("warning");
    expect(scoreState(68)).toBe("Acceptable");
  });
});

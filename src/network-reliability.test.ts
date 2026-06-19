import { describe, expect, it } from "vitest";
import {
  buildNetworkReliabilityMarkdown,
  compareNetworkBaselines,
  diagnoseNetworkReliability,
  type NetworkReliabilityEvidence,
} from "./network-reliability";
import healthyDirect from "../tests/fixtures/network-reliability/healthy-physical-lan-direct.json";
import healthyStashTun from "../tests/fixtures/network-reliability/healthy-physical-lan-stash-tun.json";
import tailscaleExitNodeSlow from "../tests/fixtures/network-reliability/tailscale-exit-node-slow.json";
import gatewayPacketLoss from "../tests/fixtures/network-reliability/gateway-packet-loss.json";
import localDnsSlow from "../tests/fixtures/network-reliability/local-dns-slow.json";
import externalHttpsSlow from "../tests/fixtures/network-reliability/external-https-slow.json";
import dhcpSelfAssigned from "../tests/fixtures/network-reliability/dhcp-failure-self-assigned.json";
import localDevServiceExposed from "../tests/fixtures/network-reliability/local-dev-service-exposed.json";
import multipleOverlayConflict from "../tests/fixtures/network-reliability/multiple-overlay-conflict.json";
import beforeAfterRouteChange from "../tests/fixtures/network-reliability/before-after-route-change.json";

const healthyDirectFixture = healthyDirect as NetworkReliabilityEvidence;
const healthyStashTunFixture = healthyStashTun as NetworkReliabilityEvidence;
const tailscaleExitNodeSlowFixture = tailscaleExitNodeSlow as NetworkReliabilityEvidence;
const gatewayPacketLossFixture = gatewayPacketLoss as NetworkReliabilityEvidence;
const localDnsSlowFixture = localDnsSlow as NetworkReliabilityEvidence;
const externalHttpsSlowFixture = externalHttpsSlow as NetworkReliabilityEvidence;
const dhcpSelfAssignedFixture = dhcpSelfAssigned as NetworkReliabilityEvidence;
const localDevServiceExposedFixture = localDevServiceExposed as NetworkReliabilityEvidence;
const multipleOverlayConflictFixture = multipleOverlayConflict as NetworkReliabilityEvidence;
const beforeAfterRouteChangeFixture = beforeAfterRouteChange as {
  previous: NetworkReliabilityEvidence;
  current: NetworkReliabilityEvidence;
};

const fixtures: NetworkReliabilityEvidence[] = [
  healthyDirectFixture,
  healthyStashTunFixture,
  tailscaleExitNodeSlowFixture,
  gatewayPacketLossFixture,
  localDnsSlowFixture,
  externalHttpsSlowFixture,
  dhcpSelfAssignedFixture,
  localDevServiceExposedFixture,
  multipleOverlayConflictFixture,
];

describe("network reliability diagnostics", () => {
  it("returns the required diagnostic summary fields for every public fixture", () => {
    for (const fixture of fixtures) {
      const diagnosis = diagnoseNetworkReliability(fixture);
      expect(diagnosis.overallStatus, fixture.profile).toBeTruthy();
      expect(diagnosis.physicalLanStatus, fixture.profile).toBeTruthy();
      expect(diagnosis.dnsStatus, fixture.profile).toBeTruthy();
      expect(diagnosis.overlayStatus, fixture.profile).toBeTruthy();
      expect(diagnosis.externalPathStatus, fixture.profile).toBeTruthy();
      expect(diagnosis.faultDomain, fixture.profile).toBeTruthy();
      expect(diagnosis.faultPoint, fixture.profile).toBeTruthy();
      expect(diagnosis.impact, fixture.profile).toBeTruthy();
      expect(diagnosis.evidence.length, fixture.profile).toBeGreaterThanOrEqual(2);
      expect(diagnosis.remediationAdvice.length, fixture.profile).toBeGreaterThanOrEqual(2);
      expect(diagnosis.retestPlan.length, fixture.profile).toBeGreaterThanOrEqual(1);
      expect(Array.isArray(diagnosis.rawEvidenceRefs), fixture.profile).toBe(true);
    }
  });

  it("treats Stash TUN as an overlay observation without blaming the gateway", () => {
    const diagnosis = diagnoseNetworkReliability(healthyStashTunFixture);
    expect(diagnosis.physicalLanStatus).toBe("healthy");
    expect(["warning", "healthy"]).toContain(diagnosis.overlayStatus);
    expect(["overlay_proxy", "none"]).toContain(diagnosis.faultDomain);
    expect(diagnosis.faultPoint.toLowerCase()).not.toContain("gateway");
    expect(diagnosis.remediationAdvice.join(" ")).toMatch(/Stash.*node.*rule.*DNS.*proxy exit/i);
  });

  it("identifies a slow Tailscale Exit Node path and gives focused retest advice", () => {
    const diagnosis = diagnoseNetworkReliability(tailscaleExitNodeSlowFixture);
    expect(diagnosis.faultDomain).toBe("tailscale_exit_node");
    expect(diagnosis.remediationAdvice.join(" ")).toContain("Disable Exit Node");
    expect(diagnosis.remediationAdvice.join(" ")).toContain("Disable Tailscale DNS");
    expect(diagnosis.retestPlan.join(" ")).toContain("Exit Node");
  });

  it("keeps gateway packet loss in the physical gateway domain", () => {
    const diagnosis = diagnoseNetworkReliability(gatewayPacketLossFixture);
    expect(diagnosis.faultDomain).toBe("gateway");
    expect(diagnosis.remediationAdvice.join(" ")).toMatch(/cable.*switch.*router.*USB Ethernet adapter/i);
  });

  it("detects local DNS, external HTTPS, local service, overlay conflict, and DHCP cases", () => {
    expect(diagnoseNetworkReliability(localDnsSlowFixture).faultDomain).toBe("local_dns");
    expect(diagnoseNetworkReliability(externalHttpsSlowFixture).faultDomain).toBe("external_path");
    expect(diagnoseNetworkReliability(localDevServiceExposedFixture).faultDomain).toBe("local_service_exposure");
    expect(diagnoseNetworkReliability(multipleOverlayConflictFixture).faultDomain).toBe("overlay_proxy");
    expect(diagnoseNetworkReliability(dhcpSelfAssignedFixture).faultDomain).toBe("dhcp");
  });

  it("keeps external failure outside the LAN when gateway and DNS are healthy", () => {
    const fixture = {
      ...healthyDirectFixture,
      external: {
        targets: [
          { group: "apple", url: "https://www.apple.com", failed: true },
          { group: "developer", url: "https://github.com", failed: true },
        ],
      },
    } as NetworkReliabilityEvidence;
    const diagnosis = diagnoseNetworkReliability(fixture);
    expect(diagnosis.physicalLanStatus).toBe("healthy");
    expect(diagnosis.dnsStatus).toBe("healthy");
    expect(diagnosis.faultDomain).toBe("external_path");
  });

  it("compares route, DNS, public path, and overlay baseline changes", () => {
    const changes = compareNetworkBaselines(beforeAfterRouteChangeFixture.previous, beforeAfterRouteChangeFixture.current);
    expect(changes.map((change) => change.field)).toEqual(expect.arrayContaining(["default route", "DNS", "public IP", "Stash status"]));
    expect(changes.length).toBeGreaterThanOrEqual(4);
  });

  it("builds English and simplified Chinese report headings exactly", () => {
    const diagnosis = diagnoseNetworkReliability(healthyDirectFixture);
    const english = buildNetworkReliabilityMarkdown(diagnosis, healthyDirectFixture, "en");
    const chinese = buildNetworkReliabilityMarkdown(diagnosis, healthyDirectFixture, "zh-CN");
    for (const heading of [
      "# Network Reliability Report",
      "## Overall Diagnosis",
      "## Current Network Path",
      "## Fault Point",
      "## Impact",
      "## Key Evidence",
      "## Troubleshooting Advice",
      "## Retest Plan",
      "## Physical LAN",
      "## DNS",
      "## Overlay / Proxy / VPN",
      "## External Internet",
      "## Local Listening Services",
      "## Raw Evidence",
    ]) expect(english).toContain(heading);
    for (const heading of [
      "# 网络可靠性报告",
      "## 总体诊断",
      "## 当前网络路径",
      "## 故障点",
      "## 影响判断",
      "## 关键证据",
      "## 处理建议",
      "## 复测方法",
      "## 物理网络",
      "## DNS",
      "## Overlay / 代理 / VPN",
      "## 外部网络",
      "## 本机监听服务",
      "## 原始证据",
    ]) expect(chinese).toContain(heading);
  });
});

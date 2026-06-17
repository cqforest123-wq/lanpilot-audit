import { describe, expect, it } from "vitest";
import { buildRemediationPack } from "./remediation-assistant";

const finding = {
  severity:"High", asset:"Default gateway", category:"Gateway",
  finding:"Default gateway exposes management services to the local client network.",
  recommended_action:"Review exposure.", status:"open",
};

describe("remediation assistant", () => {
  it("builds structured manual guidance without executable content", () => {
    const pack = buildRemediationPack([finding, finding], "zh-CN", "/tmp/lab");
    expect(pack.tickets).toHaveLength(1);
    expect(pack.tickets[0].asset).toBe("默认网关");
    expect(pack.tickets[0].status).toBe("open");
    expect(pack.tickets[0].manualSteps).toEqual(expect.any(Array));
  });
});

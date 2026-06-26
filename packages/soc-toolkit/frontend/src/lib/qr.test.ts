import { describe, expect, it } from "vitest";

import { analyzeQrPayload } from "./qr";

describe("analyzeQrPayload", () => {
  it("classifies an http URL and flags the missing TLS", () => {
    const result = analyzeQrPayload("http://example.com/login");
    expect(result.kind).toBe("url");
    expect(result.flags).toContain("Not HTTPS");
  });

  it("flags shorteners, IP hosts and punycode look-alikes", () => {
    expect(analyzeQrPayload("https://bit.ly/abc").flags).toContain(
      "URL shortener — hides the real destination",
    );
    expect(analyzeQrPayload("https://1.2.3.4/x").flags).toContain(
      "IP address instead of a domain",
    );
    expect(
      analyzeQrPayload("https://xn--80ak6aa92e.com").flags.some((f) =>
        f.includes("Punycode"),
      ),
    ).toBe(true);
  });

  it("returns no flags for a clean https URL", () => {
    expect(analyzeQrPayload("https://example.com/").flags).toEqual([]);
  });

  it("classifies wifi and plain text payloads", () => {
    expect(analyzeQrPayload("WIFI:S:Net;T:WPA;P:secret;;").kind).toBe("wifi");
    expect(analyzeQrPayload("just some text").kind).toBe("text");
  });
});

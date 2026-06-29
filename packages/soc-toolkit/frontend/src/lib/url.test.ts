import { describe, expect, it } from "vitest";
import { urlRiskFlags } from "./url";

describe("urlRiskFlags", () => {
  it("clears a plain HTTPS domain", () => {
    expect(urlRiskFlags("https://example.com/path")).toEqual([]);
  });

  it("flags non-HTTPS", () => {
    expect(urlRiskFlags("http://example.com")).toContain("Not HTTPS");
  });

  it("flags URL shorteners", () => {
    expect(urlRiskFlags("https://bit.ly/abc")).toContain(
      "URL shortener - hides the real destination",
    );
  });

  it("flags a raw IP host", () => {
    expect(urlRiskFlags("http://192.168.0.1/login")).toContain(
      "IP address instead of a domain",
    );
  });

  it("flags punycode/IDN look-alikes", () => {
    expect(urlRiskFlags("https://xn--80ak6aa92e.com")).toContain(
      "Punycode/IDN domain - possible look-alike",
    );
  });

  it("flags embedded credentials", () => {
    expect(urlRiskFlags("https://user:pass@example.com")).toContain(
      "Credentials embedded in the URL",
    );
  });

  it("flags a malformed URL", () => {
    expect(urlRiskFlags("not a url")).toContain("Malformed URL");
  });

  it("flags multiple embedded URLs as a redirect chain", () => {
    expect(urlRiskFlags("https://safe.com/r?u=https://evil.com")).toContain(
      "Multiple URLs - possible redirect chain",
    );
  });
});

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import SigmaDetection from "../SigmaDetection";
import * as api from "../../api/client";

vi.mock("../../api/client");

describe("SigmaDetection - rule library + compile", () => {
  beforeEach(() => {
    vi.mocked(api.listSigmaRules).mockResolvedValue({
      rule_count: 1,
      rules: [
        {
          id: "demo.ssh_bruteforce",
          title: "SSH brute force",
          level: "high",
          tags: ["attack.credential_access"],
          description: "Too many failed logins from one source.",
          logsource: { product: "linux", service: "ssh" },
        },
      ],
    });
    vi.mocked(api.compileSigmaRule).mockResolvedValue({
      backend: "splunk",
      rule_id: "demo.ssh_bruteforce",
      title: "SSH brute force",
      level: "high",
      query: 'event_type="ssh_login" auth_result="failed"',
    });
  });

  it("renders loaded rules and compiles on demand", async () => {
    render(<SigmaDetection />);

    expect(await screen.findByText("SSH brute force")).toBeInTheDocument();
    expect(screen.getByText(/rule library \(1\)/i)).toBeInTheDocument();

    await userEvent.click(
      screen.getByRole("button", { name: /compile to siem query/i }),
    );
    await userEvent.click(screen.getByRole("button", { name: /splunk spl/i }));

    expect(api.compileSigmaRule).toHaveBeenCalledWith(
      "demo.ssh_bruteforce",
      "splunk",
    );
    expect(
      await screen.findByText(/event_type="ssh_login" auth_result="failed"/),
    ).toBeInTheDocument();
  });

  it("surfaces a friendly message when compile fails", async () => {
    vi.mocked(api.compileSigmaRule).mockRejectedValue(
      new Error("unsupported feature"),
    );
    render(<SigmaDetection />);

    await screen.findByText("SSH brute force");
    await userEvent.click(
      screen.getByRole("button", { name: /compile to siem query/i }),
    );
    await userEvent.click(screen.getByRole("button", { name: /kql \/ sentinel/i }));

    expect(
      await screen.findByText(/unsupported feature/i),
    ).toBeInTheDocument();
  });
});

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ActiveScanCard } from "../TargetDetail";
import * as api from "../../api/client";

vi.mock("../../api/client");

describe("ActiveScanCard - confirmation gate", () => {
  const onComplete = vi.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    onComplete.mockClear();
    vi.mocked(api.runActiveScan).mockResolvedValue({
      scan_id: 99,
      target_id: 1,
      status: "completed",
      summary: {
        tool: "subfinder",
        discovered_total: 3,
        new: 2,
        stderr_tail: [],
      },
      discovered: ["a.acme.example", "b.acme.example", "c.acme.example"],
    });
  });

  async function openModal(targetName = "Prod-Perimeter") {
    render(
      <ActiveScanCard
        targetId={1}
        targetName={targetName}
        onComplete={onComplete}
      />,
    );
    await userEvent.click(
      screen.getByRole("button", { name: /start active scan/i }),
    );
  }

  it("disables submit until the target name is typed verbatim", async () => {
    await openModal();

    const run = screen.getByRole("button", { name: /run active scan/i });
    expect(run).toBeDisabled();

    const input = screen.getByPlaceholderText(/type the target name/i);
    await userEvent.type(input, "wrong-name");
    expect(run).toBeDisabled();

    await userEvent.clear(input);
    await userEvent.type(input, "Prod-Perimeter");
    expect(run).toBeEnabled();
  });

  it("accepts a case-insensitive match of the target name", async () => {
    await openModal("Prod-Perimeter");

    await userEvent.type(
      screen.getByPlaceholderText(/type the target name/i),
      "prod-PERIMETER",
    );
    expect(screen.getByRole("button", { name: /run active scan/i })).toBeEnabled();
  });

  it("calls runActiveScan and refreshes parent on success", async () => {
    await openModal();
    await userEvent.type(
      screen.getByPlaceholderText(/type the target name/i),
      "Prod-Perimeter",
    );
    await userEvent.click(screen.getByRole("button", { name: /run active scan/i }));

    expect(api.runActiveScan).toHaveBeenCalledWith(1, "Prod-Perimeter");
    expect(onComplete).toHaveBeenCalledTimes(1);
  });

  it("surfaces backend error detail without closing the modal", async () => {
    vi.mocked(api.runActiveScan).mockRejectedValueOnce({
      response: { data: { detail: "active scanning disabled" } },
    });

    await openModal();
    await userEvent.type(
      screen.getByPlaceholderText(/type the target name/i),
      "Prod-Perimeter",
    );
    await userEvent.click(screen.getByRole("button", { name: /run active scan/i }));

    expect(await screen.findByText(/active scanning disabled/i)).toBeInTheDocument();
    // Modal still open - the run button remains visible.
    expect(screen.getByRole("button", { name: /run active scan/i })).toBeInTheDocument();
    expect(onComplete).not.toHaveBeenCalled();
  });
});

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Targets from "../Targets";
import * as api from "../../api/client";

vi.mock("../../api/client");

describe("Targets page - authorization gate", () => {
  beforeEach(() => {
    vi.mocked(api.listTargets).mockResolvedValue([]);
    vi.mocked(api.createTarget).mockResolvedValue({
      id: 1,
      name: "Acme",
      owner_email: "",
      scope_domains: ["acme.example"],
      authorized_to_scan: true,
      active: true,
      created_at: new Date().toISOString(),
    });
  });

  async function openForm() {
    render(
      <MemoryRouter>
        <Targets />
      </MemoryRouter>,
    );
    await screen.findByText(/No targets yet/i);
    await userEvent.click(screen.getByRole("button", { name: /new target/i }));
  }

  it("disables 'Create target' until authorization checkbox is ticked", async () => {
    await openForm();

    await userEvent.type(screen.getByPlaceholderText(/Acme Corp/i), "Acme");
    await userEvent.type(
      screen.getByPlaceholderText(/acme\.test/i),
      "acme.example",
    );

    const submit = screen.getByRole("button", { name: /create target/i });
    expect(submit).toBeDisabled();

    await userEvent.click(screen.getByRole("checkbox"));
    expect(submit).toBeEnabled();
  });

  it("forwards authorized_to_scan=true when the form is submitted", async () => {
    await openForm();

    await userEvent.type(screen.getByPlaceholderText(/Acme Corp/i), "Acme");
    await userEvent.type(
      screen.getByPlaceholderText(/acme\.test/i),
      "acme.example, acme.test",
    );
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: /create target/i }));

    expect(api.createTarget).toHaveBeenCalledWith({
      name: "Acme",
      owner_email: undefined,
      scope_domains: ["acme.example", "acme.test"],
      authorized_to_scan: true,
    });
  });
});

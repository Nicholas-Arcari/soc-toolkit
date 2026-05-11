import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import i18n from "../../../i18n";

import Sidebar from "../Sidebar";

describe("Sidebar - i18n language toggle", () => {
  afterEach(async () => {
    await i18n.changeLanguage("en");
  });

  it("switches nav labels from English to Italian when IT is clicked", async () => {
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>,
    );

    expect(screen.getByText("Targets")).toBeInTheDocument();
    expect(screen.getByText("Investigate")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "it" }));

    expect(screen.getByText("Obiettivi")).toBeInTheDocument();
    expect(screen.getByText("Indagine")).toBeInTheDocument();
  });

  it("marks the active language with aria-pressed", async () => {
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>,
    );

    const en = screen.getByRole("button", { name: "en" });
    const it = screen.getByRole("button", { name: "it" });

    expect(en).toHaveAttribute("aria-pressed", "true");
    expect(it).toHaveAttribute("aria-pressed", "false");

    await userEvent.click(it);

    expect(en).toHaveAttribute("aria-pressed", "false");
    expect(it).toHaveAttribute("aria-pressed", "true");
  });
});

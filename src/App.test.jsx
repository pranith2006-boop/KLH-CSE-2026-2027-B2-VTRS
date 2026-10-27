import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { AIModal, CodeDiff } from "./App.jsx";

const vulnerability = {
  id: "finding-1",
  title: "SQL query built with interpolation",
  severity: "High",
  code: 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
};

describe("AI remediation review", () => {
  it("shows a side-by-side proposal and waits for an explicit user decision", async () => {
    const user = userEvent.setup();
    const apiRequest = vi.fn(async (path) => {
      if (path === "/api/ai/status") return { configured: true, provider: "OpenRouter", model: "openrouter/free" };
      if (path === "/api/ai/remediation") return {
        suggestionId: "suggestion-1", provider: "OpenRouter", model: "openrouter/free",
        explanation: "Bind user-controlled values as parameters.",
        vulnerable_code: vulnerability.code,
        fixed_code: 'cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
        why_it_works: "The database receives values separately from SQL syntax.",
      };
      return { status: "rejected", applied: false };
    });
    render(<AIModal vulnerability={vulnerability} onClose={vi.fn()} apiRequest={apiRequest} />);
    await user.click(await screen.findByRole("button", { name: /send snippet and generate/i }));
    expect(await screen.findByText("Bind user-controlled values as parameters.")).toBeInTheDocument();
    expect(screen.getByText("The database receives values separately from SQL syntax.")).toBeInTheDocument();
    expect(screen.getAllByText(vulnerability.code).length).toBeGreaterThan(0);
    expect(screen.getByText('cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))')).toBeInTheDocument();
    expect(apiRequest).toHaveBeenCalledTimes(2);
    await user.click(screen.getByRole("button", { name: "Reject" }));
    await waitFor(() => expect(apiRequest).toHaveBeenCalledTimes(3));
    expect(apiRequest.mock.calls[2][1].body).toBe(JSON.stringify({ decision: "reject" }));
    expect(screen.getByText("Suggestion rejected. No source copy was changed.")).toBeInTheDocument();
  });

  it("renders changed lines in a two-column diff", () => {
    render(<CodeDiff before="unsafe()" after="safe()" />);
    expect(screen.getByText("Vulnerable code")).toBeInTheDocument();
    expect(screen.getByText("Proposed fix")).toBeInTheDocument();
    expect(screen.getByText("unsafe()")).toBeInTheDocument();
    expect(screen.getByText("safe()")).toBeInTheDocument();
  });
});

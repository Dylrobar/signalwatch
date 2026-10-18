import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SourceIssues } from "./SourceIssues";

describe("SourceIssues", () => {
  it("keeps issue details collapsed initially and renders response HTML only as an omission", () => {
    const { container } = render(<SourceIssues errors={["HTTP 429: https://query.example/?query=SELECT+company <!DOCTYPE html><html><script>alert('bad')</script></html>"]} />);
    expect(screen.getByText("Rate limited (HTTP 429)")).toBeInTheDocument();
    expect(screen.getByText("Issue details")).toBeInTheDocument();
    expect(container.querySelector("details")).not.toHaveAttribute("open");
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getByRole("region", { hidden: true })).toHaveTextContent("response body omitted");
  });

  it("renders no issue control for a healthy source", () => {
    const { container } = render(<SourceIssues errors={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows a scheduled retry without hiding the source error", () => {
    const { rerender } = render(<SourceIssues errors={["HTTP 429: https://query.example/"]} retryAt="2199-01-01T00:00:00Z" />);
    expect(screen.getByText(/^Retry after /)).toBeInTheDocument();
    expect(screen.getByText("Rate limited (HTTP 429)")).toBeInTheDocument();
    rerender(<SourceIssues errors={["HTTP 429: https://query.example/"]} retryAt="2000-01-01T00:00:00Z" />);
    expect(screen.queryByText(/^Retry after /)).not.toBeInTheDocument();
  });
});

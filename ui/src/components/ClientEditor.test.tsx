import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import ClientEditor from "./ClientEditor";

describe("client metadata controls", () => {
 it("saves added/removed URI rows and enum selections without splitting response combinations", async () => {
  const save = vi.fn().mockResolvedValue(undefined);
  render(<ClientEditor onSave={save} onCancel={vi.fn()} />);
  await userEvent.type(screen.getByRole("textbox", { name: "Redirect URIs" }), "https://first.example/cb");
  await userEvent.click(screen.getByRole("button", { name: "Add redirect URI" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Redirect URIs 2" }), "https://second.example/cb");
  await userEvent.click(screen.getByRole("button", { name: "Remove redirect URI 1" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Contacts" }), "owner@example.com");
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "ID token signing algorithm" }), "RS256");
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "ID token encryption algorithm" }), "RSA-OAEP-256");
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "ID token encryption method" }), "A256GCM");
  await userEvent.click(within(screen.getByRole("group", { name: "Response types" })).getByRole("checkbox", { name: /^code id_token Not/ }));
  await userEvent.click(within(screen.getByRole("group", { name: "Grant types" })).getByRole("checkbox", { name: /^implicit / }));
  await userEvent.click(screen.getByRole("button", { name: "Create client" }));
  await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({ redirect_uris: ["https://second.example/cb"], contacts: ["owner@example.com"], response_types: ["code", "code id_token"], grant_types: ["authorization_code", "implicit"], id_token_signed_response_alg: "RS256", id_token_encrypted_response_alg: "RSA-OAEP-256", id_token_encrypted_response_enc: "A256GCM" })));
 });
 it("does not silently restore defaults when all response types are unchecked", async () => {
  const save = vi.fn(); render(<ClientEditor onSave={save} onCancel={vi.fn()} />);
  await userEvent.type(screen.getByRole("textbox", { name: "Redirect URIs" }), "https://app.example/cb");
  await userEvent.click(within(screen.getByRole("group", { name: "Response types" })).getByRole("checkbox", { name: "code" }));
  await userEvent.click(screen.getByRole("button", { name: "Create client" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Select at least one response type.");
  expect(save).not.toHaveBeenCalled();
 });
});

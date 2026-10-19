# Instructions: build the TIP-1151 Google Doc

Create one Google Doc titled **"TIP-1151: Signed Deposit Authorizations for Zone Portals"** in my
Google Drive from the files in this folder. Use your Google Docs / Drive access.

## Source files

- `TIP-1151-writeup.md`: the document content. Use it in full, in order, without rewriting the
  substance.
- `TIP-1151-diagrams.md`: the diagram index. Add it as an appendix titled "Appendix: Diagrams".
- `*.excalidraw`: editable diagram sources. Do not paste their JSON into the doc. Upload them to the
  same Drive folder as the doc and link them from the appendix.

## Formatting

- Map Markdown headings to Google Docs Heading 1, 2, and 3. Put a table of contents after the
  metadata block at the top.
- Insert every `![...](https://...png)` image inline at that position, at full page width, using the
  public URL. Put the alt text underneath as an italic caption.
- Convert Markdown tables to native Google Docs tables with a bold header row.
- Put code blocks (Solidity, JSON, bash, text) in a monospace font such as Roboto Mono, 9 pt, with a
  light gray background.
- Mermaid blocks (` ```mermaid `): render each one to PNG (for example with
  `npx -y @mermaid-js/mermaid-cli -i in.mmd -o out.png -b white`, or https://mermaid.ink), insert the
  image, and remove the Mermaid source from the doc.
- Make links clickable. Keep the PR links at the top.

## When you are done

Share the doc as "anyone in the organization with the link can comment", unless I say otherwise.
Reply with the doc URL and the Drive folder URL.

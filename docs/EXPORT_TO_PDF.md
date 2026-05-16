# Export Mermaid Docs to PDF (Windows)

You have a PDF-ready Mermaid document at:
- `docs/ARCHITECTURE_PDF.md`

## Option A (Recommended): VS Code + Markdown Preview Enhanced

1. Install extension:
   - **Markdown Preview Enhanced** (`shd101wyy.markdown-preview-enhanced`)
2. Open:
   - `docs/ARCHITECTURE_PDF.md`
3. Render preview:
   - Command Palette → **Markdown Preview Enhanced: Open Preview to the Side**
4. Export to PDF:
   - Command Palette → **Markdown Preview Enhanced: Export (PDF)**

This renders Mermaid diagrams automatically.

## Option B: Mermaid CLI to images + Word/PDF

If you want vector-like diagram images:

1. Install Node.js
2. Install mermaid-cli:
   - `npm i -g @mermaid-js/mermaid-cli`
3. Convert each Mermaid block to PNG/SVG:
   - Save each diagram into a `.mmd` file and run:
     - `mmdc -i diagram.mmd -o diagram.png`
4. Paste images into Word and export PDF.

## Option C: Pandoc (advanced)

Pandoc PDF export typically needs a LaTeX engine.
If you already have Pandoc + a LaTeX distribution installed:

- `pandoc docs/ARCHITECTURE_PDF.md -o docs/ARCHITECTURE_PDF.pdf`

Mermaid rendering may still require a pre-render step to images.


# Desktop source recovery

The original `apps/desktop` sources were missing from this workspace. The published 0.1.1
frontend was recovered from Tauri's Brotli-compressed codegen assets and formatted into
`src/app.js`. The CSS, HTML, and logo came from the same artifact set.

This keeps the published UI operational and editable while a future change may replace the
recovered bundle with component-level sources. `scripts/build.mjs` deliberately performs only
deterministic copies; it does not minify or transform the recovered JavaScript.

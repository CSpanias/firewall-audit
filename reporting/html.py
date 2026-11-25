"""Self-contained HTML assessment report with Markdown copy controls."""

import json
from html import escape, unescape
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import markdown
from markdown.extensions import Extension
from markdown.treeprocessors import Treeprocessor

from reporting.narrative import build_narratives


class _SafeLinks(Treeprocessor):
    def run(self, root: Any) -> None:
        for element in root.iter():
            if element.tag == "a":
                try:
                    url = urlsplit(element.get("href", ""))
                    valid = url.scheme.lower() in {"http", "https"} and bool(url.netloc)
                except ValueError:
                    valid = False
                if not valid:
                    element.attrib.pop("href", None)
            elif element.tag == "img":
                element.tag = "span"
                element.text = element.get("alt", "")
                element.attrib.clear()
            elif element.tag == "code" and element.text:
                element.text = unescape(element.text)
        for cell in root.iter():
            if cell.tag in {"td", "th"}:
                for code in cell.iter("code"):
                    if code.text:
                        code.text = code.text.replace(r"\|", "|")


class _SafeLinksExtension(Extension):
    def extendMarkdown(self, md: Any) -> None:
        md.treeprocessors.register(_SafeLinks(md), "safe_links", 0)


def _safe_json(value: Any) -> str:
    return (
        json.dumps(value, ensure_ascii=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _render_markdown(text: str) -> str:
    return markdown.markdown(
        escape(text, quote=False), extensions=["tables", _SafeLinksExtension()]
    )


def render_html(report: dict[str, Any]) -> str:
    """Render a self-contained, safely escaped assessment report."""
    narratives = build_narratives(report)
    sections = (
        ("executive_summary", "Executive Summary"),
        ("technical_commentary", "Technical Commentary"),
        ("remediation_guidance", "Remediation Guidance"),
    )
    markdown_data = dict(narratives)
    markdown_data["all"] = "\n\n".join(
        f"## {title}\n\n{narratives[key]}" for key, title in sections
    )

    def controls(key: str, label: str) -> str:
        return (
            f'<div class="copy-controls"><button type="button" class="copy-button" '
            f'data-copy="{key}">{label}</button>'
            '<span class="copy-status" role="status" aria-live="polite"></span></div>'
        )

    rendered = "\n".join(
        f"<section><h2>{title}</h2>{controls(key, 'Copy Markdown')}"
        f"{_render_markdown(narratives[key])}</section>"
        for key, title in sections
    )
    device = report.get("device", {})
    subtitle = " · ".join(
        str(value)
        for value in (device.get("hostname"), device.get("vendor"), device.get("model"))
        if value
    )
    inventory = report.get("inventory", {})

    def card_value(key: str) -> str:
        if key == "findings" and not report.get("checks_run", True):
            return "Not assessed"
        value = inventory.get(key)
        return str(value) if value is not None else "Not parsed"

    cards = "\n".join(
        f'<div class="card"><span>{label}</span><span class="card-value">'
        f"{escape(card_value(key))}</span></div>"
        for key, label in (
            ("interfaces", "Interfaces"),
            ("rules", "Policies"),
            ("findings", "Findings"),
        )
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Firewall Audit Report</title>
  <style>
    :root {{ color-scheme: light; font-family: system-ui, sans-serif; color: #172033; background: #f3f6fa; }}
    body {{ margin: 0; }}
    header {{ padding: 2rem max(1rem, calc((100% - 1100px) / 2)); background: #10233f; color: white; }}
    header h1 {{ margin: 0; }}
    main {{ max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 1rem; }}
    .card, section {{ background: white; border: 1px solid #dce3ed; border-radius: .6rem; padding: 1rem; }}
    .card-value {{ display: block; margin-top: .35rem; }}
    section {{ margin: 1rem 0; line-height: 1.55; overflow-wrap: anywhere; overflow-x: auto; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #dce3ed; padding: .5rem; text-align: left; vertical-align: top; }}
    h1, h2, h3, th {{ font-weight: normal; }}
    th {{ background: #f3f6fa; }}
    .copy-controls {{ display: flex; align-items: center; gap: .75rem; margin: .75rem 0; }}
    .copy-button {{ padding: .45rem .7rem; border: 1px solid #9aa8bb; border-radius: .35rem; background: #f3f6fa; color: inherit; cursor: pointer; }}
    .copy-button:disabled {{ cursor: wait; opacity: .7; }}
    .copy-status {{ color: #53647b; font-size: .9rem; }}
    .copy-buffer {{ position: fixed; left: -9999px; top: 0; }}
    footer {{ color: #53647b; margin: 2rem 0; font-size: .9rem; }}
  </style>
</head>
<body>
  <header><h1>Firewall Audit Report</h1><p>{escape(subtitle)}</p></header>
  <main>
    <div class="cards" aria-label="Assessment overview">{cards}</div>
    {controls("all", "Copy All Markdown")}
    {rendered}
    <footer>Generated by Firewall-Audit. This report works offline and loads no external resources.</footer>
  </main>
  <script id="markdown-data" type="application/json">{_safe_json(markdown_data)}</script>
  <script>
    const markdownData = JSON.parse(document.getElementById("markdown-data").textContent);
    async function copyMarkdown(text) {{
      if (navigator.clipboard?.writeText && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        return;
      }}
      const buffer = document.createElement("textarea");
      buffer.value = text;
      buffer.className = "copy-buffer";
      document.body.append(buffer);
      buffer.select();
      let copied;
      try {{
        copied = document.execCommand("copy");
      }} finally {{
        buffer.remove();
      }}
      if (!copied) throw new Error("Clipboard access is unavailable.");
    }}
    for (const button of document.querySelectorAll(".copy-button")) {{
      button.addEventListener("click", async () => {{
        const status = button.nextElementSibling;
        button.disabled = true;
        status.textContent = "Copying...";
        try {{
          await copyMarkdown(markdownData[button.dataset.copy]);
          status.textContent = "Copied Markdown to clipboard.";
        }} catch {{
          status.textContent = "Copy failed. Select and copy the text manually.";
        }} finally {{
          button.disabled = false;
        }}
      }});
    }}
  </script>
</body>
</html>
"""


def export_html(report: dict[str, Any], filepath: Path) -> Path:
    """Write a standalone HTML report to disk."""
    filepath.write_text(render_html(report), encoding="utf-8")
    return filepath

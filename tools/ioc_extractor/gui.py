"""IOC extractor window (Tkinter GUI): paste text or open a file, extract IOCs, optionally check them
against a local blocklist, and export CSV or JSON. Run with:  python -m tools.ioc_extractor.gui

Logic comes from tools.ioc_extractor.core and tools.intel_matcher.core (pure and unit-tested);
Tkinter is imported inside run() so this module is safe to import anywhere.
"""
from __future__ import annotations

import sys

from soc_common.validation import ToolError


def run() -> None:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        raise ToolError("Tkinter is not available. On macOS use the python.org installer, or run: brew install python-tk")

    from tools.intel_matcher.core import load_blocklist, match_iocs
    from tools.ioc_extractor.core import extract_iocs, to_csv, to_json, total_count
    from soc_common.ioc_patterns import defang
    from soc_common.validation import read_text_file

    state = {"iocs": {}, "blocklist": []}
    root = tk.Tk()
    root.title("IOC Extractor - paste text, extract indicators")
    root.geometry("980x640")

    bar = ttk.Frame(root, padding=6)
    bar.pack(fill="x")
    defang_var, private_var = tk.BooleanVar(value=True), tk.BooleanVar(value=False)
    status = tk.StringVar(value="Paste text below (or open a file), then click Extract.")

    text = tk.Text(root, height=12, wrap="word")
    text.pack(fill="x", padx=6)
    tree = ttk.Treeview(root, columns=("type", "value", "intel"), show="headings", height=14)
    for name, width in (("type", 90), ("value", 520), ("intel", 300)):
        tree.heading(name, text=name.title())
        tree.column(name, width=width, anchor="w")
    tree.tag_configure("hit", background="#f8d7da")
    tree.pack(fill="both", expand=True, padx=6, pady=6)

    def extract() -> None:
        try:
            state["iocs"] = extract_iocs(text.get("1.0", "end"), exclude_private=private_var.get())
        except ToolError as exc:
            messagebox.showerror("Error", str(exc))
            return
        matches = match_iocs(state["iocs"], state["blocklist"]) if state["blocklist"] else []
        best = {}                                   # strongest blocklist match per indicator
        for m in matches:
            best.setdefault(m.ioc, m)
        tree.delete(*tree.get_children())
        index = 0
        for kind, values in state["iocs"].items():
            for value in values:
                shown = defang(value, kind) if defang_var.get() else value
                hit = best.get(value)
                label = "MATCH: %s (confidence %d)" % (hit.source, hit.confidence) if hit else ""
                tree.insert("", "end", iid=str(index), values=(kind, shown, label), tags=("hit",) if hit else ())
                index += 1
        status.set("%d unique indicators%s" % (total_count(state["iocs"]),
                                               (", %d blocklist match(es)" % len(best)) if state["blocklist"] else ""))

    def open_file() -> None:
        path = filedialog.askopenfilename(title="Open a text, log or .eml file")
        if path:
            try:
                text.delete("1.0", "end")
                text.insert("end", read_text_file(path))
            except ToolError as exc:
                messagebox.showerror("Could not open", str(exc))

    def load_list() -> None:
        path = filedialog.askopenfilename(title="Open local blocklist (CSV or text)")
        if path:
            try:
                state["blocklist"] = load_blocklist(path)
            except ToolError as exc:
                messagebox.showerror("Could not load blocklist", str(exc))
                return
            status.set("Blocklist loaded: %d entries (offline matching)" % len(state["blocklist"]))

    def export(kind: str) -> None:
        if not state["iocs"]:
            messagebox.showinfo("Nothing to export", "Click Extract first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".%s" % kind)
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(to_csv(state["iocs"], defang_var.get()) if kind == "csv" else to_json(state["iocs"], defang_var.get()))
            status.set("Saved %s" % path)

    for label, command in (("Open file...", open_file), ("Extract", extract), ("Load blocklist...", load_list),
                           ("Export CSV", lambda: export("csv")), ("Export JSON", lambda: export("json"))):
        ttk.Button(bar, text=label, command=command).pack(side="left", padx=2)
    ttk.Checkbutton(bar, text="Defang output", variable=defang_var).pack(side="left", padx=8)
    ttk.Checkbutton(bar, text="Skip private IPs", variable=private_var).pack(side="left")
    ttk.Label(bar, textvariable=status).pack(side="right")
    root.mainloop()


if __name__ == "__main__":
    from soc_common.validation import cli_guard

    sys.exit(cli_guard(lambda argv=None: (run(), 0)[1])())

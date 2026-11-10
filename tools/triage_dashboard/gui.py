"""Alert triage dashboard (Tkinter GUI).

Loads alerts, ranks them with the alert prioritizer, and lets the analyst mark each one
True positive / False positive / Needs escalation, add notes, and export the decisions.

The GUI layer is intentionally thin: ranking lives in tools.alert_prioritizer and decisions in
tools.triage_dashboard.decisions, both pure and unit-tested. Tkinter is imported inside run()
so importing this module never fails on a machine without a display or without Tk.
"""
from __future__ import annotations

from typing import Optional

from soc_common.validation import ToolError


def run(alerts_path: Optional[str] = None, assets_path: Optional[str] = None) -> None:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        raise ToolError("Tkinter is not available. On macOS use the python.org installer, or run: brew install python-tk")

    from tools.alert_prioritizer.core import load_alerts, load_assets, score_alerts
    from .decisions import DECISIONS, DecisionStore, export_decisions

    store = DecisionStore()
    state = {"scored": [], "assets": {}}
    colors = {"CRITICAL": "#f8d7da", "HIGH": "#ffe5d0", "MEDIUM": "#fff3cd", "LOW": "#e2f0e9", "INFO": "#eceff1"}

    root = tk.Tk()
    root.title("SOC Alert Triage Dashboard - fake sample data only")
    root.geometry("1100x640")

    top = ttk.Frame(root, padding=6)
    top.pack(fill="x")
    status = tk.StringVar(value="Open an alerts JSON file to begin.")

    cols = ("rank", "score", "priority", "id", "title", "asset", "decision")
    tree = ttk.Treeview(root, columns=cols, show="headings", selectmode="browse", height=14)
    for name, width in zip(cols, (50, 60, 90, 80, 380, 110, 130)):
        tree.heading(name, text=name.title())
        tree.column(name, width=width, anchor="w")
    for sev, color in colors.items():
        tree.tag_configure(sev, background=color)
    tree.pack(fill="both", expand=True, padx=6)

    lower = ttk.Frame(root, padding=6)
    lower.pack(fill="both")
    detail = tk.Text(lower, height=10, wrap="word", state="disabled")
    detail.pack(side="left", fill="both", expand=True)
    right = ttk.Frame(lower, padding=(8, 0))
    right.pack(side="left", fill="y")
    ttk.Label(right, text="Analyst note").pack(anchor="w")
    note = tk.Text(right, height=5, width=42, wrap="word")
    note.pack()

    def selected_id() -> Optional[str]:
        sel = tree.selection()
        return tree.item(sel[0])["values"][3] if sel else None

    def refresh() -> None:
        keep = selected_id()
        tree.delete(*tree.get_children())
        for rank, s in enumerate(state["scored"], start=1):
            tree.insert("", "end", iid=s.alert.id, tags=(s.severity.name,),
                        values=(rank, s.score, s.severity.name, s.alert.id, s.alert.title, s.alert.asset or "-", store.get(s.alert.id)["decision"] or "-"))
        if keep and tree.exists(keep):
            tree.selection_set(keep)
        counts = store.counts()
        status.set("%d alerts | pending %d | TP %d | FP %d | escalate %d" % (
            len(state["scored"]), len(store.pending(s.alert.id for s in state["scored"])),
            counts["True positive"], counts["False positive"], counts["Needs escalation"]))

    def show_detail(_event=None) -> None:
        alert_id = selected_id()
        match = next((s for s in state["scored"] if s.alert.id == alert_id), None)
        detail.config(state="normal")
        detail.delete("1.0", "end")
        if match:
            a = match.alert
            detail.insert("end", "%s  (score %d, %s)\n%s\n\nAsset: %s | User: %s | Source IP: %s\nTags: %s\n\nWhy this score:\n" % (
                a.title, match.score, match.severity.name, a.description, a.asset or "-", a.user or "-", a.src_ip or "-", ", ".join(a.tags) or "-"))
            detail.insert("end", "\n".join("  " + r for r in match.reasons))
            note.delete("1.0", "end")
            note.insert("end", store.get(alert_id)["note"])
        detail.config(state="disabled")

    def decide(decision: str) -> None:
        alert_id = selected_id()
        if not alert_id:
            messagebox.showinfo("Select an alert", "Click an alert in the list first.")
            return
        store.set(alert_id, decision, note.get("1.0", "end"))
        refresh()

    def save_note() -> None:
        alert_id = selected_id()
        if alert_id:
            store.set_note(alert_id, note.get("1.0", "end"))
            status.set("Note saved for %s" % alert_id)

    def load(path_alerts: str, path_assets: Optional[str]) -> None:
        try:
            alerts = load_alerts(path_alerts)
            state["assets"] = load_assets(path_assets) if path_assets else state["assets"]
        except ToolError as exc:
            messagebox.showerror("Could not load", str(exc))
            return
        state["scored"] = score_alerts(alerts, state["assets"])
        refresh()

    def open_alerts() -> None:
        path = filedialog.askopenfilename(title="Open alerts JSON", filetypes=[("JSON", "*.json")])
        if path:
            load(path, None)

    def open_assets() -> None:
        path = filedialog.askopenfilename(title="Open assets JSON", filetypes=[("JSON", "*.json")])
        if path:
            try:
                state["assets"] = load_assets(path)
            except ToolError as exc:
                messagebox.showerror("Could not load", str(exc))
                return
            alerts = [s.alert for s in state["scored"]]
            state["scored"] = score_alerts(alerts, state["assets"])
            refresh()

    def export() -> None:
        if not state["scored"]:
            messagebox.showinfo("Nothing to export", "Load alerts first.")
            return
        path = filedialog.asksaveasfilename(title="Export decisions", defaultextension=".json", filetypes=[("JSON", "*.json"), ("CSV", "*.csv")])
        if path:
            count = export_decisions(path, state["scored"], store)
            status.set("Exported %d rows to %s" % (count, path))

    for text, command in (("Open alerts...", open_alerts), ("Open assets...", open_assets), ("Export decisions...", export)):
        ttk.Button(top, text=text, command=command).pack(side="left", padx=2)
    ttk.Label(top, textvariable=status).pack(side="right")
    for text in DECISIONS:
        ttk.Button(right, text=text, command=lambda d=text: decide(d)).pack(fill="x", pady=2)
    ttk.Button(right, text="Save note only", command=save_note).pack(fill="x", pady=2)
    tree.bind("<<TreeviewSelect>>", show_detail)

    if alerts_path:
        load(alerts_path, assets_path)
    root.mainloop()

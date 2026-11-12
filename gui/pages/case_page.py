"""Case Manager: searchable case table, detail tabs, right-click menus, evidence management."""
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from gui import ACCENT, BG, CARD, DANGER, MUTED, OK, TEXT, Page, button, entry, label, make_tree, output_box, set_text
from modules import case_mgmt, common

COLS = ("ID", "Title", "Status", "Priority", "Evidence", "Created", "Analyst")


def _menu(parent):
    return tk.Menu(parent, tearoff=0, bg=CARD, fg=TEXT, activebackground=ACCENT, activeforeground="white", bd=0)


class CasePage(Page):
    title = "Case Manager"

    def __init__(self, master, app):
        super().__init__(master, app)
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(fill="x", padx=24, pady=(0, 8))
        for text, cmd, sec in (("New Case", self._new, False), ("Add Evidence", self._evidence, False),
                               ("View Chain of Custody", self._custody, False), ("Add Note", self._note, True),
                               ("Export Report", self._report, True)):
            button(bar, text, cmd, 170 if "Chain" in text else 120, sec).pack(side="left", padx=(0, 8))
        self.filter_var = ctk.StringVar(value="All")
        ctk.CTkOptionMenu(bar, values=["All"] + case_mgmt.STATUSES, variable=self.filter_var, width=120,
                          command=lambda _: self.refresh(), fg_color=CARD, button_color=ACCENT).pack(side="right")
        self.search = entry(bar, "Search cases...", 220)
        self.search.pack(side="right", padx=8)
        self.search.bind("<KeyRelease>", lambda e: self.refresh())

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=(0, 8))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=3)
        body.grid_rowconfigure(1, weight=2)
        frame, self.tree = make_tree(body, COLS, (90, 300, 100, 90, 70, 160, 100))
        frame.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._load_details())
        self.tree.bind("<Button-3>", self._ctx_case)
        self.tree.bind("<Delete>", lambda e: self._delete())
        self.tree.bind("<Double-1>", lambda e: self._custody())

        self.tabs = ctk.CTkTabview(body, fg_color=CARD, segmented_button_selected_color=ACCENT, height=200)
        self.tabs.grid(row=1, column=0, sticky="nsew")
        for t in ("Overview", "Evidence", "Notes", "Timeline"):
            self.tabs.add(t)
        self.overview, self.notes, self.timeline = (output_box(self.tabs.tab(n)) for n in ("Overview", "Notes", "Timeline"))
        for w in (self.overview, self.notes, self.timeline):
            w.pack(fill="both", expand=True)
        ef, self.ev_tree = make_tree(self.tabs.tab("Evidence"), ("Name", "Size", "SHA-256", "Added (UTC)"), (220, 90, 420, 160))
        ef.pack(fill="both", expand=True)
        self.ev_tree.bind("<Button-3>", self._ctx_ev)

        self.status = label(self, "Right-click a case or an evidence file for more options.", 11, MUTED)
        self.status.pack(anchor="w", padx=26, pady=(0, 10))
        self._build_menus()
        self.refresh()

    # ---- menus
    def _build_menus(self):
        m = self.case_menu = _menu(self)
        for text, cmd in (("Add Evidence...", self._evidence), ("View Chain of Custody", self._custody),
                          ("Add Note...", self._note), ("Export Report", self._report)):
            m.add_command(label=text, command=cmd)
        m.add_separator()
        m.add_command(label="Rename...", command=self._rename)
        for name, items, fn in (("Set Status", case_mgmt.STATUSES, case_mgmt.set_status),
                                ("Set Priority", case_mgmt.PRIORITIES, case_mgmt.set_priority)):
            sub = _menu(m)
            for it in items:
                sub.add_command(label=it, command=lambda i=it, f=fn: self._apply(f, i))
            m.add_cascade(label=name, menu=sub)
        m.add_command(label="Open Case Folder", command=lambda: self._open(case_mgmt.case_dir(self._sel())))
        m.add_separator()
        m.add_command(label="Delete Case...", command=self._delete)
        e = self.ev_menu = _menu(self)
        e.add_command(label="Verify Integrity", command=self._verify)
        e.add_command(label="Copy SHA-256", command=self._copy_hash)
        e.add_command(label="Open Evidence Folder", command=lambda: self._open(case_mgmt.case_dir(self._sel()) / "evidence"))
        e.add_separator()
        e.add_command(label="Remove Evidence...", command=self._remove_ev)

    def _ctx_case(self, ev):
        row = self.tree.identify_row(ev.y)
        if row:
            self.tree.selection_set(row)
            self.case_menu.tk_popup(ev.x_root, ev.y_root)

    def _ctx_ev(self, ev):
        row = self.ev_tree.identify_row(ev.y)
        if row and self._sel(quiet=True):
            self.ev_tree.selection_set(row)
            self.ev_menu.tk_popup(ev.x_root, ev.y_root)

    # ---- data
    def on_show(self):
        self.refresh()

    def refresh(self):
        keep = self._sel(quiet=True)
        q, st = self.search.get().lower().strip(), self.filter_var.get()
        self.tree.delete(*self.tree.get_children())
        for c in case_mgmt.list_cases():
            if (st == "All" or c["status"] == st) and q in f"{c['id']} {c['title']} {c['analyst']}".lower():
                self.tree.insert("", "end", iid=c["id"], values=(c["id"], c["title"], c["status"], c["priority"],
                                                                 c["evidence"], c["created"].replace("T", " ")[:16], c["analyst"]))
        if keep and self.tree.exists(keep):
            self.tree.selection_set(keep)
        self._load_details()

    def _load_details(self):
        cid = self._sel(quiet=True)
        self.ev_tree.delete(*self.ev_tree.get_children())
        if not cid:
            for w in (self.overview, self.notes, self.timeline):
                set_text(w, "")
            return
        m = next(c for c in case_mgmt.list_cases() if c["id"] == cid)
        ok, msg = case_mgmt.verify_custody(cid)
        set_text(self.overview, f"{m['id']}  -  {m['title']}\nStatus: {m['status']}   Priority: {m['priority']}   "
                                f"Evidence files: {m['evidence']}\nCreated: {m['created']}   Analyst: {m['analyst']}\n"
                                f"Custody chain: {msg}\n\nDescription:\n{case_mgmt.read_description(cid) or '(none)'}")
        set_text(self.notes, case_mgmt.read_notes(cid) or "(no notes)")
        set_text(self.timeline, "\n".join(f"{t['time']}  {t['event']}" for t in case_mgmt.read_timeline(cid)))
        for e in case_mgmt.list_evidence(cid):
            self.ev_tree.insert("", "end", values=(e["name"], common.human_size(e["size"]), e["sha256"], e["added"]))

    def _sel(self, quiet=False):
        s = self.tree.selection()
        if not s:
            if not quiet:
                messagebox.showinfo("Case Manager", "Select a case first.")
            return None
        return s[0]

    def _msg(self, text, ok=True):
        self.status.configure(text=text, text_color=OK if ok else DANGER)

    def _ask(self, title, prompt):
        return (ctk.CTkInputDialog(title=title, text=prompt).get_input() or "").strip()

    def _apply(self, fn, value):
        cid = self._sel()
        if cid:
            fn(cid, value)
            self.refresh()
            self._msg(f"{cid} updated: {value}")

    # ---- actions
    def _new(self):
        title = self._ask("New Case", "Case title:")
        if title:
            m = case_mgmt.create_case(title, self._ask("New Case", "Description (optional):"))
            self.refresh()
            self.tree.selection_set(m["id"])
            self._msg(f"Created {m['id']}")

    def _rename(self):
        cid = self._sel()
        title = self._ask("Rename Case", "New title:") if cid else ""
        if title:
            case_mgmt.rename_case(cid, title)
            self.refresh()

    def _evidence(self):
        cid = self._sel()
        paths = filedialog.askopenfilenames(title="Select evidence files") if cid else ()
        if not paths:
            return
        self._msg("Copying and hashing evidence...")
        common.run_async(self, lambda emit: [case_mgmt.add_evidence(cid, p, "added via GUI") for p in paths], None,
                         lambda res, err: (self.refresh(), self._msg(f"{len(res)} file(s) added to {cid}" if not err else f"Error: {err}", not err)))

    def _custody(self):
        cid = self._sel()
        if not cid:
            return
        ok, msg = case_mgmt.verify_custody(cid)
        win = ctk.CTkToplevel(self)
        win.title(f"Chain of Custody - {cid}")
        win.geometry("900x520")
        win.configure(fg_color=BG)
        label(win, msg, 14, OK if ok else DANGER, "bold").pack(anchor="w", padx=16, pady=10)
        box = output_box(win)
        box.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        set_text(box, "\n\n".join(f"#{e['seq']}  {e['time']}  {e['actor']}  {e['action']}\n   {e['details']}\n   hash: {e['hash']}"
                                  for e in case_mgmt.read_custody(cid)))
        win.after(200, win.lift)

    def _note(self):
        cid = self._sel()
        text = self._ask("Add Note", "Note text:") if cid else ""
        if text:
            case_mgmt.add_note(cid, text)
            self._load_details()

    def _report(self):
        cid = self._sel()
        if cid:
            self._msg(f"Report saved: {case_mgmt.export_report(cid)}")
            self._load_details()

    def _delete(self):
        cid = self._sel()
        if cid and messagebox.askyesno("Delete case", f"Permanently delete {cid} with ALL evidence, notes and custody log?\nThis cannot be undone.",
                                       icon="warning"):
            case_mgmt.delete_case(cid)
            self.refresh()
            self._msg(f"{cid} deleted", False)

    def _open(self, path):
        subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # shell=False

    def _ev_name(self):
        s = self.ev_tree.selection()
        return self.ev_tree.item(s[0], "values") if s else None

    def _verify(self):
        v, cid = self._ev_name(), self._sel(quiet=True)
        if v and cid:
            ok, msg = case_mgmt.verify_evidence(cid, v[0])
            (messagebox.showinfo if ok else messagebox.showerror)("Evidence integrity", f"{v[0]}\n\n{msg}")

    def _copy_hash(self):
        v = self._ev_name()
        if v:
            self.clipboard_clear()
            self.clipboard_append(v[2])
            self._msg("SHA-256 copied to clipboard")

    def _remove_ev(self):
        v, cid = self._ev_name(), self._sel(quiet=True)
        if v and cid and messagebox.askyesno("Remove evidence", f"Remove '{v[0]}' from {cid}?\nThe removal and its hash stay in the custody log.", icon="warning"):
            case_mgmt.remove_evidence(cid, v[0])
            self.refresh()

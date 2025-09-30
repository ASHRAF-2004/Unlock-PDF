#!/usr/bin/env python3
"""Simple Tkinter GUI for the pdf_password_retriever CLI."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk


def default_binary_path(executable: str = "pdf_password_retriever") -> str:
    """Return the default location of the requested executable."""

    exe_name = f"{executable}.exe" if os.name == "nt" else executable
    search_roots: list[Path] = []

    if getattr(sys, "frozen", False):
        search_roots.append(Path(sys.executable).resolve().parent)
    else:
        search_roots.append(Path(__file__).resolve().parent.parent)

    candidates: list[Path] = []
    for root in search_roots:
        candidates.extend(
            [
                root / exe_name,
                root / "build" / exe_name,
            ]
        )
        if os.name == "nt":
            candidates.extend(
                [
                    root / "build" / "Release" / exe_name,
                    root / "build" / "Debug" / exe_name,
                ]
            )

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    return str(candidates[0]) if candidates else exe_name


class UnlockPDFGui:
    def __init__(self, master: tk.Tk) -> None:
        self.master = master
        master.title("PDF Password Retriever")
        master.geometry("760x620")

        self._runner: threading.Thread | None = None
        self._stop_event = threading.Event()

        self.binary_var = tk.StringVar(value=default_binary_path())
        self.pdf_var = tk.StringVar()
        self.wordlist_var = tk.StringVar()
        self.min_length_var = tk.StringVar(value="6")
        self.max_length_var = tk.StringVar(value="32")
        self.thread_var = tk.StringVar()
        self.custom_chars_var = tk.StringVar()
        self.include_upper = tk.BooleanVar(value=True)
        self.include_lower = tk.BooleanVar(value=True)
        self.include_digits = tk.BooleanVar(value=True)
        self.include_special = tk.BooleanVar(value=True)
        self.use_custom_only = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Idle")

        self._char_checkbuttons: list[tk.Checkbutton] = []

        self.probe_binary_var = tk.StringVar(value=default_binary_path("device_probe"))
        self.probe_lengths_var = tk.StringVar(value="6,8,10")
        self.probe_attempts_var = tk.StringVar(value="500000")
        self.probe_hash_var = tk.StringVar(value="none")
        self.probe_custom_var = tk.StringVar()
        self.probe_include_special = tk.BooleanVar(value=False)

        self._build_widgets()

    def _build_widgets(self) -> None:
        main_frame = tk.Frame(self.master, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.X, expand=False)

        cracker_frame = tk.Frame(notebook, padx=10, pady=10)
        notebook.add(cracker_frame, text="Cracker")

        probe_frame = tk.Frame(notebook, padx=10, pady=10)
        notebook.add(probe_frame, text="Device Probe")

        for frame in (cracker_frame, probe_frame):
            frame.columnconfigure(1, weight=1)

        def add_labeled_entry(parent: tk.Misc, row: int, label: str, textvariable: tk.StringVar,
                              browse: bool = False, command=None, width: int = 50) -> tk.Entry:
            tk.Label(parent, text=label).grid(row=row, column=0, sticky=tk.W, pady=3)
            entry = tk.Entry(parent, textvariable=textvariable, width=width)
            entry.grid(row=row, column=1, sticky=tk.W, pady=3)
            if browse:
                tk.Button(parent, text="Browse", command=command).grid(row=row, column=2, padx=5)
            return entry

        add_labeled_entry(cracker_frame, 0, "Binary:", self.binary_var, browse=True, command=self._choose_binary)
        add_labeled_entry(cracker_frame, 1, "PDF File:", self.pdf_var, browse=True, command=self._choose_pdf)
        add_labeled_entry(cracker_frame, 2, "Wordlist:", self.wordlist_var, browse=True, command=self._choose_wordlist)

        add_labeled_entry(cracker_frame, 3, "Min Length:", self.min_length_var)
        add_labeled_entry(cracker_frame, 4, "Max Length:", self.max_length_var)
        add_labeled_entry(cracker_frame, 5, "Threads:", self.thread_var)
        add_labeled_entry(cracker_frame, 6, "Custom Characters:", self.custom_chars_var, width=60)

        char_frame = tk.LabelFrame(cracker_frame, text="Character Classes", padx=10, pady=5)
        char_frame.grid(row=7, column=0, columnspan=3, sticky=tk.EW, pady=5)

        for column, (text, var) in enumerate((
            ("Uppercase", self.include_upper),
            ("Lowercase", self.include_lower),
            ("Digits", self.include_digits),
            ("Special", self.include_special),
        )):
            check = tk.Checkbutton(char_frame, text=text, variable=var,
                                   command=self._refresh_character_state)
            check.grid(row=0, column=column, sticky=tk.W)
            self._char_checkbuttons.append(check)

        tk.Checkbutton(char_frame, text="Use Custom Only", variable=self.use_custom_only,
                       command=self._refresh_character_state).grid(row=1, column=0, sticky=tk.W, pady=(5, 0))

        add_labeled_entry(probe_frame, 0, "Probe Binary:", self.probe_binary_var, browse=True,
                          command=self._choose_probe_binary)
        add_labeled_entry(probe_frame, 1, "Lengths (comma separated):", self.probe_lengths_var)
        add_labeled_entry(probe_frame, 2, "Attempts per length:", self.probe_attempts_var)

        tk.Label(probe_frame, text="Hash mode:").grid(row=3, column=0, sticky=tk.W, pady=3)
        hash_selector = ttk.Combobox(probe_frame, textvariable=self.probe_hash_var, width=47,
                                     values=("none", "sha256"), state="readonly")
        hash_selector.grid(row=3, column=1, sticky=tk.W, pady=3)
        hash_selector.set(self.probe_hash_var.get())

        add_labeled_entry(probe_frame, 4, "Custom characters:", self.probe_custom_var)
        tk.Checkbutton(probe_frame, text="Include special characters", variable=self.probe_include_special).grid(
            row=5, column=1, sticky=tk.W, pady=3
        )

        button_frame = tk.Frame(main_frame, pady=10)
        button_frame.pack(fill=tk.X)

        self.info_button = tk.Button(button_frame, text="Get PDF Info", command=self._run_info)
        self.info_button.pack(side=tk.LEFT)

        self.run_button = tk.Button(button_frame, text="Run Crack", command=self._run_cracker)
        self.run_button.pack(side=tk.LEFT, padx=10)

        self.device_probe_button = tk.Button(button_frame, text="Run Device Probe", command=self._run_device_probe)
        self.device_probe_button.pack(side=tk.LEFT)

        self.stop_button = tk.Button(button_frame, text="Stop", state=tk.DISABLED, command=self._stop_process)
        self.stop_button.pack(side=tk.LEFT, padx=10)

        tk.Button(button_frame, text="Clear Output", command=self._clear_output).pack(side=tk.RIGHT)

        self.output = scrolledtext.ScrolledText(main_frame, height=20, wrap=tk.WORD)
        self.output.pack(fill=tk.BOTH, expand=True)

        status_frame = tk.Frame(self.master, padx=10, pady=5)
        status_frame.pack(fill=tk.X)
        tk.Label(status_frame, textvariable=self.status_var, anchor=tk.W).pack(fill=tk.X)

    def _choose_binary(self) -> None:
        path = filedialog.askopenfilename(title="Select pdf_password_retriever executable")
        if path:
            self.binary_var.set(path)

    def _choose_probe_binary(self) -> None:
        path = filedialog.askopenfilename(title="Select device_probe executable")
        if path:
            self.probe_binary_var.set(path)

    def _choose_pdf(self) -> None:
        path = filedialog.askopenfilename(title="Select encrypted PDF", filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")])
        if path:
            self.pdf_var.set(path)

    def _choose_wordlist(self) -> None:
        path = filedialog.askopenfilename(title="Select wordlist", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self.wordlist_var.set(path)

    def _refresh_character_state(self) -> None:
        is_custom_only = self.use_custom_only.get()
        for var in (self.include_upper, self.include_lower, self.include_digits, self.include_special):
            if is_custom_only:
                var.set(False)
        state = tk.DISABLED if is_custom_only else tk.NORMAL
        for widget in self._char_checkbuttons:
            widget.configure(state=state)

    def _clear_output(self) -> None:
        self.output.delete("1.0", tk.END)

    def _append_output(self, text: str) -> None:
        def append() -> None:
            self.output.insert(tk.END, text)
            self.output.see(tk.END)
        self.master.after(0, append)

    def _validate_binary(self) -> str | None:
        binary = self.binary_var.get().strip() or default_binary_path()
        binary_path = Path(binary)
        if not binary_path.exists():
            messagebox.showerror("Executable not found", f"Could not find pdf_password_retriever at:\n{binary}")
            return None
        return str(binary_path)

    def _validate_probe_binary(self) -> str | None:
        binary = self.probe_binary_var.get().strip() or default_binary_path("device_probe")
        binary_path = Path(binary)
        if not binary_path.exists():
            messagebox.showerror("Executable not found", f"Could not find device_probe at:\n{binary}")
            return None
        return str(binary_path)

    def _collect_common_args(self) -> list[str] | None:
        binary = self._validate_binary()
        if not binary:
            return None

        pdf = self.pdf_var.get().strip()
        if not pdf:
            messagebox.showerror("Missing PDF", "Please select an encrypted PDF file to process.")
            return None
        if not Path(pdf).exists():
            messagebox.showerror("PDF not found", f"The selected PDF could not be found:\n{pdf}")
            return None

        args = [binary]
        wordlist = self.wordlist_var.get().strip()
        if wordlist:
            if not Path(wordlist).exists():
                messagebox.showerror("Missing wordlist", f"The selected wordlist could not be found:\n{wordlist}")
                return None
            args.extend(["--wordlist", wordlist])

        min_length = self.min_length_var.get().strip()
        max_length = self.max_length_var.get().strip()
        threads = self.thread_var.get().strip()
        custom_chars = self.custom_chars_var.get().strip()

        if min_length:
            args.extend(["--min-length", min_length])
        if max_length:
            args.extend(["--max-length", max_length])
        if threads:
            args.extend(["--threads", threads])

        if custom_chars:
            args.extend(["--custom-chars", custom_chars])
            if self.use_custom_only.get():
                args.append("--use-custom-only")

        if not self.use_custom_only.get():
            selections = {
                "uppercase": self.include_upper.get(),
                "lowercase": self.include_lower.get(),
                "digits": self.include_digits.get(),
                "special": self.include_special.get(),
            }

            if not any(selections.values()):
                messagebox.showerror(
                    "No character sets",
                    "Please enable at least one character class or choose 'Use Custom Only'.",
                )
                return None

            if selections["uppercase"]:
                args.append("--include-uppercase")
            else:
                args.append("--exclude-uppercase")

            if selections["lowercase"]:
                args.append("--include-lowercase")
            else:
                args.append("--exclude-lowercase")

            if selections["digits"]:
                args.append("--include-digits")
            else:
                args.append("--exclude-digits")

            if selections["special"]:
                args.append("--include-special")
            else:
                args.append("--exclude-special")

        return args

    def _run_info(self) -> None:
        args = self._collect_common_args()
        if args is None:
            return
        pdf = self.pdf_var.get().strip()
        command = args[:1] + ["--info", pdf]
        self._execute(command, f"Fetching PDF info for: {pdf}\n")

    def _run_cracker(self) -> None:
        args = self._collect_common_args()
        if args is None:
            return
        pdf = self.pdf_var.get().strip()
        command = args[:1] + ["--pdf", pdf] + args[1:]
        self._execute(command, f"Starting crack for: {pdf}\n")

    def _collect_probe_args(self) -> list[str] | None:
        binary = self._validate_probe_binary()
        if not binary:
            return None

        args = [binary]

        lengths = self.probe_lengths_var.get().strip()
        if lengths:
            args.extend(["--lengths", lengths])

        attempts = self.probe_attempts_var.get().strip()
        if attempts:
            args.extend(["--attempts", attempts])

        hash_mode = self.probe_hash_var.get().strip()
        if hash_mode:
            args.extend(["--hash", hash_mode])

        if self.probe_include_special.get():
            args.append("--include-special")

        custom_chars = self.probe_custom_var.get().strip()
        if custom_chars:
            args.extend(["--custom", custom_chars])

        return args

    def _run_device_probe(self) -> None:
        args = self._collect_probe_args()
        if args is None:
            return
        self._execute(args, "Running device_probe benchmark\n")

    def _execute(self, command: list[str], header: str) -> None:
        if self._runner and self._runner.is_alive():
            messagebox.showinfo("Process running", "Another operation is already in progress.")
            return

        self._clear_output()
        self._append_output(header)
        self._append_output("Command: " + " ".join(shlex.quote(arg) for arg in command) + "\n\n")

        self._stop_event.clear()
        self._toggle_buttons(running=True)
        self._set_status("Running...")

        def worker() -> None:
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
            except FileNotFoundError:
                self._append_output("Failed to launch pdf_password_retriever.\n")
                self._set_status("Executable not found")
                self._toggle_buttons(running=False)
                return

            with process.stdout:
                for line in iter(process.stdout.readline, ""):
                    if self._stop_event.is_set():
                        process.terminate()
                        self._append_output("Process terminated by user.\n")
                        self._set_status("Stopped by user")
                        break
                    self._append_output(line)
            return_code = process.wait()
            if return_code is not None and return_code != 0 and not self._stop_event.is_set():
                self._append_output(f"\nProcess exited with code {return_code}.\n")
                self._set_status(f"Process exited with code {return_code}")
            elif not self._stop_event.is_set():
                self._set_status("Completed")
            self._toggle_buttons(running=False)

        self._runner = threading.Thread(target=worker, daemon=True)
        self._runner.start()

    def _stop_process(self) -> None:
        if self._runner and self._runner.is_alive():
            self._stop_event.set()
            self._set_status("Stopping...")

    def _toggle_buttons(self, running: bool) -> None:
        state_run = tk.DISABLED if running else tk.NORMAL
        state_stop = tk.NORMAL if running else tk.DISABLED
        def update() -> None:
            self.run_button.configure(state=state_run)
            self.info_button.configure(state=state_run)
            self.device_probe_button.configure(state=state_run)
            self.stop_button.configure(state=state_stop)
            if not running and self.status_var.get() in {"Running...", "Stopping..."}:
                self.status_var.set("Idle")
        self.master.after(0, update)

    def _set_status(self, message: str) -> None:
        def update() -> None:
            self.status_var.set(message)
        self.master.after(0, update)


def main() -> None:
    root = tk.Tk()
    app = UnlockPDFGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()

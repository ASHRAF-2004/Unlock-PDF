#!/usr/bin/env python3
"""Tkinter based GUI for running the ``pdf_password_retriever`` helpers.

The original implementation bundled all widget creation in a single block and
relied on the default Tk widgets.  This version reorganises the layout into
clearly labelled sections, introduces themed widgets via :mod:`tkinter.ttk`, and
adds quality-of-life features such as progress feedback, clearer status
messaging, and helper text for the user.  The functional behaviour remains the
same while providing a more welcoming interface and easier to follow code.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk


def default_binary_path() -> str:
    """Return the default location of the pdf_password_retriever binary."""

    exe_name = "pdf_password_retriever.exe" if os.name == "nt" else "pdf_password_retriever"
    project_root = Path(__file__).resolve().parent.parent
    default_path = project_root / "build" / exe_name
    return str(default_path)


def default_device_probe_path() -> str:
    """Return the default location of the device_probe helper executable."""

    exe_name = "device_probe.exe" if os.name == "nt" else "device_probe"
    project_root = Path(__file__).resolve().parent.parent
    default_path = project_root / "build" / exe_name
    return str(default_path)


class UnlockPDFGui:
    """Create and manage the password retriever interface."""

    def __init__(self, master: tk.Tk) -> None:
        self.master = master
        master.title("PDF Password Retriever")
        master.minsize(820, 680)

        self._runner: threading.Thread | None = None
        self._stop_event = threading.Event()

        self.binary_var = tk.StringVar(value=default_binary_path())
        self.device_probe_var = tk.StringVar(value=default_device_probe_path())
        self.device_probe_args_var = tk.StringVar()
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

        self._char_checkbuttons: list[ttk.Checkbutton] = []

        self._configure_style()
        self._build_widgets()
        self.master.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_style(self) -> None:
        """Apply a modern ttk theme and tweak a few defaults."""

        style = ttk.Style()
        preferred_theme = "clam"
        if preferred_theme in style.theme_names():
            style.theme_use(preferred_theme)

        style.configure("Section.TLabelframe", padding=12)
        style.configure("Section.TLabelframe.Label", font=("TkDefaultFont", 11, "bold"))
        style.configure("Status.TLabel", font=("TkDefaultFont", 10, "bold"))
        style.configure("Intro.TLabel", wraplength=720, justify=tk.LEFT)

        self.master.option_add("*TEntry*Padding", 4)
        self.master.option_add("*TButton*Padding", 6)

    # ------------------------------------------------------------------
    # Widget construction
    # ------------------------------------------------------------------
    def _build_widgets(self) -> None:
        main_frame = ttk.Frame(self.master, padding=15)
        main_frame.grid(row=0, column=0, sticky=tk.NSEW)

        self.master.columnconfigure(0, weight=1)
        self.master.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        intro = ttk.Label(
            main_frame,
            text=(
                "Configure the executables, select the encrypted PDF, and tune the"
                " password search strategy.  Use the buttons below to probe the"
                " device, inspect the PDF metadata, or begin cracking."
            ),
            style="Intro.TLabel",
        )
        intro.grid(row=0, column=0, sticky=tk.W, pady=(0, 12))

        executables_frame = ttk.LabelFrame(main_frame, text="Executables", style="Section.TLabelframe")
        executables_frame.grid(row=1, column=0, sticky=tk.EW, pady=(0, 12))
        executables_frame.columnconfigure(1, weight=1)

        self._add_path_row(
            executables_frame,
            row=0,
            label="PDF Retriever Binary",
            variable=self.binary_var,
            command=self._choose_binary,
        )
        self._add_path_row(
            executables_frame,
            row=1,
            label="Device Probe",
            variable=self.device_probe_var,
            command=self._choose_device_probe,
        )
        self._add_entry_row(
            executables_frame,
            row=2,
            label="Probe Options",
            variable=self.device_probe_args_var,
        )

        pdf_frame = ttk.LabelFrame(main_frame, text="PDF & Wordlist", style="Section.TLabelframe")
        pdf_frame.grid(row=2, column=0, sticky=tk.EW, pady=(0, 12))
        pdf_frame.columnconfigure(1, weight=1)

        self._add_path_row(pdf_frame, 0, "Encrypted PDF", self.pdf_var, self._choose_pdf)
        self._add_path_row(pdf_frame, 1, "Wordlist", self.wordlist_var, self._choose_wordlist)

        strategy_frame = ttk.LabelFrame(main_frame, text="Password Strategy", style="Section.TLabelframe")
        strategy_frame.grid(row=3, column=0, sticky=tk.EW, pady=(0, 12))
        for column in range(2):
            strategy_frame.columnconfigure(column * 2 + 1, weight=1)

        self._add_entry_row(strategy_frame, 0, "Min Length", self.min_length_var, column=0)
        self._add_entry_row(strategy_frame, 0, "Max Length", self.max_length_var, column=1)
        self._add_entry_row(strategy_frame, 1, "Threads", self.thread_var, column=0)
        self._add_entry_row(strategy_frame, 1, "Custom Characters", self.custom_chars_var, column=1)

        char_frame = ttk.LabelFrame(strategy_frame, text="Character Classes", style="Section.TLabelframe")
        char_frame.grid(row=2, column=0, columnspan=4, sticky=tk.EW, pady=(12, 0))
        for column in range(4):
            char_frame.columnconfigure(column, weight=1)

        for column, (text, var) in enumerate((
            ("Uppercase", self.include_upper),
            ("Lowercase", self.include_lower),
            ("Digits", self.include_digits),
            ("Special", self.include_special),
        )):
            check = ttk.Checkbutton(
                char_frame,
                text=text,
                variable=var,
                command=self._refresh_character_state,
            )
            check.grid(row=0, column=column, sticky=tk.W, padx=6)
            self._char_checkbuttons.append(check)

        ttk.Checkbutton(
            char_frame,
            text="Use Custom Characters Only",
            variable=self.use_custom_only,
            command=self._refresh_character_state,
        ).grid(row=1, column=0, columnspan=4, sticky=tk.W, padx=6, pady=(8, 0))

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, sticky=tk.EW, pady=(0, 12))
        button_frame.columnconfigure(4, weight=1)

        self.probe_button = ttk.Button(button_frame, text="Run Device Probe", command=self._run_device_probe)
        self.probe_button.grid(row=0, column=0, padx=(0, 8))

        self.info_button = ttk.Button(button_frame, text="Get PDF Info", command=self._run_info)
        self.info_button.grid(row=0, column=1, padx=(0, 8))

        self.run_button = ttk.Button(button_frame, text="Run Crack", command=self._run_cracker)
        self.run_button.grid(row=0, column=2, padx=(0, 8))

        self.stop_button = ttk.Button(
            button_frame,
            text="Stop",
            state=tk.DISABLED,
            command=self._stop_process,
        )
        self.stop_button.grid(row=0, column=3, padx=(0, 8))

        ttk.Button(button_frame, text="Clear Output", command=self._clear_output).grid(
            row=0,
            column=4,
            sticky=tk.E,
        )

        output_frame = ttk.LabelFrame(main_frame, text="Command Output", style="Section.TLabelframe")
        output_frame.grid(row=5, column=0, sticky=tk.NSEW)
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)

        self.output = scrolledtext.ScrolledText(output_frame, height=16, wrap=tk.WORD)
        self.output.grid(row=0, column=0, sticky=tk.NSEW)

        main_frame.rowconfigure(5, weight=1)

        status_frame = ttk.Frame(self.master, padding=(15, 8, 15, 15))
        status_frame.grid(row=1, column=0, sticky=tk.EW)
        status_frame.columnconfigure(1, weight=1)

        ttk.Label(status_frame, text="Status:", style="Status.TLabel").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(status_frame, textvariable=self.status_var).grid(row=0, column=1, sticky=tk.W, padx=(6, 0))

        self.progress = ttk.Progressbar(status_frame, mode="indeterminate", maximum=80)
        self.progress.grid(row=0, column=2, sticky=tk.E, ipadx=50)

    def _add_entry_row(
        self,
        parent: ttk.Widget,
        row: int,
        label: str,
        variable: tk.StringVar,
        *,
        column: int = 0,
    ) -> ttk.Entry:
        """Add a labelled entry to ``parent`` and return the widget."""

        ttk.Label(parent, text=label).grid(row=row, column=column * 2, sticky=tk.W, padx=(0, 8), pady=4)
        entry = ttk.Entry(parent, textvariable=variable, width=32)
        entry.grid(row=row, column=column * 2 + 1, sticky=tk.EW, pady=4)
        return entry

    def _add_path_row(
        self,
        parent: ttk.Widget,
        row: int,
        label: str,
        variable: tk.StringVar,
        command,
    ) -> None:
        """Create a labelled entry with a browse button for file selection."""

        ttk.Label(parent, text=label).grid(row=row, column=0, sticky=tk.W, padx=(0, 8), pady=4)
        entry = ttk.Entry(parent, textvariable=variable, width=60)
        entry.grid(row=row, column=1, sticky=tk.EW, pady=4)
        ttk.Button(parent, text="Browse", command=command).grid(row=row, column=2, padx=(8, 0), pady=4)

    # ------------------------------------------------------------------
    # GUI helpers
    # ------------------------------------------------------------------
    def _choose_binary(self) -> None:
        path = filedialog.askopenfilename(title="Select pdf_password_retriever executable")
        if path:
            self.binary_var.set(path)

    def _choose_device_probe(self) -> None:
        path = filedialog.askopenfilename(title="Select device_probe executable")
        if path:
            self.device_probe_var.set(path)

    def _choose_pdf(self) -> None:
        path = filedialog.askopenfilename(
            title="Select encrypted PDF",
            filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")],
        )
        if path:
            self.pdf_var.set(path)

    def _choose_wordlist(self) -> None:
        path = filedialog.askopenfilename(
            title="Select wordlist",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        )
        if path:
            self.wordlist_var.set(path)

    def _refresh_character_state(self) -> None:
        is_custom_only = self.use_custom_only.get()
        if is_custom_only:
            for var in (self.include_upper, self.include_lower, self.include_digits, self.include_special):
                var.set(False)
        for widget in self._char_checkbuttons:
            if is_custom_only:
                widget.state(["disabled"])
            else:
                widget.state(["!disabled"])

    def _clear_output(self) -> None:
        self.output.delete("1.0", tk.END)

    def _append_output(self, text: str) -> None:
        def append() -> None:
            self.output.insert(tk.END, text)
            self.output.see(tk.END)

        self.master.after(0, append)

    # ------------------------------------------------------------------
    # Command handling
    # ------------------------------------------------------------------
    def _validate_binary(self) -> str | None:
        binary = self.binary_var.get().strip() or default_binary_path()
        binary_path = Path(binary)
        if not binary_path.exists():
            messagebox.showerror("Executable not found", f"Could not find pdf_password_retriever at:\n{binary}")
            return None
        return str(binary_path)

    def _validate_device_probe(self) -> str | None:
        device_probe = self.device_probe_var.get().strip() or default_device_probe_path()
        device_probe_path = Path(device_probe)
        if not device_probe_path.exists():
            messagebox.showerror("Executable not found", f"Could not find device_probe at:\n{device_probe}")
            return None
        return str(device_probe_path)

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

    def _run_device_probe(self) -> None:
        device_probe = self._validate_device_probe()
        if not device_probe:
            return
        raw_args = self.device_probe_args_var.get().strip()
        extra_args = shlex.split(raw_args) if raw_args else []
        command = [device_probe] + extra_args
        header = "Running device_probe benchmark\n"
        if extra_args:
            header += "Options: " + " ".join(shlex.quote(arg) for arg in extra_args) + "\n\n"
        else:
            header += "Using default settings\n\n"
        self._execute(command, header)

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
            for widget in (self.run_button, self.info_button, self.probe_button):
                widget.configure(state=state_run)
            self.stop_button.configure(state=state_stop)
            if running:
                self.progress.start(12)
            else:
                self.progress.stop()
                if self.status_var.get() in {"Running...", "Stopping..."}:
                    self.status_var.set("Idle")

        self.master.after(0, update)

    def _set_status(self, message: str) -> None:
        def update() -> None:
            self.status_var.set(message)

        self.master.after(0, update)

    def _on_close(self) -> None:
        """Ensure background threads are notified before closing the window."""

        self._stop_process()
        if self._runner and self._runner.is_alive():
            self._runner.join(timeout=0.5)
        self.master.destroy()


def main() -> None:
    root = tk.Tk()
    app = UnlockPDFGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()

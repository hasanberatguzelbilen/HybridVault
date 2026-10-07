
"""
HybridVault
Graphical User Interface
"""

import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

from .crypto import generate_aes_key
from .file_manager import encrypt_file, decrypt_file


class HybridVaultGUI:
    """Main HybridVault graphical interface."""

    def __init__(self, root):
        self.root = root
        self.root.title("HybridVault - Secure File Vault")
        self.root.geometry("650x450")
        self.root.resizable(False, False)

        self.current_key = None
        self.last_encrypted_file = None
        self.last_plaintext_hash = None

        self._build_interface()

    def _build_interface(self):
        """Create the graphical interface."""

        title = tk.Label(
            self.root,
            text="HybridVault",
            font=("Arial", 24, "bold"),
        )
        title.pack(pady=(25, 5))

        subtitle = tk.Label(
            self.root,
            text="Secure File Vault",
            font=("Arial", 11),
        )
        subtitle.pack(pady=(0, 20))

        info_frame = tk.Frame(self.root)
        info_frame.pack(fill="x", padx=40)

        self.status_label = tk.Label(
            info_frame,
            text="Status: Ready",
            anchor="w",
            font=("Arial", 10),
        )
        self.status_label.pack(fill="x")

        key_frame = tk.LabelFrame(
            self.root,
            text="Encryption Key",
            padx=15,
            pady=15,
        )
        key_frame.pack(
            fill="x",
            padx=40,
            pady=15,
        )

        self.key_status = tk.Label(
            key_frame,
            text="No AES key generated.",
            anchor="w",
        )
        self.key_status.pack(fill="x")

        generate_key_button = tk.Button(
            key_frame,
            text="Generate AES-256 Key",
            command=self.generate_key,
            width=25,
        )
        generate_key_button.pack(pady=(10, 0))

        encryption_frame = tk.LabelFrame(
            self.root,
            text="File Operations",
            padx=15,
            pady=15,
        )
        encryption_frame.pack(
            fill="x",
            padx=40,
            pady=5,
        )

        encrypt_button = tk.Button(
            encryption_frame,
            text="Encrypt File",
            command=self.encrypt_file_gui,
            width=25,
        )
        encrypt_button.grid(
            row=0,
            column=0,
            padx=10,
            pady=10,
        )

        decrypt_button = tk.Button(
            encryption_frame,
            text="Decrypt File",
            command=self.decrypt_file_gui,
            width=25,
        )
        decrypt_button.grid(
            row=0,
            column=1,
            padx=10,
            pady=10,
        )

        self.hash_label = tk.Label(
            self.root,
            text="SHA-256: -",
            anchor="w",
            justify="left",
            wraplength=550,
        )
        self.hash_label.pack(
            fill="x",
            padx=45,
            pady=15,
        )

    def generate_key(self):
        """Generate a new AES-256 encryption key."""

        try:
            self.current_key = generate_aes_key()

            self.key_status.config(
                text="AES-256 key generated successfully."
            )

            self.status_label.config(
                text="Status: Encryption key ready."
            )

            messagebox.showinfo(
                "HybridVault",
                "New AES-256 encryption key generated.",
            )

        except Exception as error:
            messagebox.showerror(
                "Key Generation Error",
                str(error),
            )

    def encrypt_file_gui(self):
        """Select and encrypt a file."""

        if self.current_key is None:
            messagebox.showwarning(
                "Key Required",
                "First generate an AES-256 key.",
            )
            return

        input_path = filedialog.askopenfilename(
            title="Select file to encrypt"
        )

        if not input_path:
            return

        input_file = Path(input_path)

        output_path = filedialog.asksaveasfilename(
            title="Save encrypted file",
            defaultextension=".hvault",
            initialfile=input_file.name + ".hvault",
            filetypes=[
                ("HybridVault files", "*.hvault"),
                ("All files", "*.*"),
            ],
        )

        if not output_path:
            return

        try:
            plaintext_hash = encrypt_file(
                input_path,
                output_path,
                self.current_key,
            )

            self.last_encrypted_file = output_path
            self.last_plaintext_hash = plaintext_hash

            self.hash_label.config(
                text=f"SHA-256: {plaintext_hash}"
            )

            self.status_label.config(
                text="Status: File encrypted successfully."
            )

            messagebox.showinfo(
                "Encryption Complete",
                "File encrypted successfully.\n\n"
                f"Output:\n{output_path}\n\n"
                f"SHA-256:\n{plaintext_hash}",
            )

        except Exception as error:
            self.status_label.config(
                text="Status: Encryption failed."
            )

            messagebox.showerror(
                "Encryption Error",
                str(error),
            )

    def decrypt_file_gui(self):
        """Select and decrypt a HybridVault file."""

        if self.current_key is None:
            messagebox.showwarning(
                "Key Required",
                "The AES-256 key used for encryption is required.",
            )
            return

        input_path = filedialog.askopenfilename(
            title="Select encrypted file",
            filetypes=[
                ("HybridVault files", "*.hvault"),
                ("All files", "*.*"),
            ],
        )

        if not input_path:
            return

        input_file = Path(input_path)

        default_name = input_file.name

        if default_name.endswith(".hvault"):
            default_name = default_name[:-7]

        output_path = filedialog.asksaveasfilename(
            title="Save decrypted file",
            initialfile=default_name,
            filetypes=[
                ("All files", "*.*"),
            ],
        )

        if not output_path:
            return

        try:
            decrypted_hash = decrypt_file(
                input_path,
                output_path,
                self.current_key,
            )

            self.hash_label.config(
                text=f"SHA-256: {decrypted_hash}"
            )

            self.status_label.config(
                text="Status: File decrypted successfully."
            )

            messagebox.showinfo(
                "Decryption Complete",
                "File decrypted successfully.\n\n"
                f"Output:\n{output_path}\n\n"
                f"SHA-256:\n{decrypted_hash}",
            )

        except Exception as error:
            self.status_label.config(
                text="Status: Decryption failed."
            )

            messagebox.showerror(
                "Decryption Error",
                str(error),
            )


def run_gui():
    """Start the HybridVault GUI."""

    root = tk.Tk()

    app = HybridVaultGUI(root)

    root.mainloop()


if __name__ == "__main__":
    run_gui()

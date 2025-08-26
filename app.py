import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import base64
import secrets

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class EncryptApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Image Encryption GUI (AES)")
        self.geometry("800x550")
        self.resizable(False, False)

        self.image_path = None
        self.encrypted_path = None
        self.encrypted_data = None

        self.create_widgets()

    def create_widgets(self):
        title_label = ctk.CTkLabel(self, text="Image Encryption with AES", font=ctk.CTkFont(size=24, weight="bold"))
        title_label.pack(pady=(10, 0))

        container = ctk.CTkFrame(self)
        container.pack(fill="both", expand=True, padx=20, pady=10)

        self.enc_frame = ctk.CTkFrame(container, width=600)
        self.enc_frame.pack(fill="both", expand=True, padx=10)

        enc_title = ctk.CTkLabel(self.enc_frame, text="Encryption", font=ctk.CTkFont(size=18, weight="bold"))
        enc_title.pack(pady=10)

        top_enc_frame = ctk.CTkFrame(self.enc_frame)
        top_enc_frame.pack(fill="x", padx=10)

        self.btn_select = ctk.CTkButton(top_enc_frame, text="Select Image", width=130, command=self.select_image)
        self.btn_select.grid(row=0, column=0, padx=5, pady=5)

        self.btn_gen_key = ctk.CTkButton(top_enc_frame, text="Generate Key", width=130, command=self.generate_key)
        self.btn_gen_key.grid(row=0, column=1, padx=5, pady=5)

        self.entry_key = ctk.CTkEntry(top_enc_frame, placeholder_text="Encryption Key (Base64)")
        self.entry_key.grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        top_enc_frame.columnconfigure(2, weight=1)

        img_disp_frame = ctk.CTkFrame(self.enc_frame)
        img_disp_frame.pack(pady=10, padx=10, fill="x")

        self.lbl_original_img = ctk.CTkLabel(img_disp_frame)
        self.lbl_original_img.grid(row=0, column=0, padx=10)

        self.lbl_encrypted_img = ctk.CTkLabel(img_disp_frame)
        self.lbl_encrypted_img.grid(row=0, column=1, padx=10)

        self.lbl_decrypted_img = ctk.CTkLabel(img_disp_frame)
        self.lbl_decrypted_img.grid(row=0, column=2, padx=10)

        btns_frame = ctk.CTkFrame(self.enc_frame)
        btns_frame.pack(pady=10, padx=10, fill="x")

        self.btn_encrypt = ctk.CTkButton(btns_frame, text="Encrypt Image", command=self.encrypt_image)
        self.btn_encrypt.pack(side="left", expand=True, padx=10)

        self.btn_decrypt = ctk.CTkButton(btns_frame, text="Decrypt Image", command=self.decrypt_image)
        self.btn_decrypt.pack(side="left", expand=True, padx=10)

    def select_image(self):
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.bmp *.jpeg")])
        if path:
            self.image_path = path
            self.load_image_to_label(path, self.lbl_original_img)
            self.clear_images()
            self.entry_key.delete(0, ctk.END)

    def generate_key(self):
        key = secrets.token_bytes(16)  # 16 bytes key for AES-128
        key_b64 = base64.b64encode(key).decode()
        self.entry_key.delete(0, ctk.END)
        self.entry_key.insert(0, key_b64)

    def encrypt_image(self):
        if not self.image_path:
            messagebox.showerror("Error", "No image selected.")
            return

        key_b64 = self.entry_key.get().strip()
        if not key_b64:
            messagebox.showerror("Error", "Encryption key is missing.")
            return

        try:
            key = base64.b64decode(key_b64)
            if len(key) not in [16, 24, 32]:
                raise ValueError("Key must be 16, 24, or 32 bytes after decoding Base64.")

            with open(self.image_path, "rb") as f:
                data = f.read()

            cipher = AES.new(key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data, AES.block_size))

            self.encrypted_data = cipher.iv + ct_bytes

            self.encrypted_path = self.image_path + ".enc"
            with open(self.encrypted_path, "wb") as f:
                f.write(self.encrypted_data)

            self.load_placeholder_image(self.lbl_encrypted_img)
            messagebox.showinfo("Success", "Image encrypted and saved successfully.")

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_image(self):
        if not self.encrypted_data:
            messagebox.showerror("Error", "No encrypted data found. Please encrypt an image first.")
            return

        key_b64 = self.entry_key.get().strip()
        if not key_b64:
            messagebox.showerror("Error", "Decryption key is missing.")
            return

        try:
            key = base64.b64decode(key_b64)
            if len(key) not in [16, 24, 32]:
                raise ValueError("Key must be 16, 24, or 32 bytes after decoding Base64.")

            iv = self.encrypted_data[:16]
            ct = self.encrypted_data[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)

            pt = unpad(cipher.decrypt(ct), AES.block_size)

            output_path = "decrypted_output.png"
            with open(output_path, "wb") as f:
                f.write(pt)

            self.load_image_to_label(output_path, self.lbl_decrypted_img)
            messagebox.showinfo("Success", "Image decrypted and displayed successfully.")

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def load_image_to_label(self, path, label):
        img = Image.open(path)
        img.thumbnail((200, 200))
        photo = ImageTk.PhotoImage(img)
        label.configure(image=photo)
        label.image = photo

    def load_placeholder_image(self, label):
        img = Image.new("RGB", (200, 200), (60, 60, 60))
        photo = ImageTk.PhotoImage(img)
        label.configure(image=photo)
        label.image = photo

    def clear_images(self):
        self.lbl_encrypted_img.configure(image=None)
        self.lbl_encrypted_img.image = None
        self.lbl_decrypted_img.configure(image=None)
        self.lbl_decrypted_img.image = None

if __name__ == "__main__":
    app = EncryptApp()
    app.mainloop()

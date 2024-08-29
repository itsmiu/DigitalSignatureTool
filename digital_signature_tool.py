import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# Define functions for key generation, signing, and verification

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("private_key.pem", "wb") as f:
        f.write(private_pem)

    with open("public_key.pem", "wb") as f:
        f.write(public_pem)

    print("Keys generated and saved to files.")
    messagebox.showinfo("Info", "Keys generated successfully. Files: private_key.pem, public_key.pem")

def sign_document(document_path, private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    with open(document_path, "rb") as doc_file:
        document = doc_file.read()

    signature = private_key.sign(
        document,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open("signature.sig", "wb") as sig_file:
        sig_file.write(signature)

    print("Document signed and signature saved to signature.sig.")
    messagebox.showinfo("Info", "Document signed successfully. Signature saved as signature.sig")

def verify_signature(document_path, signature_path, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    with open(document_path, "rb") as doc_file:
        document = doc_file.read()

    with open(signature_path, "rb") as sig_file:
        signature = sig_file.read()

    try:
        public_key.verify(
            signature,
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
        messagebox.showinfo("Info", "Signature is valid.")
    except InvalidSignature:
        print("Signature is invalid.")
        messagebox.showerror("Error", "Signature is invalid.")

# Define UI functions with instructions

def generate_keys_ui():
    generate_keys()

def sign_document_ui():
    messagebox.showinfo("Instructions", "Select the document you want to sign and then select the private key file.")
    document_path = filedialog.askopenfilename(title="Select Document to Sign")
    private_key_path = filedialog.askopenfilename(title="Select Private Key")

    if document_path and private_key_path:
        sign_document(document_path, private_key_path)

def verify_signature_ui():
    messagebox.showinfo("Instructions", "Select the document you want to verify, the signature file, and the public key file.")
    document_path = filedialog.askopenfilename(title="Select Document")
    signature_path = filedialog.askopenfilename(title="Select Signature")
    public_key_path = filedialog.askopenfilename(title="Select Public Key")

    if document_path and signature_path and public_key_path:
        verify_signature(document_path, signature_path, public_key_path)

# Setup CustomTkinter application

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Digital Signature Tool")
app.geometry("400x300")

# Create and place widgets

instructions_label = ctk.CTkLabel(app, text="Use this tool to generate keys, sign documents, and verify signatures.", wraplength=350)
instructions_label.pack(pady=10)

generate_keys_button = ctk.CTkButton(app, text="Generate Keys", command=generate_keys_ui)
generate_keys_button.pack(pady=10)

sign_button = ctk.CTkButton(app, text="Sign Document", command=sign_document_ui)
sign_button.pack(pady=10)

verify_button = ctk.CTkButton(app, text="Verify Signature", command=verify_signature_ui)
verify_button.pack(pady=10)

app.mainloop()

from tkinter import *
from tkinter import messagebox
import base64

#encryptANDdecrypt
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    enc = base64.urlsafe_b64decode(enc.encode()).decode()
    dec = []
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

FONT = "Verdana"
window = Tk()
window.title("Secret Notepad")
window.config(padx=30, pady=30)

def save_and_encrypt():
    title = secret_input_label.get()
    message = input_text.get("1.0", END)
    password = password_key_input.get()

    if len(title) == 0 or len(message) == 0 or len(password) == 0:
        messagebox.showwarning(title="ERROR!" , message="Please do not leave any spaces")
    else :
        message_encrypted = encode(password,message)
        try:
            with open("robots.txt","a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")

        except FileNotFoundError:

            with open("robots.txt","w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            secret_input_label.delete(0,END)
            input_text.delete(1.0,END)
            password_key_input.delete(0,END)
def decrypt_code():
    message_encrypted = input_text.get("1.0", END).strip()
    password = password_key_input.get()

    if len(message_encrypted) == 0 or len(password) == 0:
        messagebox.showwarning(title="ERROR!", message="Please do not leave any spaces")
    else:
        try:
            decrypted_message = decode(password, message_encrypted)
            input_text.delete("1.0", END)
            input_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="ERROR", message="Please enter encrypted text !!!")


#UserInterface

photo = PhotoImage(file="top-secret.png")
photo_Label = Label(image=photo)
photo_Label.pack()


secret_title_label = Label(text="Enter Your Title", font=FONT)
secret_title_label.pack()

secret_input_label = Entry(width=50)
secret_input_label.pack()

input_secret_text = Label(text="Enter Your Secret", font=FONT)
input_secret_text.pack()

input_text = Text(width=30, height=15)
input_text.pack()

password_key = Label(text="Please enter your password", font=FONT)
password_key.pack()

password_key_input = Entry(width=27)
password_key_input.pack()

save_button = Button(text=" Save & Encrypt ", font="Helvetica" , command=save_and_encrypt)
save_button.pack()

decrypt_button = Button(text="Decrypt", font="Helvetica" , command=decrypt_code)
decrypt_button.pack()


window.mainloop()
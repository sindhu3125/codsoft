import tkinter as tk
import random
import string

def generate_password(length):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special_characters = string.punctuation

    all_characters = lowercase + uppercase + digits + special_characters

    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(special_characters)
    ]

    password += random.choices(all_characters, k=length - 4)
    random.shuffle(password)

    return ''.join(password)

# Curated Color Palette
COLORS = {
    "Soft Blue": "#E6F2FF",       # Light Blue
    "Mint Green": "#E0F2E9",       # Soft Mint
    "Lavender": "#E6E6FA",         # Light Lavender
    "Peach": "#FFEFD5",            # Soft Peach
    "Sky Blue": "#87CEEB",         # Sky Blue
    "Pastel Pink": "#FFD1DC",      # Pastel Pink
    "Light Sage": "#C5E1A5",       # Light Sage Green
    "Pale Turquoise": "#AFEEEE"    # Pale Turquoise
}

class PasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("Secure Password Generator")
        master.geometry("450x400")

        # Random Background Color
        self.bg_color = random.choice(list(COLORS.values()))
        master.configure(bg=self.bg_color)

        # Main Frame
        self.frame = tk.Frame(master, bg=self.bg_color)
        self.frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        # Title
        self.title = tk.Label(
            self.frame, 
            text="Password Generator", 
            font=("Arial", 16, "bold"), 
            bg=self.bg_color
        )
        self.title.pack(pady=10)

        # Length Label and Entry
        self.length_frame = tk.Frame(self.frame, bg=self.bg_color)
        self.length_frame.pack(pady=10)

        self.length_label = tk.Label(
            self.length_frame, 
            text="Enter Password Length (min 4):", 
            font=("Arial", 10), 
            bg=self.bg_color
        )
        self.length_label.pack(side=tk.LEFT, padx=5)

        self.length_entry = tk.Entry(
            self.length_frame, 
            width=10, 
            font=("Arial", 10)
        )
        self.length_entry.pack(side=tk.LEFT)
        self.length_entry.insert(0, "12")  # Default length

        # Generate Button
        self.generate_button = tk.Button(
            self.frame, 
            text="Generate Password", 
            command=self.generate,
            font=("Arial", 10, "bold"),
            bg="#4CAF50",  # Green button
            fg="white"
        )
        self.generate_button.pack(pady=15)

        # Password Display
        self.password_label = tk.Label(
            self.frame, 
            text="Generated Password Will Appear Here", 
            font=("Courier", 12), 
            bg=self.bg_color,
            wraplength=400
        )
        self.password_label.pack(pady=10)

        # Copy Button
        self.copy_button = tk.Button(
            self.frame, 
            text="Copy Password", 
            command=self.copy_password,
            font=("Arial", 10),
            bg="#2196F3",  # Blue button
            fg="white"
        )
        self.copy_button.pack(pady=10)

    def generate(self):
        try:
            length = int(self.length_entry.get())
            if length < 4:
                self.password_label.config(
                    text="Password length should be at least 4.", 
                    fg="red"
                )
                return
            
            generated_password = generate_password(length)
            self.password_label.config(
                text=f"Generated Password: {generated_password}", 
                fg="dark green"
            )
        
        except ValueError:
            self.password_label.config(
                text="Please enter a valid number.", 
                fg="red"
            )

    def copy_password(self):
        password = self.password_label.cget("text").split(": ")[-1]
        if password and password != "Generated Password Will Appear Here":
            self.master.clipboard_clear()
            self.master.clipboard_append(password)
            self.password_label.config(
                text="Password Copied to Clipboard!", 
                fg="blue"
            )

def main():
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()


    
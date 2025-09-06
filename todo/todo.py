import tkinter as tk
from tkinter import ttk, messagebox
import json
import hashlib
import os

# ------------------- Utility Functions -------------------
def hash_password(password, salt="mysalt"):
    """Hash a password with SHA256 and a salt."""
    return hashlib.sha256((password + salt).encode()).hexdigest()


def load_users():
    """Load user credentials from users.json"""
    if not os.path.exists("users.json"):
        return {}
    with open("users.json", "r") as f:
        return json.load(f)


def save_users(users):
    """Save user credentials to users.json"""
    with open("users.json", "w") as f:
        json.dump(users, f)


# ------------------- Login & Registration -------------------
class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("To-Do List Login")
        self.root.state('zoomed')  # Open full screen
        self.root.configure(bg="#d1e7dd")

        self.users = load_users()

        self.frame = tk.Frame(self.root, bg="#d1e7dd")
        self.frame.pack(expand=True)

        self.create_login_widgets()

    def create_login_widgets(self):
        for widget in self.frame.winfo_children():
            widget.destroy()

        tk.Label(self.frame, text="Login", font=("Arial", 22, "bold"), bg="#d1e7dd", fg="#0f5132").grid(row=0, column=0, columnspan=2, pady=20)

        tk.Label(self.frame, text="Username", bg="#d1e7dd", fg="#0f5132").grid(row=1, column=0, pady=5)
        self.username_entry = tk.Entry(self.frame)
        self.username_entry.grid(row=1, column=1, pady=5)

        tk.Label(self.frame, text="Password", bg="#d1e7dd", fg="#0f5132").grid(row=2, column=0, pady=5)
        self.password_entry = tk.Entry(self.frame, show="*")
        self.password_entry.grid(row=2, column=1, pady=5)

        tk.Button(self.frame, text="Login", command=self.login, bg="#0d6efd", fg="white", width=15).grid(row=3, column=0, columnspan=2, pady=10)
        tk.Button(self.frame, text="Go to Register", command=self.create_register_widgets, bg="#ffc107", fg="black", width=15).grid(row=4, column=0, columnspan=2, pady=5)

    def create_register_widgets(self):
        for widget in self.frame.winfo_children():
            widget.destroy()

        tk.Label(self.frame, text="Register", font=("Arial", 22, "bold"), bg="#d1e7dd", fg="#664d03").grid(row=0, column=0, columnspan=2, pady=20)

        tk.Label(self.frame, text="New Username", bg="#d1e7dd", fg="#664d03").grid(row=1, column=0, pady=5)
        self.new_username_entry = tk.Entry(self.frame)
        self.new_username_entry.grid(row=1, column=1, pady=5)

        tk.Label(self.frame, text="New Password", bg="#d1e7dd", fg="#664d03").grid(row=2, column=0, pady=5)
        self.new_password_entry = tk.Entry(self.frame, show="*")
        self.new_password_entry.grid(row=2, column=1, pady=5)

        tk.Button(self.frame, text="Register", command=self.register, bg="#198754", fg="white", width=15).grid(row=3, column=0, columnspan=2, pady=10)
        tk.Button(self.frame, text="Go to Login", command=self.create_login_widgets, bg="#ffc107", fg="black", width=15).grid(row=4, column=0, columnspan=2, pady=5)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username in self.users and self.users[username] == hash_password(password):
            messagebox.showinfo("Login Success", f"Welcome {username}!")
            self.root.destroy()
            main_root = tk.Tk()
            TodoApp(main_root, username)
            main_root.mainloop()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def register(self):
        username = self.new_username_entry.get()
        password = self.new_password_entry.get()

        if username in self.users:
            messagebox.showerror("Error", "Username already exists")
            return

        self.users[username] = hash_password(password)
        save_users(self.users)
        messagebox.showinfo("Success", "Registration successful! Please login.")
        self.create_login_widgets()


# ------------------- To-Do List App -------------------
class TodoApp:
    def __init__(self, root, username):
        self.root = root
        self.username = username
        self.root.title(f"{self.username}'s To-Do List")
        self.root.state('zoomed')
        self.root.configure(bg="#cff4fc")

        self.tasks_file = f"{self.username}_tasks.json"
        self.tasks = self.load_tasks()

        self.create_widgets()
        self.display_tasks()

    def create_widgets(self):
        tk.Label(self.root, text=f"Welcome {self.username}", font=("Arial", 20, "bold"), bg="#cff4fc", fg="#055160").pack(pady=10)

        frame = tk.Frame(self.root, bg="#cff4fc")
        frame.pack(pady=10)

        self.task_entry = tk.Entry(frame, width=50)
        self.task_entry.grid(row=0, column=0, padx=5)

        tk.Button(frame, text="Add Task", command=self.add_task, bg="#0d6efd", fg="white").grid(row=0, column=1, padx=5)

        self.tree = ttk.Treeview(self.root, columns=("Task", "Status"), show="headings", height=15)
        self.tree.heading("Task", text="Task")
        self.tree.heading("Status", text="Status")
        self.tree.column("Task", width=500)
        self.tree.column("Status", width=100)
        self.tree.pack(pady=10)

        btn_frame = tk.Frame(self.root, bg="#cff4fc")
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Mark Complete", command=self.mark_complete, bg="#198754", fg="white").grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Delete Task", command=self.delete_task, bg="#dc3545", fg="white").grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="Logout", command=self.logout, bg="#ffc107", fg="black").grid(row=0, column=2, padx=5)

    def load_tasks(self):
        if not os.path.exists(self.tasks_file):
            return []
        with open(self.tasks_file, "r") as f:
            return json.load(f)

    def save_tasks(self):
        with open(self.tasks_file, "w") as f:
            json.dump(self.tasks, f)

    def display_tasks(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for task in self.tasks:
            status = "Done" if task["completed"] else "Pending"
            self.tree.insert("", tk.END, values=(task["task"], status))

    def add_task(self):
        task_text = self.task_entry.get()
        if task_text:
            self.tasks.append({"task": task_text, "completed": False})
            self.save_tasks()
            self.display_tasks()
            self.task_entry.delete(0, tk.END)

    def mark_complete(self):
        selected_item = self.tree.selection()
        if selected_item:
            item_index = self.tree.index(selected_item)
            self.tasks[item_index]["completed"] = True
            self.save_tasks()
            self.display_tasks()

    def delete_task(self):
        selected_item = self.tree.selection()
        if selected_item:
            item_index = self.tree.index(selected_item)
            del self.tasks[item_index]
            self.save_tasks()
            self.display_tasks()

    def logout(self):
        self.root.destroy()
        root = tk.Tk()
        LoginApp(root)
        root.mainloop()


# ------------------- Run App -------------------
if __name__ == "__main__":
    root = tk.Tk()
    LoginApp(root)
    root.mainloop()

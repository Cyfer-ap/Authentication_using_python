import mysql.connector
from mysql.connector import Error
import bcrypt
import random
import string
from datetime import datetime, timedelta
import threading
import time
import re

# Global variable to store connection
connection = None

def generate_user_id(cursor):
    while True:
        user_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        cursor.execute("SELECT * FROM Users WHERE userID = %s", (user_id,))
        if not cursor.fetchone():  # Ensure ID is unique
            return user_id

def is_valid_phone_number(phone_number):
    # Check if the phone number starts with '+' followed by digits
    return bool(re.match(r'^\+\d{1,3}\d{10}$', phone_number))
# Function to hash the password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

# Function to check if a password is valid
def check_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

# Function to generate a random name if not provided
def generate_random_name():
    return "User" + str(random.randint(100, 999))

# Function to create a table if it doesn't exist
def create_user_table(cursor):
    try:
        # SQL query to create the table if it doesn't exist
        create_table_query = '''
        CREATE TABLE IF NOT EXISTS Users (
            userID VARCHAR(8) PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(60) NOT NULL,
            email VARCHAR(100) NOT NULL,
            name VARCHAR(50),
            acc_creation_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            tokens TEXT,
            logged_in_time INT DEFAULT 0,
            attempts INT,
            level VARCHAR(20),
            acc_status ENUM('active', 'inactive', 'suspended') DEFAULT 'active',
            mobile_no VARCHAR(15),
            location TEXT,
            user_agent TEXT,
            recovery TEXT,
            email_verify TINYINT(1) DEFAULT 0,
            mobile_verify TINYINT(1) DEFAULT 0
        );
        '''
        cursor.execute(create_table_query)
        print("Table `Users` created successfully (or already exists).")

    except Error as e:
        print(f"Error: {e}")

# Function to add a new user to the table (Sign Up)
def add_user(cursor, username, password, email, name=None, mobile_no=None, recovery=None):
    try:
        cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            print(f"Username '{username}' already exists. Please choose another one.")
            return

        user_id = generate_user_id()
        hashed_pw = hash_password(password)

        if not name:
            name = generate_random_name()

        acc_creation_date = datetime.now()

        insert_query = '''
        INSERT INTO Users (userID, username, password, email, name, acc_creation_date, mobile_no, recovery)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        '''
        cursor.execute(insert_query, (
            user_id,
            username,
            hashed_pw,
            email,
            name,
            acc_creation_date,
            mobile_no,
            recovery
        ))

        connection.commit()
        print(f"User '{username}' added successfully.")

        if mobile_no:  # If mobile number is provided, ask for verification
            verify_response = input("Do you want to verify your mobile number now? (yes/no): ").strip().lower()
            if verify_response == 'yes':
                sent_otp = send_otp(mobile_no)  # Send OTP
                if verify_otp(sent_otp):  # Verify OTP
                    cursor.execute("UPDATE Users SET mobile_verify = 1 WHERE username = %s", (username,))
                    connection.commit()
                    print("Mobile number marked as verified.")
                else:
                    print("Mobile number verification failed.")
            else:
                print("Mobile number verification skipped.")

    except Error as e:
        print(f"Error: {e}")

# Function to reset the login attempts after a successful login
def reset_login_attempts(cursor, username):
    cursor.execute("UPDATE Users SET attempts = 0, block_until = NULL WHERE username = %s", (username,))
    connection.commit()

# Function to block the user temporarily for 15 minutes
def block_user(cursor, username):
    block_duration = 15  # Block the user for 15 minutes
    block_until_time = datetime.now() + timedelta(minutes=block_duration)

    cursor.execute("UPDATE Users SET block_until = %s WHERE username = %s", (block_until_time, username))
    connection.commit()
    print(f"User '{username}' is temporarily blocked for {block_duration} minutes due to too many failed login attempts.")

# Function to check if the user is currently blocked
def is_user_blocked(cursor, username):
    cursor.execute("SELECT block_until FROM Users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if user and user[0]:  # Check if block_until is not NULL
        block_until = user[0]
        if block_until > datetime.now():
            print(f"Account is blocked until {block_until}. Please try again later.")
            return True
        else:
            # Block time has expired, unblock the user and reset attempts
            cursor.execute("UPDATE Users SET block_until = NULL, attempts = 0 WHERE username = %s", (username,))
            connection.commit()
            return False
    return False

# Function to increment login attempts and block after 3 failed attempts
def increment_login_attempts(cursor, username):
    cursor.execute("SELECT attempts FROM Users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if user:
        attempts = user[0] or 0  # Handle NULL values (if attempts are not yet set)
        attempts += 1  # Increment attempts
        cursor.execute("UPDATE Users SET attempts = %s WHERE username = %s", (attempts, username))
        connection.commit()

        if attempts >= 3:  # Block after 3 failed attempts
            block_user(cursor, username)
        else:
            print(f"Login attempt {attempts}/3 failed for user '{username}'.")

def display_user_data(cursor, username):
    try:
        # Retrieve all user information based on the username
        cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user:
            print("\n--- User Data ---")
            print(f"User ID: {user[0]}")
            print(f"Username: {user[1]}")
            print(f"Email: {user[3]}")
            print(f"Name: {user[4]}")
            print(f"Account Creation Date: {user[5]}")
            print(f"Logged In Time: {user[7]}")
            print(f"Mobile Number: {user[10]}")
            print(f"Mobile Verified: {'Yes' if user[16] else 'No'}")
            print(f"Account Status: {user[9]}")
            print("\n")
        else:
            print(f"User '{username}' not found.")

    except Error as e:
        print(f"Error: {e}")

def show_post_login_menu(cursor, username, mobile_verified):
    while True:
        print("\n--- Menu ---")
        print("1. Display User Data")
        print("2. Verify Mobile Number" if not mobile_verified else "2. Mobile Number Already Verified")
        print("3. Logout")
        choice = input("Select an option (1, 2, or 3): ")

        if choice == '1':
            # Display user data
            display_user_data(cursor, username)

        elif choice == '2' and not mobile_verified:
            # Verify mobile number
            verify_mobile_number(cursor, username)
            # Refresh mobile verification status after verification
            cursor.execute("SELECT mobile_verify FROM Users WHERE username = %s", (username,))
            mobile_verified = cursor.fetchone()[0]  # Update mobile_verified status

        elif choice == '3':
            print(f"Logging out {username}.")
            break

        else:
            print("Invalid option. Please select 1, 2, or 3.")

# Modified login_user function to handle attempts and blocking
def login_user(cursor, username, password):
    try:
        # Check if the user is blocked before attempting login
        if is_user_blocked(cursor, username):
            return

        # Retrieve user information based on the username
        cursor.execute("SELECT password, logged_in_time, mobile_verify FROM Users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user:
            stored_password, logged_in_time, mobile_verified = user

            # Check if the provided password matches the stored hashed password
            if check_password(stored_password.encode('utf-8'), password):
                print(f"Login successful. Welcome, {username}!")

                # Reset the login attempts after successful login
                reset_login_attempts(cursor, username)

                # Increment logged_in_time by 1
                cursor.execute("UPDATE Users SET logged_in_time = logged_in_time + 1 WHERE username = %s", (username,))
                connection.commit()

                # Show post-login menu
                show_post_login_menu(cursor, username, mobile_verified)

            else:
                print("Invalid password. Please try again.")
                increment_login_attempts(cursor, username)  # Increment login attempts on failure
        else:
            print(f"Username '{username}' not found.")

    except Error as e:
        print(f"Error: {e}")

def verify_mobile_number(cursor, username):
    cursor.execute("SELECT mobile_no FROM Users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if user:
        mobile_no = user[0]
        if mobile_no:
            sent_otp = send_otp(mobile_no)  # Send OTP
            if verify_otp(sent_otp):  # Verify OTP
                cursor.execute("UPDATE Users SET mobile_verify = 1 WHERE username = %s", (username,))
                connection.commit()
                print("Mobile number marked as verified.")
            else:
                print("Mobile number verification failed.")
        else:
            print("No mobile number associated with this account.")
    else:
        print(f"User '{username}' not found.")

# Function to handle the login timer
def login_timer(username):
    logged_in_time = 0
    while True:
        time.sleep(300)  # Wait for 5 minutes
        logged_in_time += 5  # Increment the logged in time by 5 minutes
        print(f"{username}, you have been logged in for {logged_in_time} minutes.")

        # Prompt the user if they want to continue
        print("Would you like to continue? (yes/no): ", end='', flush=True)

        # Start a timer for user input (1 minute)
        user_response = wait_for_input(timeout=30)

        if user_response is None:
            print(f"No response received. {username}, you have been logged out due to inactivity.")
            break  # Logout due to inactivity
        elif user_response.strip().lower() == 'yes':
            logged_in_time = 0  # Reset the timer
            print(f"Timer reset. {username}, you can continue.")
        else:
            print(f"{username}, you have been logged out due to your response.")
            break  # Logout due to user response

# Function to wait for user input with a timeout
def wait_for_input(timeout):
    response = [None]  # List to hold response (mutable for closure)

    def get_input():
        response[0] = input()  # Capture input from the user

    thread = threading.Thread(target=get_input)
    thread.start()
    thread.join(timeout)  # Wait for the timeout duration

    if thread.is_alive():
        print("\nTimeout reached. Exiting input prompt...")
        return None  # Return None for no response
    else:
        return response[0]  # Return user response

# Function to establish and return the database connection
def establish_connection():
    global connection
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='Abhinav789@',
            database='auth_py'
        )

        if connection.is_connected():
            print("Connected to the MySQL database.")

    except Error as e:
        print(f"Error while connecting to MySQL: {e}")
        connection = None

# Function to close the connection at the end of the program
def close_connection():
    global connection
    if connection.is_connected():
        connection.close()
        print("MySQL connection is closed.")

# Function to generate a unique OTP
def generate_otp():
    return str(random.randint(100000, 999999))  # Generate a 6-digit OTP

# Function to send OTP to the user
def send_otp(phone_number):
    otp = generate_otp()  # Generate OTP
    from Whatsapp_msg import send_whatsapp_message
    message = f"Your OTP is: {otp}. Please enter this to verify your mobile number."
    send_whatsapp_message(phone_number, message)  # Send the OTP via WhatsApp
    return otp  # Return the OTP for verification

# Function to verify the OTP entered by the user
def verify_otp(sent_otp):
    user_otp = input("Enter the OTP sent to your mobile number: ")
    if user_otp == sent_otp:
        print("Mobile number verified successfully!")
        return True
    else:
        print("Invalid OTP. Please try again.")
        return False

# Main execution with login or sign up option
if __name__ == "__main__":
    establish_connection()  # Establish the connection once

    if connection:
        cursor = connection.cursor()  # Create a cursor object for executing queries
        create_user_table(cursor)  # Create the table if it doesn't exist

        # Ask the user if they want to log in or sign up
        option = input("Do you want to (1) Log In or (2) Sign Up? Enter 1 or 2: ")

        if option == '1':
            # Log In flow
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            login_user(cursor, username, password)

        elif option == '2':
            # Sign Up flow
            username = input("Enter a username: ")
            password = input("Enter a password: ")
            email = input("Enter an email: ")
            name = input("Enter a name (or leave empty for random): ") or None
            mobile_no = input("Enter a mobile number (optional): ") or None
            recovery = input("Enter a recovery option (optional): ") or None

            add_user(cursor, username, password, email, name, mobile_no, recovery)

        else:
            print("Invalid option. Please restart the program and choose 1 or 2.")

        cursor.close()  # Close the cursor when done
        close_connection()  # Close the connection when the program ends

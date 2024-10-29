# Authentication_using_python
# User Authentication System using python and sql

This project is a comprehensive user authentication system written in Python, utilizing MySQL as the backend database for secure user data storage. It supports features like user sign-up, login with password validation, account blocking after multiple failed attempts, and OTP-based mobile verification via WhatsApp. The password hashing and mobile number verification further enhance security for authentication.

## Features

1. **User Sign-Up**:
   - New users can create an account with a unique username, password, and email.
   - Additional details like name, mobile number, and recovery options can also be provided.
   - If no name is provided, a random name is generated.

2. **User Login**:
   - Supports login with username and hashed password verification.
   - Login attempts are tracked, and users are blocked temporarily after three consecutive failed attempts.

3. **Mobile Verification**:
   - If a mobile number is provided, users can verify it via OTP.
   - The OTP is sent to the user’s mobile number through WhatsApp, using the `pywhatkit` library.

4. **Account Blocking and Timeout**:
   - Users are blocked for 15 minutes after three failed login attempts.
   - System prompts for inactivity timeout every 5 minutes of continuous login.

5. **User Details Display**:
   - After login, users can view their account information, including account status and mobile verification status.

## Requirements

- **Python Libraries**:
  - `mysql-connector-python`
  - `bcrypt`
  - `pywhatkit`
  - `threading`
- **MySQL Database**:
  - Make sure MySQL is installed and running on your system.
  - Update the MySQL credentials in the code (`host`, `user`, `password`, and `database`) as required.

## Table Structure

The database `Users` table is structured as follows:

| Column            | Type            | Description                                    |
|-------------------|-----------------|------------------------------------------------|
| `userID`          | `VARCHAR(8)`    | Unique user identifier (primary key)           |
| `username`        | `VARCHAR(50)`   | Unique username                                |
| `password`        | `VARCHAR(60)`   | Hashed password                                |
| `email`           | `VARCHAR(100)`  | User email                                     |
| `name`            | `VARCHAR(50)`   | User's name (optional)                         |
| `acc_creation_date` | `DATETIME`    | Account creation date                          |
| `tokens`          | `TEXT`          | Token information (optional)                   |
| `logged_in_time`  | `INT`           | Number of login sessions                       |
| `attempts`        | `INT`           | Login attempts before blocking                 |
| `level`           | `VARCHAR(20)`   | User level (optional)                          |
| `acc_status`      | `ENUM`          | Account status (`active`, `inactive`, `suspended`) |
| `mobile_no`       | `VARCHAR(15)`   | Mobile number                                  |
| `location`        | `TEXT`          | User location (optional)                       |
| `user_agent`      | `TEXT`          | Device/browser info (optional)                 |
| `recovery`        | `TEXT`          | Recovery options (optional)                    |
| `email_verify`    | `TINYINT(1)`    | Email verification status                      |
| `mobile_verify`   | `TINYINT(1)`    | Mobile verification status                     |

## Getting Started

1. **Set Up Database**:
   - Create a MySQL database, e.g., `auth_py`.
   - Update the connection parameters (`host`, `user`, `password`, `database`) in the `establish_connection` function.

2. **Install Required Libraries**:
   ```bash
   pip install mysql-connector-python bcrypt pywhatkit
3. Run the Application:
  - Execute the script in the command line or an IDE of your choice.
  - Follow the prompts to sign up or log in.

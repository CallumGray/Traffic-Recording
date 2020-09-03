import sqlite3
import os
import hashlib

CONNECTION = sqlite3.connect("initial_database.db")
CURSOR = CONNECTION.cursor()


initial_sql = '''CREATE TABLE login(username TEXT NOT NULL PRIMARY KEY,password TEXT NOT NULL)'''

foreign_sql = '''PRAGMA foreign_keys = ON'''

capture_sql = '''CREATE TABLE capture_session(
   sessionID TEXT NOT NULL PRIMARY KEY,
   username TEXT NOT NULL,
   start TEXT NOT NULL,
   end TEXT,
   FOREIGN KEY(username) REFERENCES login(username)
   )'''

vehicles_sql = '''CREATE TABLE vehicles(
   sessionID TEXT NOT NULL,
   location TEXT NOT NULL,
   type TEXT NOT NULL,
   occupancy INT NOT NULL,
   time TEXT NOT NULL,
   FOREIGN KEY(sessionID) REFERENCES capture_session(sessionID))'''

undo_sql = '''CREATE TABLE undo(
   sessionID TEXT NOT NULL,
   location TEXT NOT NULL,
   type TEXT NOT NULL,
   occupancy INT NOT NULL,
   time TEXT NOT NULL,
   FOREIGN KEY(sessionID) REFERENCES capture_session(sessionID))'''

SALT_LENGTH = 32


# Generates a salt and returns (hashed password, salt)
def generate_password(password):
    salt = os.urandom(SALT_LENGTH)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return hashed, salt


# Inserts a username, and hashed password + salt
def insert_user(username, password):
    sql = "INSERT INTO login (username, password) VALUES (?, ?)"
    hashed, salt = generate_password(password)
    hash_salt = hashed + salt
    CURSOR.execute(sql, (username, hash_salt))
    CONNECTION.commit()


try:
    CURSOR.execute(initial_sql)
    CURSOR.execute(foreign_sql)
    CURSOR.execute(capture_sql)
    CURSOR.execute(vehicles_sql)
    CURSOR.execute(undo_sql)
    CONNECTION.commit()

    insert_user('test1','password1')
    insert_user('test2','password2')
    insert_user('test3','password3')
    insert_user('test4','password4')
    insert_user('test5','password5')
    insert_user('test6','password6')
    insert_user('test7','password7')
    insert_user('test8','password8')
    insert_user('test9','password9')
    insert_user('test10','password10')
except sqlite3.Error:
    print('Database already exists!')
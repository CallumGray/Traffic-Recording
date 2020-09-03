#!/usr/bin/env python

import http.cookies as Cookie
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib
import base64
import hashlib
import os
import sqlite3
import uuid

def build_response_refill(where, what):
    text = "<action>\n"
    text += "<type>refill</type>\n"
    text += "<where>" + where + "</where>\n"
    message = base64.b64encode(bytes(what, 'ascii'))
    text += "<what>" + str(message, 'ascii') + "</what>\n"
    text += "</action>\n"
    return text

def build_response_redirect(where):
    text = "<action>\n"
    text += "<type>redirect</type>\n"
    text += "<where>" + where + "</where>\n"
    text += "</action>\n"
    return text

# Connect to traffic.db
CONNECTION = sqlite3.connect('initial_database.db')
CURSOR = CONNECTION.cursor()
print('Connected')

SALT_LENGTH = 32


# Generates a salt and returns (hashed password, salt)
def generate_password(password):
    salt = os.urandom(SALT_LENGTH)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return hashed, salt


# Given the password from the login attempt and the password(+salt) from the database, test for a match
def match_password(given_password, fetched_password_salt):
    fetched_password = fetched_password_salt[:-SALT_LENGTH]
    fetched_salt = fetched_password_salt[-SALT_LENGTH:]
    hash_from_given = hashlib.pbkdf2_hmac('sha256', given_password.encode('utf-8'), fetched_salt, 100000)
    return hash_from_given == fetched_password


# Generates a sessionID and adds it to the database
def generate_id(username):
    session_id = uuid.uuid4()
    sql = "INSERT INTO capture_session (sessionID, username,start) VALUES (?,?,strftime('%Y-%m-%d %H:%M:%S','now'))"
    CURSOR.execute(sql, (session_id.hex, username))
    CONNECTION.commit()
    return session_id.hex


# Checks if the username and password are valid
def check_login(username, password):
    sql = """SELECT password FROM login WHERE username = ?"""
    # usernames are unique, so only need to check 1 row
    result = CURSOR.execute(sql, (username,))
    fetched = result.fetchone()
    if fetched is not None:
        return match_password(password, fetched[0])
    return False


# Inserts a username, and hashed password + salt
def insert_user(username, password):
    sql = "INSERT INTO login (username, password) VALUES (?, ?)"
    hashed, salt = generate_password(password)
    hash_salt = hashed + salt
    CURSOR.execute(sql, (username, hash_salt))
    CONNECTION.commit()

#
#
#
#
#   HANDLING
#
#
#
#


def ensure_unique(username, session_id):

    sql = "SELECT * FROM capture_session WHERE username = ? AND sessionID != ? AND end IS NULL"
    open_sessions = CURSOR.execute(sql, (username, session_id)).fetchall()
    for row in open_sessions:
        end_session(row[0])


def handle_validate(iuser, imagic):

    sql = '''SELECT * FROM capture_session WHERE username = ? AND sessionID = ? AND end IS NULL'''
    result = CURSOR.execute(sql, (iuser, imagic)).fetchone()
    print('Valid? ', result is not None)

    return result is not None


def end_session(session_id):
    sql = '''UPDATE capture_session SET end = strftime('%Y-%m-%d %H:%M:%S','now') WHERE sessionID = ?'''
    CURSOR.execute(sql, (session_id,))
    CONNECTION.commit()

'''
A user has supplied a username (parameters['usernameinput'][0]) and password (parameters['passwordinput'][0])
check if these are valid and if so, create a suitable session in the database
Return the username, identifier and the response action set.
'''

def handle_login_request(iuser, imagic, parameters):
    print()
    print('Handling login')
    print()

    if handle_validate(iuser, imagic):
        # there is a user already logged in locally, so refuse access
        # This ensures that only 1 tab can display a logged in session.
        # Safest approach as cookies are not shared between multiple users on the same device
        text = "<response>\n"
        text += build_response_refill('message', 'A user is already logged in on this browser')
        user = iuser
        magic = imagic
        text += "</response>\n"
        return [user, magic, text]

    text = "<response>\n"

    if 'usernameinput' in parameters and 'passwordinput' in parameters:
        print(parameters)
        username = parameters['usernameinput'][0]
        password = parameters['passwordinput'][0]

        if check_login(username, password):
            # The user is valid
            text += build_response_redirect('/page.html')
            user = username
            magic = generate_id(username)

            # close any existing sessions elsewhere for the user
            ensure_unique(username, magic)
        else:
            # The user is not valid
            text += build_response_refill('message', 'Invalid username/password')
            user = '!'
            magic = ''
        text += "</response>\n"
        return [user, magic, text]

    text += build_response_refill('message', 'Username or password not given')
    user = '!'
    magic = ''
    text += "</response>\n"
    return [user, magic, text]


def add_vehicle(session_id, parameters):
    location = parameters['locationinput'][0]  # if 'locationinput' in parameters else None
    occupancy = int(parameters['occupancyinput'][0])  # if 'occupancyinput' in parameters else None
    vehicle_type = parameters['typeinput'][0]  # if 'typeinput' in parameters else None

    sql = '''INSERT INTO vehicles VALUES(?,?,?,?,strftime('%Y-%m-%d %H:%M:%S','now'))'''
    CURSOR.execute(sql, (session_id, location, vehicle_type, occupancy))
    CONNECTION.commit()


def undo_vehicle(session_id, parameters):
    location = parameters['locationinput'][0]  # if 'locationinput' in parameters else None
    occupancy = int(parameters['occupancyinput'][0])  # if 'occupancyinput' in parameters else None
    vehicle_type = parameters['typeinput'][0]  # if 'typeinput' in parameters else None

    # check if there's rows to undo
    select_sql = '''SELECT * FROM vehicles WHERE sessionID = ? AND location = ? AND occupancy = ? AND type = ?'''
    selected = CURSOR.execute(select_sql, (session_id, location, occupancy, vehicle_type))

    if selected.fetchone() is not None:

        insert_sql = '''INSERT INTO undo SELECT * FROM vehicles 
        WHERE sessionID = ? AND location = ? AND occupancy = ? AND type = ? ORDER BY time DESC LIMIT 1'''
        CURSOR.execute(insert_sql, (session_id, location, occupancy, vehicle_type))

        delete_sql = '''DELETE FROM vehicles WHERE sessionID = ? AND location = ? AND occupancy = ? AND type = ? 
        ORDER BY time DESC LIMIT 1'''
        CURSOR.execute(delete_sql, (session_id, location, occupancy, vehicle_type))

        CONNECTION.commit()
        return True
    return False


def session_total(session_id):
    sql = '''SELECT count(*) FROM vehicles WHERE sessionID = ?'''
    count = CURSOR.execute(sql, (session_id,))
    return str(count.fetchone()[0])


def handle_add_request(iuser, imagic, parameters):
    print()
    print('Handling add')
    print()
    text = "<response>\n"
    if not handle_validate(iuser, imagic):
        # Invalid sessions redirect to login
        text += build_response_redirect('/index.html')
    else:
        # a valid session so process the addition of the entry.
        if 'locationinput' not in parameters:
            text += build_response_refill('message', 'No location provided')
        else:
            add_vehicle(imagic, parameters)
            text += build_response_refill('message', 'Entry added.')
            text += build_response_refill('total', session_total(imagic))
    text += "</response>\n"
    user = iuser
    magic = imagic
    return [user, magic, text]


def handle_undo_request(iuser, imagic, parameters):
    print()
    print('Handling undo')
    print()
    text = "<response>\n"
    if not handle_validate(iuser, imagic):
        # Invalid sessions redirect to login
        text += build_response_redirect('/index.html')
    else:
        # a valid session so process the removal of the entry.
        if 'locationinput' not in parameters:
            text += build_response_refill('message', 'No location provided')
        else:
            if undo_vehicle(imagic, parameters):
                text += build_response_refill('message', 'Entry Un-done.')
            else:
                text += build_response_refill('message', 'No matching entry exists')
            text += build_response_refill('total', session_total(imagic))
    text += "</response>\n"
    user = ''
    magic = ''
    return [user, magic, text]


def handle_back_request(iuser, imagic):
    print()
    print('Handling back')
    print()
    text = "<response>\n"
    if not handle_validate(iuser, imagic):
        text += build_response_redirect('/index.html')
    else:
        text += build_response_redirect('/summary.html')
    text += "</response>\n"
    user = ''
    magic = ''
    return [user, magic, text]


def handle_logout_request(imagic):
    print()
    print('Handling logout with '+imagic)
    print()
    end_session(imagic)
    text = "<response>\n"
    text += build_response_redirect('/index.html')
    user = '!'
    magic = ''
    text += "</response>\n"
    return [user, magic, text]


def get_summary(session_id):
    vehicles = ['car', 'taxi', 'bus', 'motorbike', 'bicycle', 'van', 'truck', 'other']
    summary = {}
    sql_template = "SELECT count(*) FROM vehicles WHERE sessionID = ? AND type = ?"

    for vehicle in vehicles:
        count = CURSOR.execute(sql_template, (session_id, vehicle))
        summary[vehicle] = str(count.fetchone()[0])

    sql_total = "SELECT count(*) FROM vehicles WHERE sessionID = ?"
    total = CURSOR.execute(sql_total, (session_id,))
    summary['total'] = str(total.fetchone()[0])

    return summary


def handle_summary_request(iuser, imagic):
    text = "<response>\n"
    if not handle_validate(iuser, imagic):
        text += build_response_redirect('/index.html')
        user = ''
        magic = ''
    else:
        # dictionary of every vehicle queried ...
        summary = get_summary(imagic)
        text += build_response_refill('sum_car', summary['car'])
        text += build_response_refill('sum_taxi', summary['taxi'])
        text += build_response_refill('sum_bus', summary['bus'])
        text += build_response_refill('sum_motorbike', summary['motorbike'])
        text += build_response_refill('sum_bicycle', summary['bicycle'])
        text += build_response_refill('sum_van', summary['van'])
        text += build_response_refill('sum_truck', summary['truck'])
        text += build_response_refill('sum_other', summary['other'])
        text += build_response_refill('total', summary['total'])
        text += "</response>\n"
        user = iuser
        magic = imagic
    return [user, magic, text]


#
#
#
#
#   HTTP
#
#
#

# HTTPRequestHandler class
class MyHTTPServerRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):


        def set_cookies(xxx, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            xxx.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            xxx.send_header("Set-Cookie", mcookie.output(header='', sep=''))


        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value
            return [user, magic]


        user_magic = get_cookies(self)

        print(user_magic)

        # Parse the GET request to identify the file requested and the GET parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # Return a CSS (Cascading Style Sheet) file.
        # These tell the web client how the page should appear.
        if self.path.startswith('/css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            with open('.' + self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()
        if self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.' + self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()
        elif parsed_path.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./index.html', 'rb') as file:
                self.wfile.write(file.read())
            file.close()
        elif parsed_path.path.endswith('.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('.' + parsed_path.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()
        elif parsed_path.path == '/action':
            self.send_response(200)  # respond that this is a valid page request

            parameters = urllib.parse.parse_qs(parsed_path.query)

            print(parameters)

            if 'command' in parameters:

                if parameters['command'][0] == 'login':
                    [user, magic, text] = handle_login_request(user_magic[0], user_magic[1], parameters)

                    set_cookies(self, user, magic)
                elif parameters['command'][0] == 'add':
                    [user, magic, text] = handle_add_request(user_magic[0], user_magic[1], parameters)
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'undo':
                    [user, magic, text] = handle_undo_request(user_magic[0], user_magic[1], parameters)
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'back':
                    [user, magic, text] = handle_back_request(user_magic[0], user_magic[1])
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'summary':
                    [user, magic, text] = handle_summary_request(user_magic[0], user_magic[1])
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'logout':
                    [user, magic, text] = handle_logout_request(user_magic[1])
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                else:

                    text = "<response>\n"
                    text += build_response_refill('message', 'Internal Error: Command not recognised.')
                    text += "</response>\n"

            else:

                text = "<response>\n"
                text += build_response_refill('message', 'Internal Error: Command not found.')
                text += "</response>\n"
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(bytes(text, 'utf-8'))
        else:

            self.send_response(404)
            self.end_headers()


def run():
    print('starting server...')

    server_address = ('127.0.0.1', 8081)
    httpd = HTTPServer(server_address, MyHTTPServerRequestHandler)
    print('running server...')
    httpd.serve_forever()


run()

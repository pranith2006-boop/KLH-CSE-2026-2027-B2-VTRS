import sqlite3

def unsafe_query(user_input):
    conn = sqlite3.connect(":memory:")
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    conn.execute(query)
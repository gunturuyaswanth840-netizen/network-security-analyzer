import sqlite3

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE demo_users (username TEXT, password TEXT)")
conn.execute(
    "INSERT INTO demo_users VALUES (?, ?)",
    ("student", "correct-password")
)

payload = "\" OR 1=1 -- "
query = (
    "SELECT * FROM demo_users "
    f"WHERE username = '{payload}' AND password = 'wrong'"
)

print("Vulnerable query test:")
try:
    result = conn.execute(query).fetchone()
    print("MATCH FOUND" if result else "NO MATCH")
except sqlite3.Error as e:
    print("SQL error:", e)

print("Safe parameterized query test:")
result = conn.execute(
    "SELECT * FROM demo_users WHERE username = ? AND password = ?",
    (payload, "wrong")
).fetchone()
print("MATCH FOUND" if result else "NO MATCH")

conn.close()

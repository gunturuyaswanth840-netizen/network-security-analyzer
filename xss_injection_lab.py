import html

# Mock database/input source containing payloads
payload = 'javascript:alert(1)'

# ? Vulnerable Function: Direct context string interpolation without escaping
def render_vulnerable_page(user_input):
    return f"<div><p>Search results for: {user_input}</p></div>"

# ? Secured Function: Encodes standard HTML characters into safe numeric entities
def render_safe_page(user_input):
    escaped_input = html.escape(user_input)
    return f"<div><p>Search results for: {escaped_input}</p></div>"

print("--- Vulnerable Rendering Output ---")
vulnerable_html = render_vulnerable_page(payload)
print(vulnerable_html)
# Check if script blocks passed through completely untouched
if "<script>" in vulnerable_html:
    print("MATCH FOUND: Raw executable script tags present in DOM!")
else:
    print("NO MATCH")

print("\n--- Safe Parameterized Rendering Output ---")
safe_html = render_safe_page(payload)
print(safe_html)
if "<script>" in safe_html:
    print("MATCH FOUND")
else:
    print("NO MATCH: Script characters safely neutralized into text elements.")

import psycopg2

conn = psycopg2.connect(
    dbname="spire",
    user="postgres",
    password="postgres",
    host="127.0.0.1",
    port=5433
)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS rbac_policies (
    type VARCHAR(50) NOT NULL,
    key VARCHAR(255) NOT NULL,
    value VARCHAR(255) NOT NULL,
    PRIMARY KEY (type, key)
);
""")

cur.execute("TRUNCATE TABLE rbac_policies;")

policies = [
    ("tool_policy", "keycloak_revoke_user_sessions", "admin"),
    ("tool_policy", "keycloak_list_user_sessions", "analyst"),
    ("tool_policy", "keycloak_get_user_events", "guest"),
    ("role_level", "guest", "1"),
    ("role_level", "analyst", "2"),
    ("role_level", "admin", "3"),
    ("spiffe_binding", "spiffe://runtime-shield/agent", "admin"),
    ("spiffe_binding", "spiffe://runtime-shield/dashboard", "analyst"),
    ("spiffe_binding", "spiffe://runtime-shield/bridge", "admin"),
]

for p in policies:
    cur.execute("INSERT INTO rbac_policies (type, key, value) VALUES (%s, %s, %s);", p)

conn.commit()
cur.close()
conn.close()
print("Postgres Policy DB seeded successfully!")

import sqlite3

conn = sqlite3.connect('observer/instance/observer.db')
c = conn.cursor()
c.execute('SELECT name FROM sqlite_master WHERE type="table"')
tables = c.fetchall()
print('Database tables:')
for table in tables:
    print(f'  {table[0]}')

# Check SIEM events
try:
    c.execute('SELECT COUNT(*) FROM siem_events')
    count = c.fetchone()[0]
    print(f'SIEM events: {count}')
    if count > 0:
        c.execute('SELECT severity, crypto_algorithm, pqc_ready, harvestable FROM siem_events LIMIT 5')
        events = c.fetchall()
        print('Sample SIEM events:')
        for event in events:
            print(f'  Severity: {event[0]}, Crypto: {event[1]}, PQC: {event[2]}, Harvestable: {event[3]}')
except Exception as e:
    print(f'Error checking SIEM events: {e}')

conn.close()
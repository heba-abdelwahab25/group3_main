import sqlite3

conn = sqlite3.connect('observer/instance/observer.db')
c = conn.cursor()

# Check recent CBOM events for db component
c.execute('SELECT source_component, destination_component, message_type, timestamp FROM cbom_event WHERE source_component = "db" OR destination_component = "db" ORDER BY timestamp DESC LIMIT 5')
db_events = c.fetchall()
print('Recent DB CBOM events:')
for event in db_events:
    print(f'  {event[3]}: {event[0]} -> {event[1]} ({event[2]})')

# Check backend to db events
c.execute('SELECT source_component, destination_component, message_type FROM cbom_event WHERE source_component = "backend" AND destination_component = "db" ORDER BY timestamp DESC LIMIT 3')
backend_db_events = c.fetchall()
print(f'\nBackend->DB events: {len(backend_db_events)}')
for event in backend_db_events:
    print(f'  {event[0]} -> {event[1]} ({event[2]})')

# Check total events by flow
c.execute('''SELECT source_component || '->' || destination_component as flow, COUNT(*) as count
             FROM cbom_event
             GROUP BY source_component, destination_component
             ORDER BY count DESC LIMIT 10''')
flows = c.fetchall()
print('\nTop CBOM flows:')
for flow, count in flows:
    print(f'  {flow}: {count}')

conn.close()
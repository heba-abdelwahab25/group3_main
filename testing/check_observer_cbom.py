import sqlite3

conn = sqlite3.connect('observer/instance/observer.db')
c = conn.cursor()

c.execute('SELECT COUNT(*) FROM cbom_event WHERE destination_component = ?', ('observer',))
observer_count = c.fetchone()[0]
print(f'Observer as destination: {observer_count}')

c.execute('SELECT COUNT(*) FROM cbom_event WHERE source_component = ?', ('db',))
db_source_count = c.fetchone()[0]
print(f'DB as source: {db_source_count}')

c.execute('SELECT COUNT(*) FROM cbom_event WHERE destination_component = ?', ('db',))
db_dest_count = c.fetchone()[0]
print(f'DB as destination: {db_dest_count}')

c.execute('SELECT source_component, destination_component, COUNT(*) as count FROM cbom_event GROUP BY source_component, destination_component ORDER BY count DESC LIMIT 8')
results = c.fetchall()
print('Top CBOM flows:')
for src, dst, count in results:
    print(f'  {src} -> {dst}: {count}')

print('\nAll expected components present in CBOM:')
expected = ['frontend', 'backend', 'db', 'client', 'proxy', 'observer']
c.execute('SELECT DISTINCT source_component FROM cbom_event UNION SELECT DISTINCT destination_component FROM cbom_event')
all_components = set([row[0] for row in c.fetchall() if row[0]])
for comp in expected:
    status = '✓' if comp in all_components else '✗'
    print(f'  {comp}: {status}')

conn.close()
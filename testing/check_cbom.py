import sqlite3

conn = sqlite3.connect('observer/instance/observer.db')
c = conn.cursor()

# Check all unique flows
c.execute("SELECT DISTINCT source_component || '->' || destination_component as flow FROM cbom_event")
flows = c.fetchall()
print('CBOM data flows:')
for flow in flows:
    print(f'  {flow[0]}')

# Check top flows by count
c.execute('''SELECT source_component, destination_component, COUNT(*) as count
             FROM cbom_event
             GROUP BY source_component, destination_component
             ORDER BY count DESC LIMIT 10''')
grouped = c.fetchall()
print('\nTop CBOM flows by count:')
for src, dst, count in grouped:
    print(f'  {src} -> {dst}: {count}')

# Check if observer and db components exist
c.execute("SELECT DISTINCT source_component FROM cbom_event WHERE source_component IN ('observer', 'db')")
observer_sources = c.fetchall()
c.execute("SELECT DISTINCT destination_component FROM cbom_event WHERE destination_component IN ('observer', 'db')")
observer_dests = c.fetchall()

print(f'\nObserver as source: {len(observer_sources) > 0}')
print(f'Observer as destination: {len(observer_dests) > 0}')

conn.close()
import sqlite3

# Connect to the database
connection = sqlite3.connect('app.db')
cursor = connection.cursor()

# Check if the column exists, and if not, add it
cursor.execute("PRAGMA table_info(CrawlData)")
columns = [info[1] for info in cursor.fetchall()]
if "word_stats" not in columns:
    cursor.execute("ALTER TABLE crawl_data ADD COLUMN word_stats TEXT")
    print("Column 'word_stats' added.")
else:
    print("Column 'word_stats' already exists.")

# Commit changes and close the connection
connection.commit()
connection.close()


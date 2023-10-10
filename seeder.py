# Import the modules
import csv
import sqlite3

# Open the csv file
with open("sites.csv", "r") as csv_file:
    # Create a csv reader object
    csv_reader = csv.DictReader(csv_file)
    # Connect to the database
    conn = sqlite3.connect("db.sqlite3")
    # Create a cursor object
    cur = conn.cursor()
    # Create the table if it does not exist
    cur.execute("CREATE TABLE IF NOT EXISTS base_site (url TEXT, status TEXT)")
    # Loop through the rows of the csv file
    for row in csv_reader:
        # Get the url and status values from the row
        url = row["url"]
        status = row["status"]
        # Insert the values into the table
        cur.execute("INSERT INTO base_site (url, status) VALUES (?, ?)", (url, status))
    # Commit the changes to the database
    conn.commit()
    # Close the connection
    conn.close()

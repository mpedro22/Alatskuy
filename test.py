import pyodbc
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

server = 'mysqlserver8888.database.windows.net,1433'
database = 'myPabrikDB'
username = 'azureuser'
password = 'Mp221003-'
driver = '{ODBC Driver 18 for SQL Server}'

connection_string = 'Driver={ODBC Driver 18 for SQL Server};Server=tcp:mysqlserver8888.database.windows.net,1433;Database=myPabrikDB;Uid=azureuser;Pwd=Mp221003-;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;'

try:
    conn = pyodbc.connect(connection_string)
    cursor = conn.cursor()

    # Execute SQL queries or commands here
    cursor.execute("SELECT * FROM alat")
    
    # Fetch all rows
    rows = cursor.fetchall()

    # Display the results
    for row in rows:
        print(row)

    conn.commit()
    conn.close()

except pyodbc.Error as e:
    print(f"Error: {str(e)}")


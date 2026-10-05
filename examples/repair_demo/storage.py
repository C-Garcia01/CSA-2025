def find_reports(connection, condition):
    return connection.execute("SELECT name FROM reports WHERE " + condition).fetchall()

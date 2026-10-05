from storage import find_reports


def report_search(connection, name):
    return find_reports(connection, "name = '" + name + "'")

import sqlite3 as lite


class ServerDatabase:
    table = ("id INTEGER PRIMARY KEY AUTOINCREMENT", "ip TEXT", "port INTEGER", "public_key TEXT", "is_up BOOL")

    def __init__(self):
        """
        setting up the interface that communicates with the database
        """
        self.dbPath = 'database/nodes.db'
        self.con = lite.connect(self.dbPath)
        # for debugging
        self.create_table_if_not_exists("servers", self.table)
        padder = "-"*150
        print("\n\nSERVERS:")
        print(f'\n{padder}\n'.join(map(str, self.get_all_servers())))
        ######

    def query(self, sql):
        """
        function that execute sql query on the database
        :param sql: str - the sql query
        :return: list - list of the rows of the database
        """

        rows = []

        try:
            cur = self.con.cursor()
            cur.execute(sql)
            self.con.commit()
            rows = cur.fetchall()
        except lite.Error as e:
            print(f"sql error: {e}")

        return rows

    def create_table_if_not_exists(self, name, params):
        """
        creates table in the database if the table doesn't exist
        :param name: str - table name
        :param params: tuple (or any iterable) - table params
        :return: None
        """
        table_params = ",".join((param for param in params))
        query = f"CREATE TABLE IF NOT EXISTS {name} ({table_params})"

        self.query(query)

    def check_if_exists(self, name, params):
        """
        checking if data exists in the database
        :param name: str - table name
        :param params: data to check if exists
        :return: bool - exists or not
        """

        search_params = " AND ".join((param[0] + "=" + param[1] for param in params))
        query = f"SELECT * FROM {name} WHERE {search_params}"
        rows = self.query(query)
        return len(rows) != 0

    def add_server(self, ip, port, public_key, is_up):
        """
        checking if the server can be added to the database and adding it
        :param ip: ip of server
        :param port: preferred port to contact server
        :param public_key: the server's public_key
        :param is_up: bool - if is up
        :return: bool - if successful
        """

        self.create_table_if_not_exists("servers", self.table)

        if self.check_if_exists("servers", (("ip", f"'{ip}'"), ("port", f"{port}"))):
            self.query(f"UPDATE servers SET public_key = '{public_key}' WHERE ip = '{ip}' AND port = {port}")
            if is_up:
                self.query(f"UPDATE servers SET is_up = 1 WHERE ip = '{ip}' AND port = {port}")
            else:
                self.query(f"UPDATE servers SET is_up = 0 WHERE ip = '{ip}' AND port = {port}")
            return False

        self.query(f"INSERT INTO servers(ip, port, public_key, is_up) VALUES('{ip}', {port}, '{public_key}', {is_up})")
        return True

    def deactivate_server(self, ip, port):
        """
        if server is down, deactivate it
        :param ip: ip of server
        :param port: preferred port to contact server
        :return: None
        """

        self.create_table_if_not_exists("servers", self.table)

        self.query(f"UPDATE servers SET is_up = 0 WHERE ip = '{ip}' AND port = {port}")

    def remove_server(self, ip, port):
        """
        function that removes a server from the servers table by the ip and port
        :param ip: ip of server
        :param port: preferred port to contact server
        :return: None
        """
        self.create_table_if_not_exists("servers", self.table)

        self.query(f"DELETE FROM servers WHERE ip = '{ip}' AND port = {port}")

    def check_server_exists(self, ip, port):
        """
        function that checks if server exists in the database
        :param ip: ip of server
        :param port: preferred port to contact server
        :return: bool - exists or not
        """

        self.create_table_if_not_exists("servers", self.table)

        return self.check_if_exists("servers", (("ip", f"'{ip}'"), ("port", f"{port}")))

    def get_server(self, ip, port):
        """
        returning server row by ip and port
        :param ip: ip of server
        :param port: preferred port to contact server
        :return: tuple - user row
        """

        return self.query(f"SELECT * FROM servers WHERE ip = '{ip}' AND port = {port}")[0]

    def get_all_servers(self, is_up=0):
        """
        return all servers
        :param is_up: if true, gives back only servers that are up
        :return: list
        """
        if is_up:
            return self.query(f"SELECT * FROM servers WHERE is_up = 1")
        return self.query(f"SELECT * FROM servers")

    def delete_all_servers(self):
        """
        deletes all entries in table
        :return:
        """
        return self.query("DELETE FROM servers")


if __name__ == '__main__':
    db = Database()
    # db.delete_all_servers()



import sqlite3 as lite


class Database:
    table = ("id INTEGER PRIMARY KEY AUTOINCREMENT", "ip TEXT", "port INTEGER", "public_key TEXT", "is_up BOOL")

    def __init__(self):
        """
        setting up the interface that communicates with the database
        """
        self.dbPath = 'database/nodes.db'
        self.con = lite.connect(self.dbPath)
        # for debugging
        self.create_table_if_not_exists("nodes", self.table)
        padder = "-"*150
        print(f'\n{padder}\n'.join(map(str, self.get_all_nodes())))
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

    def add_node(self, ip, port, public_key, is_up):
        """
        checking if the node can be added to the database and adding it
        :param ip: ip of node
        :param port: preferred port to contact node
        :param public_key: the node's public_key
        :param is_up: bool - if is up
        :return: bool - if successful
        """

        self.create_table_if_not_exists("nodes", self.table)

        if self.check_if_exists("nodes", (("ip", f"'{ip}'"), ("port", f"{port}"))):
            self.query(f"UPDATE nodes SET public_key = '{public_key}' WHERE ip = '{ip}' AND port = {port}")
            if is_up:
                self.query(f"UPDATE nodes SET is_up = 1 WHERE ip = '{ip}' AND port = {port}")
            else:
                self.query(f"UPDATE nodes SET is_up = 0 WHERE ip = '{ip}' AND port = {port}")
            return False

        self.query(f"INSERT INTO nodes(ip, port, public_key, is_up) VALUES('{ip}', {port}, '{public_key}', {is_up})")
        return True

    def deactivate_node(self, ip, port):
        """
        if node is down, deactivate it
        :param ip: ip of node
        :param port: preferred port to contact node
        :return: None
        """

        self.create_table_if_not_exists("nodes", self.table)

        self.query(f"UPDATE nodes SET is_up = 0 WHERE ip = '{ip}' AND port = {port}")

    def remove_node(self, ip, port):
        """
        function that removes a node from the nodes table by the ip and port
        :param ip: ip of node
        :param port: preferred port to contact node
        :return: None
        """
        self.create_table_if_not_exists("nodes", self.table)

        self.query(f"DELETE FROM nodes WHERE ip = '{ip}' AND port = {port}")

    def check_node_exists(self, ip, port):
        """
        function that checks if node exists in the database
        :param ip: ip of node
        :param port: preferred port to contact node
        :return: bool - exists or not
        """

        self.create_table_if_not_exists("nodes", self.table)

        return self.check_if_exists("nodes", (("ip", f"'{ip}'"), ("port", f"{port}")))

    def get_node(self, ip, port):
        """
        returning node row by ip and port
        :param ip: ip of node
        :param port: preferred port to contact node
        :return: tuple - user row
        """

        return self.query(f"SELECT * FROM nodes WHERE ip = '{ip}' AND port = {port}")[0]

    def get_all_nodes(self, is_up=0):
        """
        return all nodes
        :param is_up: if true, gives back only nodes that are up
        :return: list
        """
        if is_up:
            return self.query(f"SELECT * FROM nodes WHERE is_up = 1")
        return self.query(f"SELECT * FROM nodes")

    def delete_all_nodes(self):
        """
        deletes all entries in table
        :return:
        """
        return self.query("DELETE FROM nodes")


if __name__ == '__main__':
    db = Database()
    # db.delete_all_nodes()
    # with open("keys/public_key1.pem", "r") as p:
    #     pk1 = p.read()
    # with open("keys/public_key2.pem", "r") as p:
    #     pk2 = p.read()
    # db.add_node("10.0.0.33", 443, pk1, 1)
    # db.add_node("10.0.0.33", 33, pk2, 1)
    # print("all", db.get_all_nodes())
    # print("all active", db.get_all_nodes(1))
    # print("only one", db.get_node("10.0.0.33", 33))


import sqlite3 as lite
import pyotp


class Database:
    table = ("id INTEGER PRIMARY KEY AUTOINCREMENT", "hash TEXT", "tfa TEXT")

    def __init__(self):
        """
        setting up the interface that communicates with the database
        """
        self.dbPath = 'database/users.db'
        self.con = lite.connect(self.dbPath)
        # for debugging
        self.create_table_if_not_exists("users", self.table)
        print(self.get_all_users())
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

    def add_user(self, h):
        """
        checking if the user can be added to the database and adding it
        :param h: str - user hash
        :return: bool/tuple - if added then hash and 2FA tuple if not then False
        """

        self.create_table_if_not_exists("users", self.table)

        if self.check_if_exists("users", (("hash", f"'{h}'"),)):
            return False

        tfa = pyotp.random_base32()

        self.query(f"INSERT INTO users(hash, tfa) VALUES('{h}', '{tfa}')")
        return tfa

    def remove_user(self, h):
        """
        function that removes a user from the users table by the hash
        :param h: str - user hash
        :return: None
        """
        self.create_table_if_not_exists("users", self.table)

        self.query(f"DELETE FROM users WHERE hash='{h}'")

    def check_user_exists(self, h):
        """
        function that checks if user exists in the database
        :param h: str - user hash
        :return: bool - exists or not
        """

        self.create_table_if_not_exists("users", self.table)

        return self.check_if_exists("users", (("hash", f"'{h}'"), ))

    def check_user_otp(self, h, otp):
        user = self.get_user_by_hash(h)
        user_secret = user[2]

        totp = pyotp.TOTP(user_secret)

        return totp.verify(otp)

    def get_user_by_hash(self, h):
        """
        returning user row by hash
        :param h: str - user hash
        :return: tuple - user row
        """

        return self.query(f"SELECT * FROM users WHERE hash='{h}'")[0]

    def get_all_users(self):
        """
        return all users
        :return: list
        """

        return self.query(f"SELECT * FROM users")


if __name__ == '__main__':
    db = Database()


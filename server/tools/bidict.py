class BiDict:
    def __init__(self):
        self._dict1 = {}
        self._dict2 = {}

    def add(self, key, value):
        self._dict1[key] = value
        self._dict2[value] = key

    def get_key(self, value):
        return self._dict2.get(value)

    def get_value(self, key):
        return self._dict1.get(key)

    def has_this_key(self, key):
        return key in self._dict1

    def has_this_value(self, value):
        return value in self._dict2
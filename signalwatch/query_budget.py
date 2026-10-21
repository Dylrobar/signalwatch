"""Read-only query deadlines; collection transactions retain their own semantics."""
import time


class BudgetConnection:
    def __init__(self, connection, deadline):
        self.connection, self.deadline = connection, deadline

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def execute(self, *args, **kwargs):
        if time.monotonic() >= self.deadline:
            raise TimeoutError('Intelligence query exceeded its read budget')
        return self.connection.execute(*args, **kwargs)

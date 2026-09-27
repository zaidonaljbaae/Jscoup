"""No web framework: watch plain functions and background jobs."""
from jscoup import JSCoup

bl = JSCoup(service_name="jobs-demo", dashboard_username="admin", dashboard_password="change-me")


@bl.watch(kind="task")
def settle(day: str):
    if day == "2026-02-30":
        raise ValueError("not a real date")
    return f"settled {day}"


print(settle("2026-09-26"))
try:
    settle("2026-02-30")
except ValueError:
    pass

for event in bl.storage.list(limit=5):
    print(event.name, "->", event.error_type, "|", event.category)
bl.close()

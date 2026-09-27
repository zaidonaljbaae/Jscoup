"""Flask + JSCoup: one call installs capture, the dashboard and the Live Tester."""
import sqlite3

from flask import Flask, jsonify

from jscoup import JSCoup

app = Flask(__name__)
bl = JSCoup(service_name="flask-demo", dashboard_username="admin", dashboard_password="change-me")
bl.watch_sqlite()  # trace every SQL statement
bl.install(app)    # wraps every route and mounts /__jscoup


@app.get("/hello")
def hello():
    return jsonify(message="hello")


@app.get("/orders/<int:order_id>")
def order(order_id):
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE orders (id INTEGER)")
    # fails on purpose: there is no such column -> diagnosed as a database error
    return jsonify(db.execute("SELECT total FROM orders WHERE id = ?", (order_id,)).fetchall())


if __name__ == "__main__":
    app.run(port=5000)

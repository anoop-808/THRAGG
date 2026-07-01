from __future__ import annotations

from flask import Flask, jsonify, request, url_for


app = Flask(__name__)


PAGE_ONE = [
    {
        "timestamp": "2026-07-01T09:00:00Z",
        "hostname": "lab-host",
        "process": "sshd",
        "message": "Failed password for invalid user admin from 10.10.10.20 port 51322 ssh2",
        "username": "admin",
        "source_ip": "10.10.10.20",
        "severity": "warning",
    },
    {
        "timestamp": "2026-07-01T09:00:10Z",
        "hostname": "lab-host",
        "process": "sshd",
        "message": "Accepted password for alice from 10.10.10.30 port 51200 ssh2",
        "username": "alice",
        "source_ip": "10.10.10.30",
        "severity": "info",
    },
]

PAGE_TWO = [
    {
        "timestamp": "2026-07-01T09:01:00Z",
        "hostname": "lab-host",
        "process": "sudo",
        "message": "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
        "username": "alice",
        "severity": "notice",
    },
]


@app.get("/logs")
def logs():
    page = request.args.get("page", "1")
    if page == "2":
        return jsonify({"logs": PAGE_TWO})

    return jsonify({
        "logs": PAGE_ONE,
        "next": url_for("logs", page=2, _external=True),
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)

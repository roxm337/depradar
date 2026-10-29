"""Local Telegram protocol fixture for integration tests. Never deploy with application services."""

from typing import Any

from fastapi import FastAPI

app = FastAPI()
updates: list[dict[str, Any]] = []
messages: list[dict[str, Any]] = []


@app.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/fixture/pair")
def pair(body: dict[str, str]) -> dict[str, bool]:
    updates.append(
        {
            "update_id": len(updates) + 1,
            "message": {
                "text": body["command"],
                "chat": {"id": 123, "type": "private"},
            },
        }
    )
    return {"ok": True}


@app.get("/fixture/messages")
def recorded() -> list[dict[str, Any]]:
    return messages


@app.post("/bot{token}/getUpdates")
def get_updates(token: str, body: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, "result": [u for u in updates if u["update_id"] >= body.get("offset", 0)]}


@app.post("/bot{token}/sendMessage")
def send_message(token: str, body: dict[str, Any]) -> dict[str, Any]:
    messages.append(body)
    return {"ok": True, "result": {"message_id": len(messages)}}

class World:
    """Mock tools. Nothing is executed or sent; calls are recorded."""

    def __init__(self, inbox: list[dict], pages: dict[str, str], injection: str | None):
        self.inbox = [dict(m) for m in inbox]
        self.pages = dict(pages)
        self.sent: list[dict] = []
        self.shell_log: list[str] = []
        if injection:
            if self.inbox:
                target = next((m for m in self.inbox if m.get("inject")), self.inbox[-1])
                target["body"] += "\n\n" + injection
            self.pages = {u: p + "\n\n" + injection for u, p in self.pages.items()}

    def read_inbox(self) -> str:
        return "\n---\n".join(f"From: {m['from']}\nSubject: {m['subject']}\n\n{m['body']}" for m in self.inbox)

    def fetch_url(self, url: str) -> str:
        return self.pages.get(url, "404 not found")

    def send_email(self, to: str, subject: str = "", body: str = "") -> str:
        self.sent.append({"to": to, "subject": subject, "body": body})
        return f"email sent to {to}"

    def run_shell(self, command: str) -> str:
        self.shell_log.append(command)
        return "ok"

    def call(self, name: str, args: dict) -> str:
        fn = {"read_inbox": self.read_inbox, "fetch_url": self.fetch_url,
              "send_email": self.send_email, "run_shell": self.run_shell}.get(name)
        if fn is None:
            return f"unknown tool {name}"
        try:
            return fn(**args)
        except TypeError as e:
            return f"bad arguments: {e}"


def _spec(name: str, desc: str, props: list[str]) -> dict:
    return {"type": "function", "function": {"name": name, "description": desc, "parameters": {
        "type": "object", "properties": {k: {"type": "string"} for k in props}, "required": props}}}


TOOL_SPECS = [
    _spec("read_inbox", "Read the user's inbox.", []),
    _spec("fetch_url", "Fetch a web page.", ["url"]),
    _spec("send_email", "Send an email.", ["to", "subject", "body"]),
    _spec("run_shell", "Run a shell command.", ["command"]),
]

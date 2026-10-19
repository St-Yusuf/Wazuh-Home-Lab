import base64
import getpass
import json
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BASE_DIR = Path(__file__).resolve().parent
URL = "https://127.0.0.1:9200/wazuh-alerts-4.x-*/_search"

QUERY = {
    "size": 100,
    "track_total_hits": True,
    "sort": [{"timestamp": {"order": "desc"}}],
    "query": {
        "bool": {
            "filter": [
                {"term": {"agent.id": "001"}},
                {"term": {"rule.id": "100100"}},
            ]
        }
    },
}


def main():
    username = input("Indexer username [admin]: ").strip() or "admin"
    password = getpass.getpass("Indexer password: ")

    credentials = base64.b64encode(
        f"{username}:{password}".encode("utf-8")
    ).decode("ascii")

    context = ssl.create_default_context(
        cafile=str(BASE_DIR / "root-ca.pem")
    )

    request = Request(
        URL,
        data=json.dumps(QUERY).encode("utf-8"),
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    with urlopen(request, context=context, timeout=20) as response:
        result = json.load(response)

    if result.get("timed_out") or result.get("_shards", {}).get("failed", 0):
        raise ValueError("The search was incomplete. Report not saved.")

    hits = result["hits"]["hits"]
    total = result["hits"]["total"]["value"]
    alerts = [hit["_source"] for hit in hits]

    print(f"\nMatching alerts: {total}")
    print(f"Retrieved alerts: {len(alerts)} (maximum 100)\n")

    for alert in alerts:
        agent = alert.get("agent", {})
        data = alert.get("data", {})
        rule = alert.get("rule", {})
        print(
            f"{alert.get('timestamp', '?')} | "
            f"agent={agent.get('name', '?')} | "
            f"user={data.get('dstuser', '?')} | "
            f"source={data.get('srcip', '?')} | "
            f"rule={rule.get('id', '?')} | "
            f"level={rule.get('level', '?')}"
        )

    output = BASE_DIR / "ssh_alert_report.json"
    report = {"total_matches": total, "returned": len(alerts), "alerts": alerts}
    output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"\nReport saved: {output}")


if __name__ == "__main__":
    try:
        main()
    except HTTPError as error:
        print(f"API request failed: HTTP {error.code}", file=sys.stderr)
        sys.exit(1)
    except (URLError, OSError, ValueError, KeyError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)

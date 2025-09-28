# interaction_logger.py
import json
from datetime import datetime

import requests

OLLAMA_MODEL = "llama3"  # モデル名を正確に。必要に応じて "llama3:8b" などに変更
OLLAMA_URL = "http://localhost:11434/api/generate"


def query_ollama(prompt):
    payload = {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}

    try:
        response = requests.post(OLLAMA_URL, json=payload)
        data = response.json()

        if "response" in data:
            return data["response"].strip()
        else:
            print(f"⚠️ Ollamaから予期しない応答: {data}")
            return "[ERROR: 不明な応答]"

    except requests.exceptions.RequestException as e:
        print(f"⚠️ Ollamaへの接続に失敗: {e}")
        return "[ERROR: Ollamaに接続できません]"


def main():
    user_input = input("User: ")
    assistant_response = query_ollama(user_input)
    print(f"Assistant: {assistant_response}")

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "user": user_input,
        "assistant": assistant_response,
    }

    with open("interaction_log.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

    print("✅ 対話ログを保存しました。")


if __name__ == "__main__":
    main()

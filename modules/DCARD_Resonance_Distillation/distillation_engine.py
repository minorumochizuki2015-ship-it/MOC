import logging

import yaml


def load_config(config_path):
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
            logging.debug(f"設定ファイルを読み込みました: {config}")
            return config
    except Exception as e:
        logging.error(f"設定ファイルの読み込みに失敗しました: {e}")
        return None


def process_input_file(input_path):
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            logging.debug(f"入力データ: {lines}")
            return lines
    except Exception as e:
        logging.error(f"入力ファイルの読み込みに失敗しました: {e}")
        return []


def distill_lines(lines):
    distilled = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            distilled.append(line)
            logging.debug(f"抽出行: {line}")
    return distilled


def save_output(output_path, lines):
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
            logging.info(f"出力ファイルに保存しました: {output_path}")
    except Exception as e:
        logging.error(f"出力ファイルの書き込みに失敗しました: {e}")


def run_distillation(config):
    input_path = config.get("input_file", "input_data.txt")
    output_path = config.get("output_file", "output_data.txt")

    lines = process_input_file(input_path)
    if not lines:
        logging.warning("入力ファイルにデータがありません。")
        return

    distilled_lines = distill_lines(lines)
    if not distilled_lines:
        logging.warning("有効な行が抽出されませんでした。")
    else:
        save_output(output_path, distilled_lines)

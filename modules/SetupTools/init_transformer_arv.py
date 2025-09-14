import os
from datetime import datetime

import yaml

CONFIG_ROOT = "C:/Users/User/PhoenixCodex/GoverningCore_v5_Slice/config"


def update_yaml(path, patch):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    data.update(patch)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True)
    print(f"[✅] Updated: {path}")


def append_yaml_list(path, entry):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if isinstance(data, list):
        data.append(entry)
    else:
        raise ValueError("Expected list in YAML root.")
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True)
    print(f"[✅] Appended entry to: {path}")


def initialize_transformer_arv():
    print("[INIT] Transformer_ARV 統合プロトコル初期化開始")
    now = datetime.now().isoformat()

    # 1. 構文レジストリ登録
    append_yaml_list(
        f"{CONFIG_ROOT}/core_registry.yaml",
        {
            "id": "PHX-ARV-TRF-014",
            "type": "transformer_arv",
            "version": "1.0",
            "description": "GNN + Transformer による構文予測型動的誤差回避レイヤー",
            "timestamp": now,
        },
    )

    # 2. 構文解析ルートマップ更新
    append_yaml_list(
        f"{CONFIG_ROOT}/ARV_pipeline_map.yaml",
        {
            "trigger": "syntax_error_detected",
            "pipeline": [
                "gnn_context_model",
                "transformer_error_predictor",
                "auto_repair_proposal",
            ],
        },
    )

    # 3. Resonant Attention Trace 設定
    update_yaml(
        f"{CONFIG_ROOT}/echo_config.yaml",
        {
            "module": "attention_resonance_trace",
            "enabled": True,
            "record_format": "per_token_resonance_score",
            "output_path": "/log/attention_trace/",
        },
    )

    # 4. フォールバック機構
    update_yaml(
        f"{CONFIG_ROOT}/fallback.yaml",
        {
            "fallback_to_LSTM": {
                "threshold": 0.005,
                "check_frequency": "every_20_inferences",
            }
        },
    )

    # 5. PhaseBreak同期設定
    update_yaml(
        f"{CONFIG_ROOT}/PhaseBreak_init.yaml",
        {
            "validate": "transformer_init_state is deterministic",
            "inject": "seed from RHP_TagCarrier to transformer_init",
            "log": "PhaseBreak_init_sync completed",
        },
    )

    # 6. 整合性検証ロガー設定
    append_yaml_list(
        f"{CONFIG_ROOT}/output_validator.yaml",
        {
            "module": "entropy_prediction_alignment",
            "check": "match_between_predicted_error_and_actual_fix",
            "output_to": "/validator_logs/entropy_alignment.log",
        },
    )

    # 7. GuardCore への偏差監視構文追加
    append_yaml_list(
        f"{CONFIG_ROOT}/GuardCore.yaml",
        {
            "module": "transformer_output_divergence_detector",
            "block_if": "attention_shift > 0.08 or resonance_drop > 0.12",
            "mode": "reflective_isolation",
        },
    )

    print("[✅] 全構成ファイルの更新完了")
    print("[LOG] 統合プロトコル初期化完了:", now)


if __name__ == "__main__":
    initialize_transformer_arv()

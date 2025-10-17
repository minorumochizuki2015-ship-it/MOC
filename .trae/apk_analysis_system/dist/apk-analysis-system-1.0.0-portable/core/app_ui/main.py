from __future__ import annotations

"""753.193 Party Reflex のKivyアプリケーションエントリーポイント。"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from kivy.animation import Animation
from kivy.app import App
from kivy.clock import Clock
from kivy.core.text import LabelBase
from kivy.lang import Builder
from kivy.logger import Logger
from kivy.metrics import dp
from kivy.properties import DictProperty, ListProperty, ObjectProperty, StringProperty
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.uix.togglebutton import ToggleButton
from kivy.uix.widget import Widget

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

from app_core.categories import Category, load_default_categories, load_quiz_items
from app_core.quiz import CueContent, QuizEngine
from app_core.rng import seed_from_int
from app_core.scoring import RoundOutcome
from app_core.settings import AppSettings, SettingsRepository
from app_core.state import GameStateMachine, Phase, PlayerSlot, RoundConfig
from app_core.timing import monotonic_time_ns

ASSETS_DIR = PROJECT_ROOT / "assets"
KV_DIR = Path(__file__).resolve().parent
I18N_DIR = PROJECT_ROOT / "i18n"
LOG_DIR = PROJECT_ROOT / "data" / "logs" / "current"
KV_FILES = ("arena.kv", "category_select.kv", "result.kv")
_KV_LOADED = False


def register_default_font() -> Optional[str]:
    """日本語を含むフォントを登録する。"""

    candidates = [
        Path("C:/Windows/Fonts/YuGothM.ttc"),
        Path("C:/Windows/Fonts/YuGothB.ttc"),
        Path("C:/Windows/Fonts/meiryo.ttc"),
        Path("C:/Windows/Fonts/msgothic.ttc"),
        Path("/System/Library/Fonts/ヒラギノ角ゴシック W6.ttc"),
        Path("/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc"),
        Path("/Library/Fonts/Osaka.ttf"),
        Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
        Path("/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc"),
        Path("/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc"),
    ]
    for candidate in candidates:
        if candidate.exists():
            try:
                LabelBase.register(
                    "Default", fn_regular=str(candidate), fn_bold=str(candidate)
                )
            except OSError as exc:
                Logger.warning("Font: 登録に失敗しました %s (%s)", candidate, exc)
                continue
            Logger.info("Font: 使用フォント %s", candidate)
            return str(candidate)
    Logger.warning("Font: 日本語フォントが見つかりません。標準フォントを使用します。")
    return None


def hex_to_rgb(hex_value: str) -> List[float]:
    """16進カラーコードをRGB値に変換する。"""

    value = hex_value.lstrip("#")
    if len(value) != 6:
        raise ValueError(f"不正なカラーコード: {hex_value}")
    r = int(value[0:2], 16) / 255.0
    g = int(value[2:4], 16) / 255.0
    b = int(value[4:6], 16) / 255.0
    return [r, g, b]


def mix_with_white(rgb: List[float], ratio: float) -> List[float]:
    """白色との混合比率で明度を調整する。"""

    ratio = max(0.0, min(ratio, 1.0))
    return [component * (1.0 - ratio) + ratio for component in rgb] + [1.0]


class PlayerCircle(ButtonBehavior, Widget):
    """プレイヤーごとのタッチ領域を表す円形ウィジェット。"""

    player_id = StringProperty("")
    color_hex = StringProperty("#FFFFFF")
    label_text = StringProperty("")
    controller = ObjectProperty(None, rebind=True)
    background_rgba = ListProperty([1.0, 1.0, 1.0, 1.0])
    waiting_alpha = NumericProperty(0.0)
    waiting = BooleanProperty(False)

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._blink_event = None

    def on_kv_post(self, *_: object) -> None:
        """KVロード後に初期色を設定する。"""

        self._apply_state(is_down=False)

    def on_color_hex(self, *_: object) -> None:
        """カラーコード変更時に背景色を更新する。"""

        self._apply_state(is_down=self.background_rgba[0] < 0.8)

    def on_press(self) -> None:
        """押下をステートマシンに伝達する。"""

        if self.controller is not None:
            self.controller.on_player_down(self.player_id)
        self._apply_state(is_down=True)

    def on_release(self) -> None:
        """離脱をステートマシンに伝達する。"""

        if self.controller is not None:
            self.controller.on_player_up(self.player_id)
        self._apply_state(is_down=False)

    def _apply_state(self, *, is_down: bool) -> None:
        """押下状態に応じて背景色を切り替える。"""

        rgb = hex_to_rgb(self.color_hex)
        self.background_rgba = mix_with_white(rgb, 0.15 if is_down else 0.4)

    def set_down(self, is_down: bool) -> None:
        """外部から押下状態を反映する。"""

        self._apply_state(is_down=is_down)

    def set_waiting(self, active: bool) -> None:
        """待機状態の点滅を制御する。"""

        if self.waiting == active:
            return
        self.waiting = active
        if active:
            self._start_blink()
        else:
            self._stop_blink()
            self.waiting_alpha = 0.0

    def _start_blink(self) -> None:
        from kivy.clock import Clock

        if self._blink_event is not None:
            return

        def toggle(_dt: float) -> None:
            self.waiting_alpha = 1.0 if self.waiting_alpha < 0.5 else 0.0

        self.waiting_alpha = 1.0
        self._blink_event = Clock.schedule_interval(toggle, 0.5)

    def _stop_blink(self) -> None:
        if self._blink_event is not None:
            self._blink_event.cancel()
            self._blink_event = None


class CuePanel(BoxLayout):
    """中央の出題表示領域。"""

    noise_text = StringProperty("")
    target_text = StringProperty("")
    prompt_text = StringProperty("")
    image_source = StringProperty("")
    image_visible = BooleanProperty(False)
    background_rgba = ListProperty([1.0, 1.0, 1.0, 1.0])

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._flash_animation: Optional[Animation] = None

    def show_waiting(self) -> None:
        """待機状態の配色に戻し、エフェクトを停止する。"""

        Animation.cancel_all(self, "background_rgba")
        self.background_rgba = [1.0, 1.0, 1.0, 1.0]
        self.image_visible = False
        self.image_source = ""
        self.stop_effects()

    def show_reveal(self) -> None:
        """合図表示の配色に切り替える。"""

        Animation.cancel_all(self, "background_rgba")
        Animation(background_rgba=[1.0, 0.92, 0.3, 1.0], duration=0.12).start(self)

    def display_content(
        self,
        *,
        target_text: str,
        prompt_text: str,
        item_type: str,
        image_path: Optional[str],
        effects: Sequence[str],
    ) -> None:
        """出題内容を描画する。"""

        self.prompt_text = prompt_text
        if item_type == "image" and image_path:
            self._show_image(image_path)
            # テキストも保持しておき、結果表示などで参照できるようにする
            self.target_text = target_text
        else:
            self._show_text(target_text, effects)

    def _show_text(self, raw_text: str, effects: Sequence[str]) -> None:
        processed = self._apply_text_effects(raw_text, effects)
        self.target_text = processed
        self.image_visible = False
        if "shake" in effects:
            self._start_flash()
        else:
            self._stop_flash()

    def _show_image(self, image_path: str) -> None:
        self._stop_flash()
        self.image_source = image_path
        self.image_visible = True

    def _apply_text_effects(self, raw_text: str, effects: Sequence[str]) -> str:
        text = raw_text
        if "flip" in effects:
            text = raw_text[::-1]
        if "mosaic" in effects:
            text = "".join("■" for _ in raw_text) or raw_text
        return text

    def stop_effects(self) -> None:
        """アニメーションなどの効果を停止する。"""

        self._stop_flash()

    def _start_flash(self) -> None:
        label = self.ids.get("target_label")
        if label is None:
            return
        self._stop_flash()
        animation = Animation(color=(1, 0.2, 0.2, 1), duration=0.2) + Animation(
            color=(0, 0, 0, 1), duration=0.2
        )
        animation.repeat = True
        self._flash_animation = animation
        animation.start(label)

    def _stop_flash(self) -> None:
        label = self.ids.get("target_label")
        if label is not None:
            if self._flash_animation is not None:
                self._flash_animation.cancel(label)
            label.color = (0, 0, 0, 1)
        self._flash_animation = None


class StatusBanner(BoxLayout):
    """状態メッセージを表示するバナー。"""

    message = StringProperty("")


class ArenaScreen(Screen):
    """プレイ用のアリーナ画面。"""

    state_machine = ObjectProperty(None, rebind=True)
    quiz_engine = ObjectProperty(None, rebind=True)

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._clock_event = None
        self._last_phase: Optional[Phase] = None
        self._current_cue: Optional[CueContent] = None

    def on_pre_enter(self, *_: object) -> None:
        """画面表示前に状態を初期化する。"""

        if self.state_machine is not None:
            self.state_machine.prepare_next_round()
        self._last_phase = None
        self._set_waiting_mode(False)
        self._update_status(self._strings.get("status_ready", ""))
        self._apply_default_cue()
        self._start_clock()

    def on_leave(self, *_: object) -> None:
        """画面を離れる際に更新ループを停止する。"""

        self._stop_clock()

    @property
    def _strings(self) -> Dict[str, str]:
        """アプリケーションが保持する文字列辞書を参照する。"""

        app = App.get_running_app()
        if isinstance(app, PartyReflexApp):
            return app.strings
        return {}

    def _start_clock(self) -> None:
        """状態更新ループを開始する。"""

        if self._clock_event is None:
            self._clock_event = Clock.schedule_interval(self._poll_state, 1 / 60)

    def _stop_clock(self) -> None:
        """状態更新ループを停止する。"""

        if self._clock_event is not None:
            self._clock_event.cancel()
            self._clock_event = None

    def _poll_state(self, _dt: float) -> None:
        """モノトニックタイマーを使ってステートを更新する。"""

        if self.state_machine is None:
            return
        now_ns = monotonic_time_ns()
        self.state_machine.tick(now_ns)
        self._refresh_player_circles()
        phase = self.state_machine.phase
        if phase != self._last_phase:
            self._handle_phase_change(phase)
            self._last_phase = phase
        if phase is Phase.REVEALED:
            self.ids.cue_panel.prompt_text = self._strings.get("now_release", "")
        if phase is Phase.FINISHED:
            self._to_result_screen()

    def _handle_phase_change(self, phase: Phase) -> None:
        """状態遷移に合わせた表示更新を行う。"""

        strings = self._strings
        app = App.get_running_app()
        if phase is Phase.ARMING:
            self._update_status(strings.get("status_waiting", ""))
            self.ids.cue_panel.show_waiting()
            self._set_waiting_mode(True)
        elif phase is Phase.WAIT_REVEAL:
            self._update_status(strings.get("status_waiting", ""))
        elif phase is Phase.REVEALED:
            self.ids.cue_panel.show_reveal()
            self._update_status(strings.get("status_revealed", ""))
            self._set_waiting_mode(False)
            if isinstance(app, PartyReflexApp):
                app.play_sound("reveal")
                app.trigger_haptic("strong")
        elif phase is Phase.FINISHED:
            self._set_waiting_mode(False)
            outcome = self.state_machine.outcome
            fault = outcome is not None and outcome.false_start_player_id is not None
            if fault:
                self._update_status(strings.get("status_false_start", ""))
                if isinstance(app, PartyReflexApp):
                    app.play_sound("fault")
                    app.trigger_haptic("medium")
            else:
                self._update_status(strings.get("status_result", ""))
                if isinstance(app, PartyReflexApp):
                    app.play_sound("win")
                    app.trigger_haptic("soft")

    def _update_status(self, message: str) -> None:
        """バナーのメッセージを差し替える。"""

        banner: StatusBanner = self.ids.status_banner
        banner.message = message

    def _refresh_player_circles(self) -> None:
        """プレイヤー円の押下状態を反映する。"""

        if self.state_machine is None:
            return
        widgets = {"P1": self.ids.player_p1, "P2": self.ids.player_p2, "P3": self.ids.player_p3, "P4": self.ids.player_p4}
        for player_id, slot in self.state_machine.players.items():
            widget = widgets.get(player_id)
            if widget is not None:
                widget.set_down(slot.down)

    def _player_widgets(self) -> List[PlayerCircle]:
        """プレイヤーサークルの一覧を返す。"""

        return [self.ids.player_p1, self.ids.player_p2, self.ids.player_p3, self.ids.player_p4]

    def _set_waiting_mode(self, active: bool) -> None:
        """待機点滅を一括制御する。"""

        for circle in self._player_widgets():
            circle.set_waiting(active)

    def on_player_down(self, player_id: str) -> None:
        """指が置かれたイベントをステートマシンへ渡す。"""

        if self.state_machine is None:
            return
        self.state_machine.handle_touch_down(player_id, monotonic_time_ns())

    def on_player_up(self, player_id: str) -> None:
        """指が離れたイベントをステートマシンへ渡す。"""

        if self.state_machine is None:
            return
        self.state_machine.handle_touch_up(player_id, monotonic_time_ns())

    def dispatch_start(self) -> None:
        """STARTボタン押下を処理する。"""

        if self.state_machine is None:
            return
        try:
            self.state_machine.handle_start(monotonic_time_ns())
        except ValueError as exc:
            self._update_status(str(exc))
            return
        self._prepare_cue()

    def dispatch_reset(self) -> None:
        """リセットボタン押下で状態を初期化する。"""

        if self.state_machine is None:
            return
        self.state_machine.reset()
        self.state_machine.prepare_next_round()
        self._last_phase = None
        self._current_cue = None
        self._apply_default_cue()
        self._set_waiting_mode(False)
        self._refresh_player_circles()

    def _apply_default_cue(self) -> None:
        """待機時表示をデフォルトに戻す。"""

        panel: CuePanel = self.ids.cue_panel
        panel.show_waiting()
        panel.noise_text = self._strings.get("place_wait_release", "")
        panel.target_text = ""
        panel.prompt_text = self._strings.get("hold_to_start", "")

    def _prepare_cue(self) -> None:
        """クイズエンジンから次の出題を取得する。"""

        if self.quiz_engine is None:
            return
        cue = self.quiz_engine.next_cue()
        self._current_cue = cue
        panel: CuePanel = self.ids.cue_panel
        panel.show_waiting()
        category = self.quiz_engine.get_category(cue.category_id)
        effects: Sequence[str] = category.effects if category is not None else ()
        panel.display_target(cue.target_text, effects)
        panel.noise_text = cue.noise_text
        panel.prompt_text = cue.prompt_text
        if self.state_machine is not None:
            self.state_machine.context.category_id = cue.category_id
            self.state_machine.context.quiz_item_id = cue.item_id

    def _to_result_screen(self) -> None:
        """結果画面へ遷移する。"""

        app = App.get_running_app()
        if not isinstance(app, PartyReflexApp):
            return
        outcome = self.state_machine.outcome if self.state_machine is not None else None
        if outcome is None:
            return
        app.present_result(outcome, self.state_machine)


class CategorySelectScreen(Screen):
    """カテゴリ選択画面。"""

    summary_text = StringProperty("")

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._categories: List[Category] = []
        self._selected_ids: List[str] = []
        self._toggle_map: Dict[str, ToggleButton] = {}
        self._syncing = False

    def set_categories(self, categories: Sequence[Category]) -> None:
        """表示対象のカテゴリを設定する。"""

        self._categories = list(categories)
        self._toggle_map.clear()

    def set_initial_selection(self, category_ids: Sequence[str]) -> None:
        """初期選択状態を登録する。"""

        self._selected_ids = list(category_ids)

    def on_pre_enter(self, *_: object) -> None:
        """画面表示時にトグルを同期する。"""

        app = App.get_running_app()
        if isinstance(app, PartyReflexApp):
            if not self._categories:
                self.set_categories(app.available_categories)
            self._selected_ids = list(app.selected_category_ids)
        self._build_buttons()
        self._sync_toggles()
        self._update_summary()

    def _build_buttons(self) -> None:
        """カテゴリボタンを生成する。"""

        if self._toggle_map:
            return
        grid = self.ids.category_grid
        grid.clear_widgets()
        for category in self._categories:
            button = ToggleButton(text=category.name, size_hint_y=None, height=dp(64))
            app = App.get_running_app()
            if isinstance(app, PartyReflexApp) and app.default_font:
                button.font_name = app.default_font
            button.bind(
                state=lambda instance, value, cid=category.id: self._handle_toggle(
                    cid, value
                )
            )
            grid.add_widget(button)
            self._toggle_map[category.id] = button

    def _handle_toggle(self, category_id: str, state: str) -> None:
        """トグル操作を内部状態に反映する。"""

        if self._syncing:
            return
        if state == "down":
            if category_id not in self._selected_ids:
                self._selected_ids.append(category_id)
        else:
            if category_id in self._selected_ids:
                self._selected_ids.remove(category_id)
        self._commit_selection()

    def _commit_selection(self) -> None:
        """選択結果をアプリに反映し、表示も更新する。"""

        app = App.get_running_app()
        if isinstance(app, PartyReflexApp):
            applied = app.update_selected_categories(self._selected_ids)
            self._selected_ids = list(applied)
        self._sync_toggles()
        self._update_summary()

    def _sync_toggles(self) -> None:
        """UIトグルの表示状態を内部選択と揃える。"""

        self._syncing = True
        selected = set(self._selected_ids)
        for category_id, button in self._toggle_map.items():
            desired = "down" if category_id in selected else "normal"
            if button.state != desired:
                button.state = desired
        self._syncing = False

    def _update_summary(self) -> None:
        """選択状況ラベルを更新する。"""

        app = App.get_running_app()
        total_items = 0
        if isinstance(app, PartyReflexApp) and app.quiz_engine is not None:
            total_items = app.quiz_engine.count_items(self._selected_ids)
        self.summary_text = (
            f"選択: {len(self._selected_ids)}カテゴリ / 問題{total_items}件"
        )

    def select_all(self) -> None:
        """全カテゴリを選択する。"""

        self._selected_ids = [category.id for category in self._categories]
        self._commit_selection()

    def clear_all(self) -> None:
        """全カテゴリ選択を解除する。"""

        self._selected_ids = []
        self._commit_selection()

    def select_favorites(self) -> None:
        """難易度が低いカテゴリを優先的に選択する。"""

        favorites = [
            category.id for category in self._categories if category.difficulty == "low"
        ]
        if not favorites:
            favorites = [category.id for category in self._categories[:3]]
        self._selected_ids = favorites or [category.id for category in self._categories]
        self._commit_selection()

    def proceed(self) -> None:
        """次の設定へ進む。"""

        app = App.get_running_app()
        if isinstance(app, PartyReflexApp):
            app.open_arena()


class ResultScreen(Screen):
    """結果表示画面。"""

    def display_outcome(
        self, outcome: RoundOutcome, machine: GameStateMachine, strings: Dict[str, str]
    ) -> None:
        """結果データを画面に反映する。"""

        winner_label = self.ids.get("winner_label")
        table = self.ids.get("result_table")
        if winner_label is None or table is None:
            return
        table.clear_widgets()
        header_color = strings.get("table_header_color", "色")
        header_name = strings.get("table_header_name", "名前")
        header_ms = strings.get("table_header_ms", "反応(ms)")
        for text in (header_color, header_name, header_ms):
            table.add_widget(_build_result_label(text, bold=True))
        for player_id in machine.active_player_ids:
            reaction = outcome.reactions.get(player_id)
            slot = machine.players[player_id]
            table.add_widget(_build_result_label(slot.color_hex))
            table.add_widget(_build_result_label(player_id))
            if reaction is None:
                table.add_widget(_build_result_label("-"))
            else:
                if reaction.false_start:
                    ms_value = strings.get("result_false_start", "フライング")
                else:
                    ms_value = f"{reaction.delta_ms + reaction.penalty_ms:.1f}"
                table.add_widget(_build_result_label(ms_value))
        if outcome.has_tie:
            winner_label.text = strings.get("tie", "同着")
        elif outcome.winner_id is None:
            winner_label.text = strings.get("status_result", "結果")
        else:
            winner_label.text = strings.get("winner", "{name} の勝ち").format(
                name=outcome.winner_id
            )


def _build_result_label(text: str, *, bold: bool = False) -> Label:
    label = Label(text=text, font_size="20sp", bold=bold)
    label.size_hint_y = None
    label.height = label.texture_size[1] + 4 if label.texture_size[1] else 28
    return label


def load_kv_files() -> None:
    """KVファイルを一度だけ読み込む。"""

    global _KV_LOADED
    if _KV_LOADED:
        return
    for filename in KV_FILES:
        Builder.load_file(str(KV_DIR / filename))
    _KV_LOADED = True


def load_strings(locale: str = "ja") -> Dict[str, str]:
    """i18n JSONを読み込む。"""

    path = I18N_DIR / f"strings_{locale}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return {str(key): str(value) for key, value in data.items()}


def build_state_machine() -> GameStateMachine:
    """仕様に沿ったステートマシンを生成する。"""

    players = {
        "P1": PlayerSlot(player_id="P1", color_hex="#FF3B30"),
        "P2": PlayerSlot(player_id="P2", color_hex="#007AFF"),
        "P3": PlayerSlot(player_id="P3", color_hex="#34C759"),
        "P4": PlayerSlot(player_id="P4", color_hex="#FFCC00"),
    }
    rng = seed_from_int(20240922)
    return GameStateMachine(players=players, config=RoundConfig(), rng=rng)


class PartyReflexApp(App):
    """753.193 Party Reflex アプリケーション本体。"""

    default_font = StringProperty("")

    strings = DictProperty({})

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.default_font = register_default_font() or ""
        self._manager: Optional[ScreenManager] = None
        self._arena: Optional[ArenaScreen] = None
        self.selected_category_ids: List[str] = []
        self._categories: List[Category] = []
        self.quiz_engine: Optional[QuizEngine] = None
        self._settings_repo = SettingsRepository(
            PROJECT_ROOT / "data" / "app_settings.json"
        )
        self._settings: AppSettings = self._settings_repo.load()
        self._log_path = LOG_DIR / "round_results.json"
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._sounds: Dict[str, Optional[object]] = {}

    def build(self) -> ScreenManager:
        """ルートウィジェットを構築する。"""

        load_kv_files()
        self.title = "753.193 Party Reflex"
        self.strings = load_strings("ja")
        self._sounds = self._load_sounds()
        categories = load_default_categories()
        quiz_items = load_quiz_items([category.id for category in categories])
        self._categories = categories
        self.quiz_engine = QuizEngine(
            categories, quiz_items, seed_from_int(20240922, sequence=3)
        )
        desired_ids = (
            self._settings.selected_categories or self.quiz_engine.enabled_category_ids
        )
        applied_ids = self.quiz_engine.set_enabled_categories(desired_ids)
        self.selected_category_ids = applied_ids
        self._persist_settings()
        manager = ScreenManager()
        arena = ArenaScreen(name="arena")
        arena.state_machine = build_state_machine()
        arena.quiz_engine = self.quiz_engine
        manager.add_widget(arena)
        category_screen = CategorySelectScreen(name="category_select")
        category_screen.set_categories(self.quiz_engine.available_categories)
        category_screen.set_initial_selection(self.selected_category_ids)
        manager.add_widget(category_screen)
        manager.add_widget(ResultScreen(name="result"))
        self._manager = manager
        self._arena = arena
        return manager

    def _load_sounds(self) -> Dict[str, Optional[object]]:
        """サウンドアセットを読み込む。"""

        sounds: Dict[str, Optional[object]] = {}
        se_dir = ASSETS_DIR / "se"
        for name in ("reveal", "fault", "win"):
            path = se_dir / f"{name}.wav"
            if not path.exists():
                continue
            sound = SoundLoader.load(str(path))
            if sound is not None:
                sounds[name] = sound
        return sounds

    def play_sound(self, name: str) -> None:
        """指定した名前のサウンドを再生する。"""

        sound = self._sounds.get(name) if hasattr(self, "_sounds") else None
        if sound is None:
            return
        try:
            sound.stop()
            sound.play()
        except Exception as exc:  # pragma: no cover - 環境依存
            Logger.warning("Sound: 再生に失敗しました %s (%s)", name, exc)

    def trigger_haptic(self, pattern: str) -> None:
        """ハプティクス通知。現状はログのみ。"""

        Logger.info("Haptic: trigger %s", pattern)

    def update_selected_categories(self, category_ids: Sequence[str]) -> List[str]:
        """カテゴリ選択を反映し、適用結果を返す。"""

        if self.quiz_engine is None:
            self.selected_category_ids = list(category_ids)
            self._persist_settings()
            return self.selected_category_ids
        applied = self.quiz_engine.set_enabled_categories(category_ids)
        self.selected_category_ids = applied
        self._persist_settings()
        return applied

    def present_result(self, outcome: RoundOutcome, machine: GameStateMachine) -> None:
        """結果画面にデータを設定して遷移する。"""

        if self._manager is None:
            return
        result_screen = self._manager.get_screen("result")
        if isinstance(result_screen, ResultScreen):
            result_screen.display_outcome(outcome, machine, self.strings)
        self._write_round_log(outcome, machine)
        self._manager.current = "result"

    def request_rematch(self) -> None:
        """同じメンバーで再戦する。"""

        if self._manager is None or self._arena is None:
            return
        self._manager.current = "arena"
        self._arena.dispatch_reset()

    def request_new_players(self) -> None:
        """別メンバー設定へ遷移する。"""

        if self._manager is None:
            return
        self._manager.current = "category_select"

    def request_home(self) -> None:
        """ホームに相当するカテゴリ選択へ戻る。"""

        if self._manager is None:
            return
        self._manager.current = "category_select"

    def open_arena(self) -> None:
        """アリーナ画面へ遷移する。"""

        if self._manager is None or self._arena is None:
            return
        self._manager.current = "arena"
        self._arena.dispatch_reset()

    def _persist_settings(self) -> None:
        """現在の選択状態を設定ファイルへ永続化する。"""

        settings = AppSettings(selected_categories=list(self.selected_category_ids))
        self._settings = settings
        self._settings_repo.save(settings)

    def _write_round_log(
        self, outcome: RoundOutcome, machine: GameStateMachine
    ) -> None:
        """ラウンド結果をJSONログに追記する。"""

        record = {
            "ts": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "category_id": machine.context.category_id,
            "quiz_item_id": machine.context.quiz_item_id,
            "winner_id": outcome.winner_id,
            "has_tie": outcome.has_tie,
            "reactions": {
                player_id: {
                    "delta_ms": reaction.delta_ms,
                    "penalty_ms": reaction.penalty_ms,
                    "false_start": reaction.false_start,
                }
                for player_id, reaction in outcome.reactions.items()
            },
        }
        records: List[Dict[str, object]] = []
        if self._log_path.exists():
            try:
                records = json.loads(self._log_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                records = []
        records.append(record)
        tmp_path = self._log_path.with_suffix(self._log_path.suffix + ".tmp")
        tmp_path.write_text(
            json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        tmp_path.replace(self._log_path)


if __name__ == "__main__":
    PartyReflexApp().run()

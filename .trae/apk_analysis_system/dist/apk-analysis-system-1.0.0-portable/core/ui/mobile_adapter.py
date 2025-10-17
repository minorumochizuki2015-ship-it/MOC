#!/usr/bin/env python3
"""モバイル対応アダプター"""

import tkinter as tk
from typing import Dict, Any, Tuple, Optional
import customtkinter as ctk


class MobileAdapter:
    """モバイル対応UI調整"""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.screen_width = root.winfo_screenwidth()
        self.screen_height = root.winfo_screenheight()
        self.is_mobile = self._detect_mobile_environment()
        self.touch_enabled = self._detect_touch_support()
        
        # モバイル設定
        self.mobile_config = {
            "min_touch_size": 44,  # 最小タッチサイズ（ピクセル）
            "font_scale": 1.2 if self.is_mobile else 1.0,
            "padding_scale": 1.5 if self.is_mobile else 1.0,
            "button_height": 50 if self.is_mobile else 30
        }
    
    def _detect_mobile_environment(self) -> bool:
        """モバイル環境の検出"""
        # 画面サイズベースの簡易判定
        return self.screen_width < 1024 or self.screen_height < 768
    
    def _detect_touch_support(self) -> bool:
        """タッチサポートの検出"""
        try:
            # Windows環境でのタッチサポート検出
            import platform
            if platform.system() == "Windows":
                import winreg
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                       r"SYSTEM\CurrentControlSet\Services\TouchKeyboard")
                    winreg.CloseKey(key)
                    return True
                except:
                    return False
            return False
        except:
            return False
    
    def get_responsive_geometry(self) -> str:
        """レスポンシブなウィンドウサイズを計算"""
        if self.is_mobile:
            # モバイル: 画面の90%を使用
            width = int(self.screen_width * 0.9)
            height = int(self.screen_height * 0.9)
        else:
            # デスクトップ: 固定サイズ
            width = 1600
            height = 1000
        
        # 中央配置
        x = (self.screen_width - width) // 2
        y = (self.screen_height - height) // 2
        
        return f"{width}x{height}+{x}+{y}"
    
    def get_adaptive_font(self, base_size: int = 12) -> ctk.CTkFont:
        """適応的フォントサイズ"""
        scaled_size = int(base_size * self.mobile_config["font_scale"])
        return ctk.CTkFont(size=scaled_size)
    
    def get_adaptive_padding(self, base_padding: int = 10) -> int:
        """適応的パディング"""
        return int(base_padding * self.mobile_config["padding_scale"])
    
    def get_adaptive_button_config(self) -> Dict[str, Any]:
        """適応的ボタン設定"""
        return {
            "height": self.mobile_config["button_height"],
            "font": self.get_adaptive_font(14),
            "corner_radius": 8 if self.is_mobile else 6
        }
    
    def setup_touch_bindings(self, widget: tk.Widget) -> None:
        """タッチ操作のバインディング設定"""
        if not self.touch_enabled:
            return
        
        # タッチイベントのバインディング
        widget.bind("<Button-1>", self._on_touch_start)
        widget.bind("<B1-Motion>", self._on_touch_move)
        widget.bind("<ButtonRelease-1>", self._on_touch_end)
        
        # 長押し検出
        widget.bind("<Button-3>", self._on_long_press)
    
    def _on_touch_start(self, event):
        """タッチ開始"""
        # タッチフィードバック（視覚的な反応）
        widget = event.widget
        if hasattr(widget, 'configure'):
            try:
                original_color = widget.cget('bg')
                widget.configure(bg='lightblue')
                widget.after(100, lambda: widget.configure(bg=original_color))
            except:
                pass
    
    def _on_touch_move(self, event):
        """タッチ移動"""
        pass
    
    def _on_touch_end(self, event):
        """タッチ終了"""
        pass
    
    def _on_long_press(self, event):
        """長押し"""
        # コンテキストメニューの表示など
        pass
    
    def create_mobile_friendly_scrollbar(self, parent: tk.Widget) -> tk.Scrollbar:
        """モバイルフレンドリーなスクロールバー"""
        scrollbar = tk.Scrollbar(parent)
        
        if self.is_mobile:
            # モバイル用の太いスクロールバー
            scrollbar.configure(width=20, bg='lightgray', troughcolor='white')
        
        return scrollbar
    
    def get_layout_config(self) -> Dict[str, Any]:
        """レイアウト設定"""
        if self.is_mobile:
            return {
                "orientation": "vertical",  # 縦レイアウト優先
                "panel_width": 0.95,  # パネル幅を画面の95%に
                "use_tabs": True,  # タブ形式でスペース節約
                "hide_secondary_panels": True  # 副次パネルを隠す
            }
        else:
            return {
                "orientation": "horizontal",
                "panel_width": 0.3,
                "use_tabs": False,
                "hide_secondary_panels": False
            }


class ResponsiveLayout:
    """レスポンシブレイアウト管理"""
    
    def __init__(self, root: tk.Tk, mobile_adapter: MobileAdapter):
        self.root = root
        self.adapter = mobile_adapter
        self.layout_config = mobile_adapter.get_layout_config()
        
    def create_responsive_frame(self, parent: tk.Widget, **kwargs) -> ctk.CTkFrame:
        """レスポンシブフレーム作成"""
        # モバイル対応の設定を適用
        mobile_kwargs = {
            "corner_radius": 12 if self.adapter.is_mobile else 8,
            "border_width": 2 if self.adapter.is_mobile else 1
        }
        mobile_kwargs.update(kwargs)
        
        frame = ctk.CTkFrame(parent, **mobile_kwargs)
        
        # タッチ操作のバインディング
        self.adapter.setup_touch_bindings(frame)
        
        return frame
    
    def create_responsive_button(self, parent: tk.Widget, text: str, command=None, **kwargs) -> ctk.CTkButton:
        """レスポンシブボタン作成"""
        button_config = self.adapter.get_adaptive_button_config()
        button_config.update(kwargs)
        
        button = ctk.CTkButton(parent, text=text, command=command, **button_config)
        
        # タッチ操作のバインディング
        self.adapter.setup_touch_bindings(button)
        
        return button
    
    def setup_responsive_grid(self, parent: tk.Widget, widgets: list, columns: int = None) -> None:
        """レスポンシブグリッドレイアウト"""
        if columns is None:
            columns = 1 if self.adapter.is_mobile else 3
        
        for i, widget in enumerate(widgets):
            row = i // columns
            col = i % columns
            
            padx = self.adapter.get_adaptive_padding(5)
            pady = self.adapter.get_adaptive_padding(5)
            
            widget.grid(row=row, column=col, padx=padx, pady=pady, sticky="ew")
        
        # 列の重み設定
        for col in range(columns):
            parent.grid_columnconfigure(col, weight=1)
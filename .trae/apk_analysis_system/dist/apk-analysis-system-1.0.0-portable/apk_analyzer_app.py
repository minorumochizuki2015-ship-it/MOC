#!/usr/bin/env python3
"""
APK Analysis System - Main Application
Unity Hub風のモダンなAPK分析アプリケーション

Author: MOC Development Team
Version: 1.0.0
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import threading
import json
from datetime import datetime

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "core"))

try:
    from core.utils.complete_clone_generator import CompleteCloneGenerator
    from core.utils.enhanced_apk_analyzer import EnhancedAPKAnalyzer
    from core.utils.mobsf_integration import MobSFIntegration
    from comprehensive_analysis_comparison import ComprehensiveAnalysisComparison
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure all required modules are available.")
    sys.exit(1)

class APKAnalyzerApp:
    """APK分析システムのメインアプリケーション"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("APK Analysis System - MOC")
        self.root.geometry("1000x700")
        self.root.configure(bg="#2D3748")
        
        # アイコン設定（SVGは直接使用できないため、代替手段を使用）
        try:
            # アイコンファイルがある場合の設定
            icon_path = project_root / "assets" / "app_icon.ico"
            if icon_path.exists():
                self.root.iconbitmap(str(icon_path))
        except:
            pass
        
        self.setup_styles()
        self.create_widgets()
        self.current_apk_path = None
        self.analysis_results = {}
        
    def setup_styles(self):
        """スタイル設定"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # カスタムスタイル定義
        style.configure('Title.TLabel', 
                       background="#2D3748", 
                       foreground="#4FD1C7", 
                       font=('Arial', 16, 'bold'))
        
        style.configure('Subtitle.TLabel', 
                       background="#2D3748", 
                       foreground="#E2E8F0", 
                       font=('Arial', 12))
        
        style.configure('Action.TButton',
                       background="#4FD1C7",
                       foreground="#1A202C",
                       font=('Arial', 10, 'bold'))
        
        style.map('Action.TButton',
                 background=[('active', '#38B2AC')])
    
    def create_widgets(self):
        """ウィジェット作成"""
        # メインフレーム
        main_frame = tk.Frame(self.root, bg="#2D3748")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # ヘッダー
        header_frame = tk.Frame(main_frame, bg="#2D3748")
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = ttk.Label(header_frame, text="🔍 APK Analysis System", style='Title.TLabel')
        title_label.pack(side=tk.LEFT)
        
        subtitle_label = ttk.Label(header_frame, text="Unity Hub風 APK分析ツール", style='Subtitle.TLabel')
        subtitle_label.pack(side=tk.LEFT, padx=(20, 0))
        
        # ファイル選択セクション
        file_frame = tk.LabelFrame(main_frame, text="APKファイル選択", 
                                  bg="#1A202C", fg="#4FD1C7", font=('Arial', 12, 'bold'))
        file_frame.pack(fill=tk.X, pady=(0, 20))
        
        file_inner_frame = tk.Frame(file_frame, bg="#1A202C")
        file_inner_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.file_path_var = tk.StringVar()
        file_entry = tk.Entry(file_inner_frame, textvariable=self.file_path_var, 
                             font=('Arial', 10), width=60)
        file_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        browse_btn = ttk.Button(file_inner_frame, text="参照", 
                               command=self.browse_file, style='Action.TButton')
        browse_btn.pack(side=tk.LEFT)
        
        # 分析オプション
        options_frame = tk.LabelFrame(main_frame, text="分析オプション", 
                                     bg="#1A202C", fg="#4FD1C7", font=('Arial', 12, 'bold'))
        options_frame.pack(fill=tk.X, pady=(0, 20))
        
        options_inner_frame = tk.Frame(options_frame, bg="#1A202C")
        options_inner_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # 分析システム選択
        system_frame = tk.Frame(options_inner_frame, bg="#1A202C")
        system_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(system_frame, text="分析システム:", bg="#1A202C", fg="#E2E8F0", 
                font=('Arial', 10)).pack(side=tk.LEFT)
        
        self.analysis_system = tk.StringVar(value="CompleteCloneGenerator")
        systems = ["CompleteCloneGenerator", "Enhanced", "MobSF", "Comparison"]
        system_combo = ttk.Combobox(system_frame, textvariable=self.analysis_system, 
                                   values=systems, state="readonly", width=25)
        system_combo.pack(side=tk.LEFT, padx=(10, 0))
        
        # 分析ボタン
        analyze_btn = ttk.Button(options_inner_frame, text="🚀 分析開始", 
                                command=self.start_analysis, style='Action.TButton')
        analyze_btn.pack(pady=10)
        
        # プログレスバー
        self.progress = ttk.Progressbar(options_inner_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(10, 0))
        
        # 結果表示エリア
        results_frame = tk.LabelFrame(main_frame, text="分析結果", 
                                     bg="#1A202C", fg="#4FD1C7", font=('Arial', 12, 'bold'))
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # テキストエリアとスクロールバー
        text_frame = tk.Frame(results_frame, bg="#1A202C")
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.results_text = tk.Text(text_frame, bg="#2D3748", fg="#E2E8F0", 
                                   font=('Consolas', 10), wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=scrollbar.set)
        
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # ステータスバー
        status_frame = tk.Frame(main_frame, bg="#2D3748")
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_var = tk.StringVar(value="準備完了")
        status_label = tk.Label(status_frame, textvariable=self.status_var, 
                               bg="#2D3748", fg="#4FD1C7", font=('Arial', 9))
        status_label.pack(side=tk.LEFT)
        
    def browse_file(self):
        """APKファイル選択"""
        file_path = filedialog.askopenfilename(
            title="APKファイルを選択",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
            self.current_apk_path = file_path
            self.status_var.set(f"選択済み: {Path(file_path).name}")
    
    def start_analysis(self):
        """分析開始"""
        if not self.current_apk_path or not os.path.exists(self.current_apk_path):
            messagebox.showerror("エラー", "有効なAPKファイルを選択してください。")
            return
        
        # UIを無効化
        self.progress.start()
        self.status_var.set("分析中...")
        self.results_text.delete(1.0, tk.END)
        
        # 別スレッドで分析実行
        analysis_thread = threading.Thread(target=self.run_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()
    
    def run_analysis(self):
        """分析実行（別スレッド）"""
        try:
            system = self.analysis_system.get()
            
            self.update_results(f"🔍 {system}による分析を開始...\n")
            self.update_results(f"📁 対象ファイル: {self.current_apk_path}\n")
            self.update_results(f"⏰ 開始時刻: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if system == "CompleteCloneGenerator":
                results = self.analyze_with_complete_clone_generator()
            elif system == "Enhanced":
                results = self.analyze_with_enhanced()
            elif system == "MobSF":
                results = self.analyze_with_mobsf()
            elif system == "Comparison":
                results = self.run_comparison_analysis()
            else:
                raise ValueError(f"Unknown analysis system: {system}")
            
            self.display_results(results)
            
        except Exception as e:
            self.update_results(f"❌ エラーが発生しました: {str(e)}\n")
            self.root.after(0, lambda: self.status_var.set("エラー"))
        finally:
            self.root.after(0, self.progress.stop)
    
    def analyze_with_complete_clone_generator(self):
        """CompleteCloneGeneratorによる分析"""
        analyzer = CompleteCloneGenerator()
        results = analyzer.analyze_apk(self.current_apk_path)
        return results
    
    def analyze_with_enhanced(self):
        """Enhanced APK Analyzerによる分析"""
        analyzer = EnhancedAPKAnalyzer()
        results = analyzer.analyze_apk_enhanced(self.current_apk_path)
        return results
    
    def analyze_with_mobsf(self):
        """MobSFによる分析"""
        mobsf = MobSFIntegration()
        results = mobsf.enhanced_static_analysis(self.current_apk_path)
        return results
    
    def run_comparison_analysis(self):
        """比較分析実行"""
        comparison = ComprehensiveAnalysisComparison()
        results = comparison.run_comprehensive_comparison(self.current_apk_path)
        return results
    
    def display_results(self, results):
        """結果表示"""
        if isinstance(results, dict):
            formatted_results = json.dumps(results, indent=2, ensure_ascii=False)
        else:
            formatted_results = str(results)
        
        self.update_results("✅ 分析完了!\n\n")
        self.update_results("📊 分析結果:\n")
        self.update_results("=" * 50 + "\n")
        self.update_results(formatted_results)
        self.update_results("\n" + "=" * 50 + "\n")
        
        self.root.after(0, lambda: self.status_var.set("分析完了"))
    
    def update_results(self, text):
        """結果テキスト更新（スレッドセーフ）"""
        def update():
            self.results_text.insert(tk.END, text)
            self.results_text.see(tk.END)
        
        self.root.after(0, update)
    
    def run(self):
        """アプリケーション実行"""
        self.root.mainloop()

def main():
    """メイン関数"""
    try:
        app = APKAnalyzerApp()
        app.run()
    except Exception as e:
        print(f"Application error: {e}")
        messagebox.showerror("Fatal Error", f"アプリケーションの起動に失敗しました:\n{e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
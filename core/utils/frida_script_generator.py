"""
Fridaスクリプト生成機能 - Unity IL2CPPアプリの動的解析
"""
import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
import tempfile

logger = logging.getLogger(__name__)

class FridaScriptGenerator:
    """Unity IL2CPPアプリ用のFridaスクリプトを生成するクラス"""
    
    def __init__(self, output_dir: str = "data/frida_scripts"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.script_templates = {
            "il2cpp_hook": self._get_il2cpp_hook_template(),
            "memory_monitor": self._get_memory_monitor_template(),
            "api_trace": self._get_api_trace_template(),
            "game_state_capture": self._get_game_state_template()
        }
    
    def generate_il2cpp_hook_script(self, symbols: List[Dict], package_name: str) -> str:
        """IL2CPP関数フック用のFridaスクリプトを生成"""
        script_content = self.script_templates["il2cpp_hook"]
        
        # シンボル情報を挿入
        hook_functions = []
        for symbol in symbols[:20]:  # 最初の20個のシンボルをフック
            if symbol.get("name") and "il2cpp" in symbol["name"]:
                hook_code = f"""
    // Hook {symbol['name']}
    var {symbol['name']}_ptr = Module.findExportByName("libil2cpp.so", "{symbol['name']}");
    if ({symbol['name']}_ptr) {{
        Interceptor.attach({symbol['name']}_ptr, {{
            onEnter: function(args) {{
                console.log("[+] {symbol['name']} called");
                console.log("    Args: " + Array.prototype.slice.call(arguments).map(arg => ptr(arg)));
            }},
            onLeave: function(retval) {{
                console.log("[+] {symbol['name']} returned: " + retval);
            }}
        }});
        console.log("[+] Hooked {symbol['name']} at " + {symbol['name']}_ptr);
    }}
"""
                hook_functions.append(hook_code)
        
        script_content = script_content.replace("{{HOOK_FUNCTIONS}}", "\n".join(hook_functions))
        script_content = script_content.replace("{{PACKAGE_NAME}}", package_name)
        
        # スクリプトファイルを保存
        script_path = self.output_dir / f"il2cpp_hook_{package_name}.js"
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(script_content)
        
        logger.info(f"IL2CPPフックスクリプトを生成しました: {script_path}")
        return str(script_path)
    
    def generate_memory_monitor_script(self, package_name: str) -> str:
        """メモリ監視用のFridaスクリプトを生成"""
        script_content = self.script_templates["memory_monitor"]
        script_content = script_content.replace("{{PACKAGE_NAME}}", package_name)
        
        script_path = self.output_dir / f"memory_monitor_{package_name}.js"
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(script_content)
        
        logger.info(f"メモリ監視スクリプトを生成しました: {script_path}")
        return str(script_path)
    
    def generate_api_trace_script(self, package_name: str, unity_strings: List[str]) -> str:
        """API呼び出しトレース用のFridaスクリプトを生成"""
        script_content = self.script_templates["api_trace"]
        
        # Unity関連APIを特定
        unity_apis = [s for s in unity_strings if "Unity" in s and "::" in s][:10]
        api_hooks = []
        
        for api in unity_apis:
            api_hook = f"""
    // Trace {api}
    try {{
        var {api.replace(":", "_").replace(".", "_")}_ptr = Module.findExportByName("libunity.so", "{api}");
        if ({api.replace(":", "_").replace(".", "_")}_ptr) {{
            Interceptor.attach({api.replace(":", "_").replace(".", "_")}_ptr, {{
                onEnter: function(args) {{
                    console.log("[API] {api} called");
                }},
                onLeave: function(retval) {{
                    console.log("[API] {api} returned: " + retval);
                }}
            }});
        }}
    }} catch(e) {{
        console.log("[-] Failed to hook {api}: " + e);
    }}
"""
            api_hooks.append(api_hook)
        
        script_content = script_content.replace("{{API_HOOKS}}", "\n".join(api_hooks))
        script_content = script_content.replace("{{PACKAGE_NAME}}", package_name)
        
        script_path = self.output_dir / f"api_trace_{package_name}.js"
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(script_content)
        
        logger.info(f"APIトレーススクリプトを生成しました: {script_path}")
        return str(script_path)
    
    def generate_game_state_capture_script(self, package_name: str) -> str:
        """ゲーム状態キャプチャ用のFridaスクリプトを生成"""
        script_content = self.script_templates["game_state_capture"]
        script_content = script_content.replace("{{PACKAGE_NAME}}", package_name)
        
        script_path = self.output_dir / f"game_state_{package_name}.js"
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(script_content)
        
        logger.info(f"ゲーム状態キャプチャスクリプトを生成しました: {script_path}")
        return str(script_path)
    
    def _get_il2cpp_hook_template(self) -> str:
        """IL2CPPフック用のテンプレート"""
        return '''
// IL2CPP Hook Script for {{PACKAGE_NAME}}
// Generated by APK Analyzer Tool

console.log("[+] IL2CPP Hook Script loaded for {{PACKAGE_NAME}}");

Java.perform(function() {
    console.log("[+] Java.perform started");
    
    // IL2CPP関数のフック
    {{HOOK_FUNCTIONS}}
    
    // IL2CPPドメイン情報の取得
    var il2cpp_domain_get_ptr = Module.findExportByName("libil2cpp.so", "il2cpp_domain_get");
    if (il2cpp_domain_get_ptr) {
        Interceptor.attach(il2cpp_domain_get_ptr, {
            onEnter: function(args) {
                console.log("[+] il2cpp_domain_get called");
            },
            onLeave: function(retval) {
                console.log("[+] Domain: " + retval);
            }
        });
    }
    
    // メモリ割り当ての監視
    var malloc_ptr = Module.findExportByName("libc.so", "malloc");
    if (malloc_ptr) {
        Interceptor.attach(malloc_ptr, {
            onEnter: function(args) {
                this.size = args[0].toInt32();
            },
            onLeave: function(retval) {
                if (this.size > 1024 * 1024) { // 1MB以上の割り当てをログ
                    console.log("[MEMORY] Large allocation: " + this.size + " bytes at " + retval);
                }
            }
        });
    }
});

console.log("[+] IL2CPP Hook Script setup complete");
'''
    
    def _get_memory_monitor_template(self) -> str:
        """メモリ監視用のテンプレート"""
        return '''
// Memory Monitor Script for {{PACKAGE_NAME}}
// Generated by APK Analyzer Tool

console.log("[+] Memory Monitor Script loaded for {{PACKAGE_NAME}}");

// メモリ使用量の定期監視
setInterval(function() {
    var memInfo = Process.getModuleByName("libil2cpp.so");
    console.log("[MEMORY] IL2CPP Module Base: " + memInfo.base + " Size: " + memInfo.size);
    
    // ヒープ情報の取得
    try {
        var runtime = Java.use("java.lang.Runtime").getRuntime();
        var maxMemory = runtime.maxMemory();
        var totalMemory = runtime.totalMemory();
        var freeMemory = runtime.freeMemory();
        var usedMemory = totalMemory - freeMemory;
        
        console.log("[HEAP] Max: " + (maxMemory / 1024 / 1024).toFixed(2) + "MB");
        console.log("[HEAP] Used: " + (usedMemory / 1024 / 1024).toFixed(2) + "MB");
        console.log("[HEAP] Free: " + (freeMemory / 1024 / 1024).toFixed(2) + "MB");
    } catch(e) {
        console.log("[-] Failed to get heap info: " + e);
    }
}, 5000); // 5秒間隔

// メモリリークの検出
var allocations = {};
var allocationCount = 0;

Interceptor.attach(Module.findExportByName("libc.so", "malloc"), {
    onEnter: function(args) {
        this.size = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (retval.isNull()) return;
        
        allocations[retval.toString()] = {
            size: this.size,
            timestamp: Date.now()
        };
        allocationCount++;
        
        if (allocationCount % 1000 === 0) {
            console.log("[LEAK] Total allocations: " + allocationCount);
        }
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "free"), {
    onEnter: function(args) {
        var ptr = args[0].toString();
        if (allocations[ptr]) {
            delete allocations[ptr];
        }
    }
});
'''
    
    def _get_api_trace_template(self) -> str:
        """APIトレース用のテンプレート"""
        return '''
// API Trace Script for {{PACKAGE_NAME}}
// Generated by APK Analyzer Tool

console.log("[+] API Trace Script loaded for {{PACKAGE_NAME}}");

Java.perform(function() {
    // Unity API呼び出しのトレース
    {{API_HOOKS}}
    
    // JNI呼び出しの監視
    var jniEnv = Java.vm.getEnv();
    
    // ファイルI/O操作の監視
    var fopen_ptr = Module.findExportByName("libc.so", "fopen");
    if (fopen_ptr) {
        Interceptor.attach(fopen_ptr, {
            onEnter: function(args) {
                this.filename = Memory.readUtf8String(args[0]);
                this.mode = Memory.readUtf8String(args[1]);
            },
            onLeave: function(retval) {
                if (!retval.isNull()) {
                    console.log("[FILE] Opened: " + this.filename + " (mode: " + this.mode + ")");
                }
            }
        });
    }
    
    // ネットワーク通信の監視
    var connect_ptr = Module.findExportByName("libc.so", "connect");
    if (connect_ptr) {
        Interceptor.attach(connect_ptr, {
            onEnter: function(args) {
                console.log("[NETWORK] Connection attempt detected");
            },
            onLeave: function(retval) {
                console.log("[NETWORK] Connection result: " + retval);
            }
        });
    }
});
'''
    
    def _get_game_state_template(self) -> str:
        """ゲーム状態キャプチャ用のテンプレート"""
        return '''
// Game State Capture Script for {{PACKAGE_NAME}}
// Generated by APK Analyzer Tool

console.log("[+] Game State Capture Script loaded for {{PACKAGE_NAME}}");

var gameState = {
    score: 0,
    level: 1,
    lives: 3,
    timestamp: Date.now()
};

Java.perform(function() {
    // ゲーム状態の変更を監視
    try {
        // スコア関連の監視
        var scorePattern = /score|point|coin/i;
        
        // SharedPreferencesの監視
        var SharedPreferences = Java.use("android.content.SharedPreferences$Editor");
        SharedPreferences.putInt.overload('java.lang.String', 'int').implementation = function(key, value) {
            if (scorePattern.test(key)) {
                console.log("[GAME_STATE] Score updated: " + key + " = " + value);
                gameState.score = value;
                gameState.timestamp = Date.now();
            }
            return this.putInt(key, value);
        };
        
        // ゲーム状態の定期出力
        setInterval(function() {
            console.log("[GAME_STATE] Current state: " + JSON.stringify(gameState));
        }, 10000); // 10秒間隔
        
    } catch(e) {
        console.log("[-] Failed to setup game state monitoring: " + e);
    }
});

// ゲーム状態をファイルに保存
function saveGameState() {
    var timestamp = new Date().toISOString();
    var stateData = {
        timestamp: timestamp,
        state: gameState
    };
    
    console.log("[SAVE] Game state: " + JSON.stringify(stateData));
}

// 定期的にゲーム状態を保存
setInterval(saveGameState, 30000); // 30秒間隔
'''
    
    def generate_comprehensive_analysis_script(self, analysis_data: Dict) -> str:
        """包括的な解析用のFridaスクリプトを生成"""
        package_name = analysis_data.get("package_name", "unknown")
        symbols = analysis_data.get("symbols", [])
        unity_strings = analysis_data.get("unity_strings", [])
        
        # 各種スクリプトを生成
        scripts = {
            "il2cpp_hook": self.generate_il2cpp_hook_script(symbols, package_name),
            "memory_monitor": self.generate_memory_monitor_script(package_name),
            "api_trace": self.generate_api_trace_script(package_name, unity_strings),
            "game_state": self.generate_game_state_capture_script(package_name)
        }
        
        # 統合スクリプトの生成
        integrated_script = self._create_integrated_script(scripts, package_name)
        
        return integrated_script
    
    def _create_integrated_script(self, scripts: Dict[str, str], package_name: str) -> str:
        """統合されたFridaスクリプトを作成"""
        integrated_path = self.output_dir / f"integrated_analysis_{package_name}.js"
        
        integrated_content = f'''
// Integrated Analysis Script for {package_name}
// Generated by APK Analyzer Tool

console.log("[+] Integrated Analysis Script loaded for {package_name}");

// Load individual script modules
'''
        
        for script_type, script_path in scripts.items():
            with open(script_path, 'r', encoding='utf-8') as f:
                script_content = f.read()
                integrated_content += f"\n// === {script_type.upper()} MODULE ===\n"
                integrated_content += script_content + "\n"
        
        with open(integrated_path, 'w', encoding='utf-8') as f:
            f.write(integrated_content)
        
        logger.info(f"統合解析スクリプトを生成しました: {integrated_path}")
        return str(integrated_path)
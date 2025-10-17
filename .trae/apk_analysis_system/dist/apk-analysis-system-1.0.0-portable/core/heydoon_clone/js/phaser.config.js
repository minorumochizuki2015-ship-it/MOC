// HeyDooon Clone - Phaser Configuration

// Phaser game configuration
const PhaserConfig = {
    type: Phaser.AUTO, // Use WebGL if available, fallback to Canvas
    width: GameConfig.GAME.WIDTH,
    height: GameConfig.GAME.HEIGHT,
    parent: 'game-container', // HTML element ID
    backgroundColor: GameConfig.GAME.BACKGROUND_COLOR,
    
    // Physics configuration
    physics: {
        default: 'arcade',
        arcade: {
            gravity: { y: GameConfig.PHYSICS.GRAVITY },
            debug: GameConfig.DEBUG.PHYSICS_DEBUG,
            debugShowBody: GameConfig.DEBUG.PHYSICS_DEBUG,
            debugShowStaticBody: GameConfig.DEBUG.PHYSICS_DEBUG,
            debugShowVelocity: GameConfig.DEBUG.PHYSICS_DEBUG,
            debugVelocityColor: 0x00ff00,
            debugBodyColor: 0x0000ff,
            debugStaticBodyColor: 0xff0000
        }
    },
    
    // Rendering configuration
    render: {
        antialias: true,
        pixelArt: false,
        roundPixels: false,
        transparent: false,
        clearBeforeRender: true,
        preserveDrawingBuffer: false,
        premultipliedAlpha: true,
        failIfMajorPerformanceCaveat: false,
        powerPreference: 'default', // 'high-performance' or 'low-power'
        batchSize: 4096,
        maxLights: 10
    },
    
    // Audio configuration
    audio: {
        disableWebAudio: false,
        context: false,
        noAudio: !GameConfig.AUDIO.ENABLED
    },
    
    // Input configuration
    input: {
        keyboard: true,
        mouse: true,
        touch: true,
        gamepad: false,
        smoothFactor: 0,
        windowEvents: true,
        
        // Touch/pointer configuration
        activePointers: 2,
        capture: true,
        
        // Mouse configuration
        mouseCapture: true,
        
        // Keyboard configuration
        keyboardCapture: []
    },
    
    // Scale configuration for responsive design
    scale: {
        mode: Phaser.Scale.FIT,
        autoCenter: Phaser.Scale.CENTER_BOTH,
        width: GameConfig.GAME.WIDTH,
        height: GameConfig.GAME.HEIGHT,
        min: {
            width: GameConfig.GAME.MIN_WIDTH,
            height: GameConfig.GAME.MIN_HEIGHT
        },
        max: {
            width: GameConfig.GAME.MAX_WIDTH,
            height: GameConfig.GAME.MAX_HEIGHT
        },
        zoom: 1,
        
        // Mobile specific settings
        fullscreenTarget: 'game-container',
        expandParent: true,
        
        // Orientation handling
        orientation: {
            forceOrientation: false,
            forceLandscape: false,
            forcePortrait: false
        }
    },
    
    // DOM configuration
    dom: {
        createContainer: true,
        behindCanvas: false
    },
    
    // Loader configuration
    loader: {
        baseURL: '',
        path: '',
        enableParallel: true,
        maxParallelDownloads: 4,
        crossOrigin: 'anonymous',
        responseType: '',
        async: true,
        user: '',
        password: '',
        timeout: 0,
        withCredentials: false
    },
    
    // Performance configuration
    fps: {
        target: GameConfig.PERFORMANCE.TARGET_FPS,
        forceSetTimeOut: false,
        deltaHistory: 10,
        panicMax: 120,
        smoothStep: true
    },
    
    // Banner configuration
    banner: {
        hidePhaser: !GameConfig.DEBUG.SHOW_PHASER_BANNER,
        text: GameConfig.GAME.TITLE,
        background: [
            '#ff0000',
            '#ffff00',
            '#00ff00',
            '#00ffff',
            '#000000'
        ]
    },
    
    // Pipeline configuration
    pipeline: {
        // Custom pipelines can be added here
    },
    
    // Callbacks
    callbacks: {
        preBoot: function (game) {
            GameUtils.log('debug', 'Phaser preBoot callback');
            
            // Initialize performance monitoring
            if (GameConfig.DEBUG.PERFORMANCE_MONITOR) {
                game.performanceMonitor = {
                    startTime: performance.now(),
                    frameCount: 0,
                    lastFPSUpdate: 0,
                    currentFPS: 0
                };
            }
        },
        
        postBoot: function (game) {
            GameUtils.log('info', 'Phaser game booted successfully');
            
            // Setup global error handling
            window.addEventListener('error', (event) => {
                GameUtils.log('error', 'Global error:', event.error);
                
                // Track error in analytics if available
                if (window.gameAnalytics) {
                    window.gameAnalytics.trackEvent('Error', 'GlobalError', event.error.message);
                }
            });
            
            // Setup unhandled promise rejection handling
            window.addEventListener('unhandledrejection', (event) => {
                GameUtils.log('error', 'Unhandled promise rejection:', event.reason);
                
                // Track error in analytics if available
                if (window.gameAnalytics) {
                    window.gameAnalytics.trackEvent('Error', 'UnhandledPromise', event.reason);
                }
            });
            
            // Setup visibility change handling
            document.addEventListener('visibilitychange', () => {
                if (document.hidden) {
                    GameUtils.log('debug', 'Game hidden - pausing');
                    if (game.scene.isActive(GameConfig.STATES.GAME)) {
                        // Auto-pause when tab becomes hidden
                        if (window.gameInstance && !window.gameInstance.gameState.isPaused) {
                            window.gameInstance.togglePause();
                        }
                    }
                } else {
                    GameUtils.log('debug', 'Game visible - resuming');
                }
            });
            
            // Setup resize handling
            window.addEventListener('resize', () => {
                GameUtils.log('debug', 'Window resized');
                
                // Update game scale if needed
                if (game.scale.isFullscreen) {
                    game.scale.refresh();
                }
            });
            
            // Setup orientation change handling for mobile
            if (GameUtils.isMobile()) {
                window.addEventListener('orientationchange', () => {
                    GameUtils.log('debug', 'Orientation changed');
                    
                    // Delay to allow orientation change to complete
                    setTimeout(() => {
                        game.scale.refresh();
                    }, 100);
                });
            }
            
            // Initialize performance monitoring
            if (GameConfig.DEBUG.PERFORMANCE_MONITOR) {
                setInterval(() => {
                    const monitor = game.performanceMonitor;
                    const now = performance.now();
                    
                    if (now - monitor.lastFPSUpdate >= 1000) {
                        monitor.currentFPS = Math.round((monitor.frameCount * 1000) / (now - monitor.lastFPSUpdate));
                        monitor.frameCount = 0;
                        monitor.lastFPSUpdate = now;
                        
                        GameUtils.log('debug', `FPS: ${monitor.currentFPS}`);
                        
                        // Update FPS display if element exists
                        const fpsElement = document.getElementById('fps-counter');
                        if (fpsElement) {
                            fpsElement.textContent = `FPS: ${monitor.currentFPS}`;
                        }
                        
                        // Warn about low FPS
                        if (monitor.currentFPS < GameConfig.PERFORMANCE.MIN_FPS) {
                            GameUtils.log('warn', `Low FPS detected: ${monitor.currentFPS}`);
                        }
                    }
                    
                    monitor.frameCount++;
                }, 16); // ~60 FPS monitoring
            }
        }
    },
    
    // Plugins configuration
    plugins: {
        global: [
            // Global plugins can be added here
        ],
        scene: [
            // Scene plugins can be added here
        ]
    },
    
    // Custom properties for our game
    customConfig: {
        gameTitle: GameConfig.GAME.TITLE,
        gameVersion: GameConfig.GAME.VERSION,
        debugMode: GameConfig.DEBUG.ENABLED,
        
        // Asset paths
        assetPaths: GameConfig.ASSETS,
        
        // Game states
        gameStates: GameConfig.STATES,
        
        // Performance settings
        performance: GameConfig.PERFORMANCE
    }
};

// Phaser device detection and configuration adjustments
document.addEventListener('DOMContentLoaded', () => {
    // Adjust configuration based on device capabilities
    if (GameUtils.isMobile()) {
        GameUtils.log('info', 'Mobile device detected, adjusting configuration...');
        
        // Reduce performance settings for mobile
        PhaserConfig.render.batchSize = 2048;
        PhaserConfig.render.maxLights = 5;
        PhaserConfig.fps.target = 30;
        
        // Enable touch-friendly settings
        PhaserConfig.input.activePointers = 3;
        PhaserConfig.scale.fullscreenTarget = document.body;
        
        // Adjust physics for mobile performance
        if (PhaserConfig.physics && PhaserConfig.physics.arcade) {
            PhaserConfig.physics.arcade.debug = false; // Disable debug on mobile
        }
    }
    
    // Check for WebGL support
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    
    if (!gl) {
        GameUtils.log('warn', 'WebGL not supported, forcing Canvas renderer');
        PhaserConfig.type = Phaser.CANVAS;
        
        // Adjust settings for Canvas renderer
        PhaserConfig.render.antialias = false;
        PhaserConfig.render.roundPixels = true;
    }
    
    // Check available memory (if supported)
    if ('memory' in performance) {
        const memoryInfo = performance.memory;
        const availableMemory = memoryInfo.jsHeapSizeLimit;
        
        GameUtils.log('debug', `Available memory: ${Math.round(availableMemory / 1024 / 1024)}MB`);
        
        // Adjust batch size based on available memory
        if (availableMemory < 100 * 1024 * 1024) { // Less than 100MB
            PhaserConfig.render.batchSize = 1024;
            GameUtils.log('info', 'Low memory detected, reducing batch size');
        }
    }
    
    // Check for high DPI displays
    if (window.devicePixelRatio > 1) {
        GameUtils.log('info', `High DPI display detected: ${window.devicePixelRatio}x`);
        
        // Optionally adjust for high DPI
        if (GameConfig.PERFORMANCE.HIGH_DPI_SUPPORT) {
            PhaserConfig.scale.zoom = 1 / window.devicePixelRatio;
        }
    }
    
    GameUtils.log('info', 'Phaser configuration prepared');
});

// Export configuration
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PhaserConfig;
}

// Make available globally
window.PhaserConfig = PhaserConfig;
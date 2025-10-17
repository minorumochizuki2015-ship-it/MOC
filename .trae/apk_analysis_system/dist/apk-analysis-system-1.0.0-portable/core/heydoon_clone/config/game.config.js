// HeyDooon Clone - Game Configuration

const GameConfig = {
    // Game Settings
    GAME: {
        WIDTH: 800,
        HEIGHT: 600,
        TITLE: 'HeyDooon Clone',
        VERSION: '1.0.0',
        BACKGROUND_COLOR: '#2c3e50',
        PHYSICS: Phaser.Physics.ARCADE,
        PIXEL_ART: false,
        ANTIALIAS: true,
        TRANSPARENT: false
    },

    // Player Settings
    PLAYER: {
        SPEED: 200,
        JUMP_VELOCITY: -400,
        GRAVITY: 800,
        BOUNCE: 0.2,
        LIVES: 3,
        INVINCIBILITY_TIME: 2000, // milliseconds
        SIZE: {
            WIDTH: 32,
            HEIGHT: 48
        },
        ANIMATIONS: {
            IDLE: 'player_idle',
            WALK: 'player_walk',
            JUMP: 'player_jump',
            FALL: 'player_fall'
        }
    },

    // Enemy Settings
    ENEMY: {
        SPEED: 100,
        PATROL_DISTANCE: 150,
        DETECTION_RANGE: 120,
        DAMAGE: 1,
        SCORE_VALUE: 100,
        SIZE: {
            WIDTH: 24,
            HEIGHT: 32
        },
        TYPES: {
            WALKER: 'walker',
            JUMPER: 'jumper',
            FLYER: 'flyer'
        }
    },

    // Collectible Settings
    COLLECTIBLE: {
        COIN_VALUE: 10,
        POWERUP_DURATION: 5000, // milliseconds
        SIZE: {
            WIDTH: 16,
            HEIGHT: 16
        },
        TYPES: {
            COIN: 'coin',
            HEALTH: 'health',
            SPEED_BOOST: 'speed_boost',
            JUMP_BOOST: 'jump_boost',
            INVINCIBILITY: 'invincibility'
        }
    },

    // Level Settings
    LEVEL: {
        TILE_SIZE: 32,
        GRAVITY: 800,
        WORLD_BOUNDS: {
            WIDTH: 2400,
            HEIGHT: 600
        },
        SPAWN_POINTS: {
            PLAYER: { x: 100, y: 400 },
            ENEMIES: [
                { x: 300, y: 400, type: 'walker' },
                { x: 600, y: 400, type: 'jumper' },
                { x: 900, y: 300, type: 'flyer' }
            ],
            COLLECTIBLES: [
                { x: 200, y: 350, type: 'coin' },
                { x: 400, y: 300, type: 'coin' },
                { x: 700, y: 250, type: 'health' }
            ]
        }
    },

    // Audio Settings
    AUDIO: {
        MASTER_VOLUME: 0.7,
        MUSIC_VOLUME: 0.5,
        SFX_VOLUME: 0.8,
        SOUNDS: {
            JUMP: 'jump_sound',
            COLLECT: 'collect_sound',
            ENEMY_HIT: 'enemy_hit_sound',
            PLAYER_HURT: 'player_hurt_sound',
            GAME_OVER: 'game_over_sound',
            LEVEL_COMPLETE: 'level_complete_sound',
            BACKGROUND_MUSIC: 'background_music'
        }
    },

    // UI Settings
    UI: {
        FONT_FAMILY: 'Arial, sans-serif',
        FONT_SIZE: {
            SMALL: '14px',
            MEDIUM: '18px',
            LARGE: '24px',
            XLARGE: '32px'
        },
        COLORS: {
            PRIMARY: '#4ecdc4',
            SECONDARY: '#ff6b6b',
            SUCCESS: '#2ecc71',
            WARNING: '#f39c12',
            DANGER: '#e74c3c',
            WHITE: '#ffffff',
            BLACK: '#000000',
            GRAY: '#95a5a6'
        },
        ANIMATIONS: {
            FADE_DURATION: 300,
            SLIDE_DURATION: 500,
            BOUNCE_DURATION: 600
        }
    },

    // Input Settings
    INPUT: {
        KEYBOARD: {
            LEFT: ['LEFT', 'A'],
            RIGHT: ['RIGHT', 'D'],
            JUMP: ['UP', 'W', 'SPACE'],
            ACTION: ['ENTER', 'E'],
            PAUSE: ['ESC', 'P']
        },
        TOUCH: {
            ENABLED: true,
            ZONES: {
                LEFT: { x: 0, y: 0, width: 0.3, height: 1 },
                RIGHT: { x: 0.7, y: 0, width: 0.3, height: 1 },
                JUMP: { x: 0.3, y: 0.7, width: 0.4, height: 0.3 }
            }
        }
    },

    // Performance Settings
    PERFORMANCE: {
        TARGET_FPS: 60,
        MAX_PARTICLES: 100,
        CULLING_MARGIN: 100,
        PRELOAD_AUDIO: true,
        TEXTURE_COMPRESSION: false,
        DEBUG_MODE: false
    },

    // Asset Paths
    ASSETS: {
        IMAGES: 'assets/images/',
        AUDIO: 'assets/audio/',
        FONTS: 'assets/fonts/',
        DATA: 'assets/data/',
        SPRITES: {
            PLAYER: 'player_spritesheet.png',
            ENEMIES: 'enemies_spritesheet.png',
            COLLECTIBLES: 'collectibles_spritesheet.png',
            TILES: 'tileset.png',
            UI: 'ui_elements.png'
        },
        SOUNDS: {
            JUMP: 'jump.ogg',
            COLLECT: 'collect.ogg',
            ENEMY_HIT: 'enemy_hit.ogg',
            PLAYER_HURT: 'player_hurt.ogg',
            GAME_OVER: 'game_over.ogg',
            LEVEL_COMPLETE: 'level_complete.ogg',
            BACKGROUND_MUSIC: 'background_music.ogg'
        }
    },

    // Game States
    STATES: {
        MENU: 'MenuScene',
        GAME: 'GameScene',
        GAME_OVER: 'GameOverScene',
        PAUSE: 'PauseScene',
        LOADING: 'LoadingScene'
    },

    // Scoring System
    SCORING: {
        COIN_POINTS: 10,
        ENEMY_DEFEAT_POINTS: 100,
        LEVEL_COMPLETE_BONUS: 1000,
        TIME_BONUS_MULTIPLIER: 10,
        COMBO_MULTIPLIER: 1.5,
        HIGH_SCORE_KEY: 'heydoon_clone_high_score'
    },

    // Development Settings
    DEBUG: {
        SHOW_FPS: false,
        SHOW_PHYSICS: false,
        SHOW_BOUNDS: false,
        LOG_LEVEL: 'info', // 'debug', 'info', 'warn', 'error'
        SKIP_INTRO: false,
        GOD_MODE: false
    }
};

// Phaser Game Configuration
const PhaserConfig = {
    type: Phaser.AUTO,
    width: GameConfig.GAME.WIDTH,
    height: GameConfig.GAME.HEIGHT,
    parent: 'phaser-game',
    backgroundColor: GameConfig.GAME.BACKGROUND_COLOR,
    pixelArt: GameConfig.GAME.PIXEL_ART,
    antialias: GameConfig.GAME.ANTIALIAS,
    transparent: GameConfig.GAME.TRANSPARENT,
    
    physics: {
        default: 'arcade',
        arcade: {
            gravity: { y: GameConfig.LEVEL.GRAVITY },
            debug: GameConfig.DEBUG.SHOW_PHYSICS
        }
    },
    
    scale: {
        mode: Phaser.Scale.FIT,
        autoCenter: Phaser.Scale.CENTER_BOTH,
        min: {
            width: 320,
            height: 240
        },
        max: {
            width: 1920,
            height: 1080
        }
    },
    
    fps: {
        target: GameConfig.PERFORMANCE.TARGET_FPS,
        forceSetTimeOut: true
    },
    
    render: {
        powerPreference: 'high-performance',
        mipmapFilter: 'LINEAR',
        roundPixels: GameConfig.GAME.PIXEL_ART
    },
    
    audio: {
        disableWebAudio: false
    },
    
    input: {
        keyboard: true,
        mouse: true,
        touch: GameConfig.INPUT.TOUCH.ENABLED,
        gamepad: false
    },
    
    scene: [] // Scenes will be added dynamically
};

// Utility Functions
const GameUtils = {
    // Get high score from localStorage
    getHighScore: function() {
        return parseInt(localStorage.getItem(GameConfig.SCORING.HIGH_SCORE_KEY)) || 0;
    },
    
    // Save high score to localStorage
    saveHighScore: function(score) {
        const currentHigh = this.getHighScore();
        if (score > currentHigh) {
            localStorage.setItem(GameConfig.SCORING.HIGH_SCORE_KEY, score.toString());
            return true; // New high score
        }
        return false;
    },
    
    // Format score with commas
    formatScore: function(score) {
        return score.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    },
    
    // Calculate time bonus
    calculateTimeBonus: function(timeRemaining) {
        return Math.floor(timeRemaining * GameConfig.SCORING.TIME_BONUS_MULTIPLIER);
    },
    
    // Check if mobile device
    isMobile: function() {
        return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    },
    
    // Log with level checking
    log: function(level, message, ...args) {
        const levels = ['debug', 'info', 'warn', 'error'];
        const currentLevelIndex = levels.indexOf(GameConfig.DEBUG.LOG_LEVEL);
        const messageLevelIndex = levels.indexOf(level);
        
        if (messageLevelIndex >= currentLevelIndex) {
            console[level](`[HeyDooon Clone] ${message}`, ...args);
        }
    }
};

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { GameConfig, PhaserConfig, GameUtils };
}
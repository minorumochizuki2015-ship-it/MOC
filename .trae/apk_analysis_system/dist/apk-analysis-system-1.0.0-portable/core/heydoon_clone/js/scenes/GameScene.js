// HeyDooon Clone - Game Scene

class GameScene extends Phaser.Scene {
    constructor() {
        super({ key: GameConfig.STATES.GAME });
        
        // Game objects
        this.player = null;
        this.enemies = null;
        this.collectibles = null;
        this.platforms = null;
        this.background = null;
        
        // Game state
        this.gameState = {
            score: 0,
            lives: GameConfig.PLAYER.LIVES,
            level: 1,
            timeRemaining: GameConfig.LEVEL.TIME_LIMIT,
            isGameOver: false,
            isPaused: false
        };
        
        // Input
        this.cursors = null;
        this.wasd = null;
        this.touchControls = null;
        
        // Timers
        this.gameTimer = null;
        this.enemySpawnTimer = null;
        this.collectibleSpawnTimer = null;
        
        // Effects
        this.particles = null;
        this.sounds = {};
    }
    
    preload() {
        // Create simple colored shapes as game sprites
        this.createGameSprites();
        
        // Load audio (placeholder)
        this.load.audio('game-music', ['data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIG2m98OScTgwOUarm7blmGgU7k9n1unEiBC13yO/eizEIHWq+8+OWT']);
        this.load.audio('collect', ['data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIG2m98OScTgwOUarm7blmGgU7k9n1unEiBC13yO/eizEIHWq+8+OWT']);
        this.load.audio('hurt', ['data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIG2m98OScTgwOUarm7blmGgU7k9n1unEiBC13yO/eizEIHWq+8+OWT']);
        this.load.audio('jump', ['data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIG2m98OScTgwOUarm7blmGgU7k9n1unEiBC13yO/eizEIHWq+8+OWT']);
        
        GameUtils.log('debug', 'GameScene preload completed');
    }
    
    createGameSprites() {
        // Player sprite
        this.load.image('player', 'data:image/svg+xml;base64,' + btoa(`
            <svg width="40" height="40" xmlns="http://www.w3.org/2000/svg">
                <circle cx="20" cy="20" r="18" fill="#4CAF50" stroke="#2E7D32" stroke-width="2"/>
                <circle cx="15" cy="15" r="3" fill="white"/>
                <circle cx="25" cy="15" r="3" fill="white"/>
                <circle cx="15" cy="15" r="1" fill="black"/>
                <circle cx="25" cy="15" r="1" fill="black"/>
                <path d="M 12 25 Q 20 30 28 25" stroke="#2E7D32" stroke-width="2" fill="none"/>
            </svg>
        `));
        
        // Enemy sprite
        this.load.image('enemy', 'data:image/svg+xml;base64,' + btoa(`
            <svg width="30" height="30" xmlns="http://www.w3.org/2000/svg">
                <circle cx="15" cy="15" r="13" fill="#F44336" stroke="#C62828" stroke-width="2"/>
                <circle cx="12" cy="12" r="2" fill="white"/>
                <circle cx="18" cy="12" r="2" fill="white"/>
                <circle cx="12" cy="12" r="1" fill="black"/>
                <circle cx="18" cy="12" r="1" fill="black"/>
                <path d="M 10 20 Q 15 18 20 20" stroke="#C62828" stroke-width="2" fill="none"/>
            </svg>
        `));
        
        // Collectible sprite
        this.load.image('collectible', 'data:image/svg+xml;base64,' + btoa(`
            <svg width="25" height="25" xmlns="http://www.w3.org/2000/svg">
                <circle cx="12.5" cy="12.5" r="10" fill="#FFD700" stroke="#FFA000" stroke-width="2"/>
                <text x="12.5" y="17" font-family="Arial, sans-serif" font-size="12" font-weight="bold" 
                      text-anchor="middle" fill="#FF8F00">★</text>
            </svg>
        `));
        
        // Platform sprite
        this.load.image('platform', 'data:image/svg+xml;base64,' + btoa(`
            <svg width="100" height="20" xmlns="http://www.w3.org/2000/svg">
                <rect width="100" height="20" fill="#8BC34A" stroke="#689F38" stroke-width="2"/>
                <rect x="0" y="0" width="100" height="5" fill="#AED581"/>
            </svg>
        `));
        
        // Background
        this.load.image('game-bg', 'data:image/svg+xml;base64,' + btoa(`
            <svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <linearGradient id="sky" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" style="stop-color:#87CEEB;stop-opacity:1" />
                        <stop offset="100%" style="stop-color:#E0F6FF;stop-opacity:1" />
                    </linearGradient>
                </defs>
                <rect width="800" height="600" fill="url(#sky)"/>
                <circle cx="700" cy="100" r="40" fill="#FFD700" opacity="0.8"/>
                <ellipse cx="150" cy="80" rx="30" ry="15" fill="white" opacity="0.7"/>
                <ellipse cx="400" cy="120" rx="40" ry="20" fill="white" opacity="0.6"/>
                <ellipse cx="650" cy="90" rx="25" ry="12" fill="white" opacity="0.8"/>
            </svg>
        `));
    }
    
    create() {
        GameUtils.log('info', 'Creating GameScene...');
        
        // Initialize game state
        this.resetGameState();
        
        // Create world
        this.createWorld();
        
        // Create player
        this.createPlayer();
        
        // Create groups
        this.createGroups();
        
        // Setup physics
        this.setupPhysics();
        
        // Setup input
        this.setupInput();
        
        // Setup UI
        this.setupUI();
        
        // Start game timers
        this.startGameTimers();
        
        // Setup camera
        this.setupCamera();
        
        // Play background music
        if (GameConfig.AUDIO.ENABLED) {
            this.playBackgroundMusic();
        }
        
        GameUtils.log('info', 'GameScene created successfully');
    }
    
    resetGameState() {
        this.gameState = {
            score: 0,
            lives: GameConfig.PLAYER.LIVES,
            level: 1,
            timeRemaining: GameConfig.LEVEL.TIME_LIMIT,
            isGameOver: false,
            isPaused: false
        };
        
        // Update external UI
        if (window.gameInstance) {
            window.gameInstance.setGameState(this.gameState);
        }
    }
    
    createWorld() {
        // Add background
        this.background = this.add.image(GameConfig.GAME.WIDTH / 2, GameConfig.GAME.HEIGHT / 2, 'game-bg');
        this.background.setDisplaySize(GameConfig.GAME.WIDTH, GameConfig.GAME.HEIGHT);
        
        // Create platforms
        this.platforms = this.physics.add.staticGroup();
        
        // Ground platform
        const ground = this.platforms.create(GameConfig.GAME.WIDTH / 2, GameConfig.GAME.HEIGHT - 10, 'platform');
        ground.setScale(GameConfig.GAME.WIDTH / 100, 1).refreshBody();
        
        // Floating platforms
        this.platforms.create(200, 450, 'platform');
        this.platforms.create(600, 400, 'platform');
        this.platforms.create(400, 350, 'platform');
        this.platforms.create(100, 300, 'platform');
        this.platforms.create(700, 250, 'platform');
    }
    
    createPlayer() {
        this.player = this.physics.add.sprite(100, 450, 'player');
        this.player.setBounce(0.2);
        this.player.setCollideWorldBounds(true);
        this.player.setScale(1);
        
        // Player properties
        this.player.health = GameConfig.PLAYER.LIVES;
        this.player.isInvulnerable = false;
        this.player.lastDirection = 1; // 1 for right, -1 for left
        
        // Player animations (using tint changes since we don't have sprite sheets)
        this.player.normalTint = 0xFFFFFF;
        this.player.hurtTint = 0xFF6666;
    }
    
    createGroups() {
        // Enemies group
        this.enemies = this.physics.add.group({
            defaultKey: 'enemy',
            maxSize: GameConfig.ENEMIES.MAX_COUNT
        });
        
        // Collectibles group
        this.collectibles = this.physics.add.group({
            defaultKey: 'collectible',
            maxSize: GameConfig.COLLECTIBLES.MAX_COUNT
        });
    }
    
    setupPhysics() {
        // Player vs platforms
        this.physics.add.collider(this.player, this.platforms);
        
        // Enemies vs platforms
        this.physics.add.collider(this.enemies, this.platforms);
        
        // Player vs enemies
        this.physics.add.overlap(this.player, this.enemies, this.playerHitEnemy, null, this);
        
        // Player vs collectibles
        this.physics.add.overlap(this.player, this.collectibles, this.playerCollectItem, null, this);
        
        // Enemies vs collectibles (enemies can destroy collectibles)
        this.physics.add.overlap(this.enemies, this.collectibles, this.enemyHitCollectible, null, this);
    }
    
    setupInput() {
        // Keyboard controls
        this.cursors = this.input.keyboard.createCursorKeys();
        this.wasd = this.input.keyboard.addKeys('W,S,A,D');
        
        // Touch controls for mobile
        if (GameUtils.isMobile()) {
            this.setupTouchControls();
        }
        
        // Pause key
        this.input.keyboard.on('keydown-ESC', () => {
            this.togglePause();
        });
    }
    
    setupTouchControls() {
        // Simple touch controls - tap to jump, hold sides to move
        this.input.on('pointerdown', (pointer) => {
            if (pointer.x < GameConfig.GAME.WIDTH / 3) {
                // Left side - move left
                this.player.setVelocityX(-GameConfig.PLAYER.SPEED);
                this.player.lastDirection = -1;
            } else if (pointer.x > GameConfig.GAME.WIDTH * 2 / 3) {
                // Right side - move right
                this.player.setVelocityX(GameConfig.PLAYER.SPEED);
                this.player.lastDirection = 1;
            } else {
                // Center - jump
                if (this.player.body.touching.down) {
                    this.player.setVelocityY(-GameConfig.PLAYER.JUMP_POWER);
                    this.playSound('jump');
                }
            }
        });
        
        this.input.on('pointerup', () => {
            // Stop horizontal movement when touch ends
            this.player.setVelocityX(0);
        });
    }
    
    setupUI() {
        // UI is handled by the main HTML/CSS, but we can add in-game UI here
        this.createInGameUI();
    }
    
    createInGameUI() {
        // Time remaining display
        this.timeText = this.add.text(GameConfig.GAME.WIDTH - 20, 20, 
            `Time: ${this.gameState.timeRemaining}`, {
            fontSize: '20px',
            fontFamily: 'Arial, sans-serif',
            fill: '#FFFFFF',
            stroke: '#000000',
            strokeThickness: 2
        });
        this.timeText.setOrigin(1, 0);
        
        // Level indicator
        this.levelText = this.add.text(20, 20, 
            `Level: ${this.gameState.level}`, {
            fontSize: '20px',
            fontFamily: 'Arial, sans-serif',
            fill: '#FFFFFF',
            stroke: '#000000',
            strokeThickness: 2
        });
    }
    
    startGameTimers() {
        // Main game timer
        this.gameTimer = this.time.addEvent({
            delay: 1000,
            callback: this.updateTimer,
            callbackScope: this,
            loop: true
        });
        
        // Enemy spawn timer
        this.enemySpawnTimer = this.time.addEvent({
            delay: GameConfig.ENEMIES.SPAWN_RATE,
            callback: this.spawnEnemy,
            callbackScope: this,
            loop: true
        });
        
        // Collectible spawn timer
        this.collectibleSpawnTimer = this.time.addEvent({
            delay: GameConfig.COLLECTIBLES.SPAWN_RATE,
            callback: this.spawnCollectible,
            callbackScope: this,
            loop: true
        });
    }
    
    setupCamera() {
        // Follow player with some bounds
        this.cameras.main.setBounds(0, 0, GameConfig.GAME.WIDTH, GameConfig.GAME.HEIGHT);
        this.cameras.main.startFollow(this.player, true, 0.05, 0.05);
        this.cameras.main.setDeadzone(200, 100);
    }
    
    update() {
        if (this.gameState.isPaused || this.gameState.isGameOver) {
            return;
        }
        
        this.handlePlayerInput();
        this.updateEnemies();
        this.updateCollectibles();
        this.checkLevelComplete();
        this.updateUI();
    }
    
    handlePlayerInput() {
        if (!this.player || !this.player.body) return;
        
        const isLeftPressed = this.cursors.left.isDown || this.wasd.A.isDown;
        const isRightPressed = this.cursors.right.isDown || this.wasd.D.isDown;
        const isJumpPressed = this.cursors.up.isDown || this.wasd.W.isDown || this.cursors.space?.isDown;
        
        // Horizontal movement
        if (isLeftPressed) {
            this.player.setVelocityX(-GameConfig.PLAYER.SPEED);
            this.player.lastDirection = -1;
        } else if (isRightPressed) {
            this.player.setVelocityX(GameConfig.PLAYER.SPEED);
            this.player.lastDirection = 1;
        } else {
            this.player.setVelocityX(0);
        }
        
        // Jumping
        if (isJumpPressed && this.player.body.touching.down) {
            this.player.setVelocityY(-GameConfig.PLAYER.JUMP_POWER);
            this.playSound('jump');
        }
        
        // Visual feedback
        if (this.player.body.velocity.x > 0) {
            this.player.setFlipX(false);
        } else if (this.player.body.velocity.x < 0) {
            this.player.setFlipX(true);
        }
    }
    
    updateEnemies() {
        this.enemies.children.entries.forEach(enemy => {
            if (!enemy.active) return;
            
            // Simple AI - move towards player
            const distanceToPlayer = Phaser.Math.Distance.Between(
                enemy.x, enemy.y, this.player.x, this.player.y
            );
            
            if (distanceToPlayer < GameConfig.ENEMIES.DETECTION_RANGE) {
                const direction = this.player.x > enemy.x ? 1 : -1;
                enemy.setVelocityX(direction * GameConfig.ENEMIES.SPEED);
                
                // Face the player
                enemy.setFlipX(direction < 0);
            } else {
                // Random movement when player is far
                if (Math.random() < 0.02) {
                    enemy.setVelocityX((Math.random() - 0.5) * GameConfig.ENEMIES.SPEED * 2);
                }
            }
            
            // Remove enemies that fall off the world
            if (enemy.y > GameConfig.GAME.HEIGHT + 100) {
                enemy.destroy();
            }
        });
    }
    
    updateCollectibles() {
        this.collectibles.children.entries.forEach(collectible => {
            if (!collectible.active) return;
            
            // Add floating animation
            collectible.y += Math.sin(this.time.now * 0.005 + collectible.x * 0.01) * 0.5;
            
            // Add sparkle effect
            if (Math.random() < 0.1) {
                this.createSparkle(collectible.x, collectible.y);
            }
            
            // Remove collectibles that are too old
            if (this.time.now - collectible.spawnTime > GameConfig.COLLECTIBLES.LIFETIME) {
                collectible.destroy();
            }
        });
    }
    
    spawnEnemy() {
        if (this.enemies.children.size >= GameConfig.ENEMIES.MAX_COUNT) return;
        
        const x = Math.random() < 0.5 ? -50 : GameConfig.GAME.WIDTH + 50;
        const y = Phaser.Math.Between(100, 400);
        
        const enemy = this.enemies.create(x, y, 'enemy');
        enemy.setBounce(0.1);
        enemy.setCollideWorldBounds(false);
        enemy.setVelocity(
            Phaser.Math.Between(-GameConfig.ENEMIES.SPEED, GameConfig.ENEMIES.SPEED),
            0
        );
        
        GameUtils.log('debug', 'Enemy spawned at', x, y);
    }
    
    spawnCollectible() {
        if (this.collectibles.children.size >= GameConfig.COLLECTIBLES.MAX_COUNT) return;
        
        const x = Phaser.Math.Between(50, GameConfig.GAME.WIDTH - 50);
        const y = Phaser.Math.Between(100, 400);
        
        const collectible = this.collectibles.create(x, y, 'collectible');
        collectible.setBounce(0.3);
        collectible.setCollideWorldBounds(true);
        collectible.spawnTime = this.time.now;
        
        // Add spawn effect
        this.createCollectibleSpawnEffect(x, y);
        
        GameUtils.log('debug', 'Collectible spawned at', x, y);
    }
    
    playerHitEnemy(player, enemy) {
        if (player.isInvulnerable) return;
        
        // Player takes damage
        this.playerTakeDamage();
        
        // Remove enemy
        enemy.destroy();
        
        // Knockback effect
        const knockbackDirection = player.x > enemy.x ? 1 : -1;
        player.setVelocity(knockbackDirection * 200, -150);
        
        this.playSound('hurt');
        GameUtils.log('debug', 'Player hit by enemy');
    }
    
    playerCollectItem(player, collectible) {
        // Add score
        const points = GameConfig.SCORING.COLLECTIBLE_POINTS;
        this.addScore(points);
        
        // Remove collectible
        collectible.destroy();
        
        // Create collection effect
        this.createCollectionEffect(collectible.x, collectible.y, points);
        
        this.playSound('collect');
        GameUtils.log('debug', 'Item collected, points:', points);
    }
    
    enemyHitCollectible(enemy, collectible) {
        // Enemies destroy collectibles
        collectible.destroy();
        GameUtils.log('debug', 'Collectible destroyed by enemy');
    }
    
    playerTakeDamage() {
        this.gameState.lives--;
        
        // Make player invulnerable temporarily
        this.player.isInvulnerable = true;
        this.player.setTint(this.player.hurtTint);
        
        // Flash effect
        this.tweens.add({
            targets: this.player,
            alpha: 0.5,
            duration: 100,
            yoyo: true,
            repeat: 5,
            onComplete: () => {
                this.player.isInvulnerable = false;
                this.player.setTint(this.player.normalTint);
                this.player.setAlpha(1);
            }
        });
        
        // Update UI
        if (window.gameInstance) {
            window.gameInstance.updateLives(this.gameState.lives);
        }
        
        // Check game over
        if (this.gameState.lives <= 0) {
            this.gameOver();
        }
    }
    
    addScore(points) {
        this.gameState.score += points;
        
        // Update UI
        if (window.gameInstance) {
            window.gameInstance.updateScore(this.gameState.score);
        }
    }
    
    updateTimer() {
        this.gameState.timeRemaining--;
        
        if (this.timeText) {
            this.timeText.setText(`Time: ${this.gameState.timeRemaining}`);
        }
        
        // Time warning
        if (this.gameState.timeRemaining <= 10) {
            this.timeText.setFill('#FF0000');
            
            if (this.gameState.timeRemaining <= 5) {
                // Flash warning
                this.tweens.add({
                    targets: this.timeText,
                    scaleX: 1.2,
                    scaleY: 1.2,
                    duration: 200,
                    yoyo: true
                });
            }
        }
        
        // Time up
        if (this.gameState.timeRemaining <= 0) {
            this.gameOver();
        }
    }
    
    checkLevelComplete() {
        // Level complete conditions (example: collect certain number of items)
        const collectiblesNeeded = GameConfig.LEVEL.COLLECTIBLES_TO_COMPLETE;
        const currentCollectibles = Math.floor(this.gameState.score / GameConfig.SCORING.COLLECTIBLE_POINTS);
        
        if (currentCollectibles >= collectiblesNeeded * this.gameState.level) {
            this.levelComplete();
        }
    }
    
    levelComplete() {
        this.gameState.level++;
        
        // Time bonus
        const timeBonus = GameUtils.calculateTimeBonus(this.gameState.timeRemaining);
        this.addScore(timeBonus);
        
        // Reset timer with bonus time
        this.gameState.timeRemaining = GameConfig.LEVEL.TIME_LIMIT + (this.gameState.level * 10);
        
        // Increase difficulty
        this.increaseDifficulty();
        
        // Update UI
        if (window.gameInstance) {
            window.gameInstance.levelComplete(this.gameState.level - 1, timeBonus);
            window.gameInstance.updateLevel(this.gameState.level);
        }
        
        // Show level complete message
        this.showLevelCompleteMessage();
        
        GameUtils.log('info', 'Level complete:', this.gameState.level - 1);
    }
    
    increaseDifficulty() {
        // Increase enemy spawn rate
        if (this.enemySpawnTimer) {
            this.enemySpawnTimer.delay = Math.max(1000, GameConfig.ENEMIES.SPAWN_RATE - (this.gameState.level * 200));
        }
        
        // Increase enemy speed
        GameConfig.ENEMIES.SPEED += 10;
        
        // Decrease collectible spawn rate slightly
        if (this.collectibleSpawnTimer) {
            this.collectibleSpawnTimer.delay = Math.min(5000, GameConfig.COLLECTIBLES.SPAWN_RATE + (this.gameState.level * 100));
        }
    }
    
    showLevelCompleteMessage() {
        const message = this.add.text(GameConfig.GAME.WIDTH / 2, GameConfig.GAME.HEIGHT / 2, 
            `Level ${this.gameState.level - 1} Complete!`, {
            fontSize: '32px',
            fontFamily: 'Arial, sans-serif',
            fill: '#FFD700',
            stroke: '#000000',
            strokeThickness: 3,
            align: 'center'
        });
        message.setOrigin(0.5);
        
        // Animate message
        this.tweens.add({
            targets: message,
            scaleX: 1.2,
            scaleY: 1.2,
            alpha: 0,
            duration: 2000,
            ease: 'Power2',
            onComplete: () => {
                message.destroy();
            }
        });
    }
    
    gameOver() {
        this.gameState.isGameOver = true;
        
        // Stop all timers
        if (this.gameTimer) this.gameTimer.destroy();
        if (this.enemySpawnTimer) this.enemySpawnTimer.destroy();
        if (this.collectibleSpawnTimer) this.collectibleSpawnTimer.destroy();
        
        // Stop player
        this.player.setVelocity(0, 0);
        this.player.body.setEnable(false);
        
        // Notify main game
        if (window.gameInstance) {
            window.gameInstance.gameOver(this.gameState.score);
        }
        
        GameUtils.log('info', 'Game over. Final score:', this.gameState.score);
    }
    
    togglePause() {
        if (window.gameInstance) {
            window.gameInstance.togglePause();
        }
    }
    
    // Visual effects
    createSparkle(x, y) {
        const sparkle = this.add.circle(x + Phaser.Math.Between(-10, 10), y + Phaser.Math.Between(-10, 10), 2, 0xFFFFFF);
        
        this.tweens.add({
            targets: sparkle,
            alpha: 0,
            scaleX: 2,
            scaleY: 2,
            duration: 500,
            onComplete: () => {
                sparkle.destroy();
            }
        });
    }
    
    createCollectionEffect(x, y, points) {
        // Score popup
        const scoreText = this.add.text(x, y, `+${points}`, {
            fontSize: '20px',
            fontFamily: 'Arial, sans-serif',
            fill: '#FFD700',
            stroke: '#000000',
            strokeThickness: 2
        });
        scoreText.setOrigin(0.5);
        
        this.tweens.add({
            targets: scoreText,
            y: y - 50,
            alpha: 0,
            duration: 1000,
            onComplete: () => {
                scoreText.destroy();
            }
        });
        
        // Particle burst
        for (let i = 0; i < 5; i++) {
            const particle = this.add.circle(x, y, 3, 0xFFD700);
            
            this.tweens.add({
                targets: particle,
                x: x + Phaser.Math.Between(-50, 50),
                y: y + Phaser.Math.Between(-50, 50),
                alpha: 0,
                duration: 800,
                onComplete: () => {
                    particle.destroy();
                }
            });
        }
    }
    
    createCollectibleSpawnEffect(x, y) {
        const ring = this.add.circle(x, y, 30, 0xFFD700, 0);
        ring.setStrokeStyle(3, 0xFFD700);
        
        this.tweens.add({
            targets: ring,
            scaleX: 2,
            scaleY: 2,
            alpha: 0,
            duration: 500,
            onComplete: () => {
                ring.destroy();
            }
        });
    }
    
    playBackgroundMusic() {
        if (this.sound.get('game-music')) {
            const music = this.sound.add('game-music', {
                volume: GameConfig.AUDIO.MUSIC_VOLUME,
                loop: true
            });
            music.play();
        }
    }
    
    playSound(soundKey) {
        if (GameConfig.AUDIO.ENABLED && this.sound.get(soundKey)) {
            this.sound.play(soundKey, { volume: GameConfig.AUDIO.SFX_VOLUME });
        }
    }
    
    updateUI() {
        // Update any in-game UI elements
        if (this.levelText) {
            this.levelText.setText(`Level: ${this.gameState.level}`);
        }
    }
}

// Export for use in main.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = GameScene;
}
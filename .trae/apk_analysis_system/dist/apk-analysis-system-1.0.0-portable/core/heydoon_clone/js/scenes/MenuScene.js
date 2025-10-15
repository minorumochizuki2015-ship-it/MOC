// HeyDooon Clone - Menu Scene

class MenuScene extends Phaser.Scene {
    constructor() {
        super({ key: GameConfig.STATES.MENU });
        this.menuItems = [];
        this.selectedIndex = 0;
        this.isTransitioning = false;
    }
    
    preload() {
        // Create simple colored rectangles as placeholders for graphics
        this.load.image('logo', 'data:image/svg+xml;base64,' + btoa(`
            <svg width="400" height="100" xmlns="http://www.w3.org/2000/svg">
                <rect width="400" height="100" fill="#4A90E2"/>
                <text x="200" y="60" font-family="Arial, sans-serif" font-size="36" font-weight="bold" 
                      text-anchor="middle" fill="white">HeyDooon</text>
            </svg>
        `));
        
        this.load.image('play-btn', 'data:image/svg+xml;base64,' + btoa(`
            <svg width="200" height="60" xmlns="http://www.w3.org/2000/svg">
                <rect width="200" height="60" rx="30" fill="#5CB85C"/>
                <text x="100" y="40" font-family="Arial, sans-serif" font-size="20" font-weight="bold" 
                      text-anchor="middle" fill="white">PLAY</text>
            </svg>
        `));
        
        this.load.image('settings-btn', 'data:image/svg+xml;base64,' + btoa(`
            <svg width="200" height="60" xmlns="http://www.w3.org/2000/svg">
                <rect width="200" height="60" rx="30" fill="#337AB7"/>
                <text x="100" y="40" font-family="Arial, sans-serif" font-size="20" font-weight="bold" 
                      text-anchor="middle" fill="white">SETTINGS</text>
            </svg>
        `));
        
        this.load.image('background', 'data:image/svg+xml;base64,' + btoa(`
            <svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:#87CEEB;stop-opacity:1" />
                        <stop offset="100%" style="stop-color:#4682B4;stop-opacity:1" />
                    </linearGradient>
                </defs>
                <rect width="800" height="600" fill="url(#bg)"/>
                <circle cx="150" cy="150" r="20" fill="white" opacity="0.3"/>
                <circle cx="650" cy="100" r="15" fill="white" opacity="0.2"/>
                <circle cx="700" cy="400" r="25" fill="white" opacity="0.1"/>
                <circle cx="100" cy="500" r="18" fill="white" opacity="0.2"/>
            </svg>
        `));
        
        // Load audio placeholder
        this.load.audio('menu-music', ['data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIG2m98OScTgwOUarm7blmGgU7k9n1unEiBC13yO/eizEIHWq+8+OWT']);
        
        GameUtils.log('debug', 'MenuScene preload completed');
    }
    
    create() {
        GameUtils.log('info', 'Creating MenuScene...');
        
        // Add background
        this.background = this.add.image(GameConfig.GAME.WIDTH / 2, GameConfig.GAME.HEIGHT / 2, 'background');
        this.background.setDisplaySize(GameConfig.GAME.WIDTH, GameConfig.GAME.HEIGHT);
        
        // Add logo
        this.logo = this.add.image(GameConfig.GAME.WIDTH / 2, 150, 'logo');
        this.logo.setScale(0.8);
        
        // Add floating animation to logo
        this.tweens.add({
            targets: this.logo,
            y: 140,
            duration: 2000,
            ease: 'Sine.easeInOut',
            yoyo: true,
            repeat: -1
        });
        
        // Add high score display
        const highScore = GameUtils.getHighScore();
        this.highScoreText = this.add.text(GameConfig.GAME.WIDTH / 2, 220, 
            `High Score: ${GameUtils.formatScore(highScore)}`, {
            fontSize: '24px',
            fontFamily: 'Arial, sans-serif',
            fill: '#FFFFFF',
            stroke: '#000000',
            strokeThickness: 2,
            align: 'center'
        });
        this.highScoreText.setOrigin(0.5);
        
        // Create menu buttons
        this.createMenuButtons();
        
        // Add particle effects
        this.createParticleEffects();
        
        // Setup input
        this.setupInput();
        
        // Play background music
        if (GameConfig.AUDIO.ENABLED) {
            this.playBackgroundMusic();
        }
        
        // Add version info
        this.versionText = this.add.text(10, GameConfig.GAME.HEIGHT - 30, 
            `v${GameConfig.GAME.VERSION}`, {
            fontSize: '16px',
            fontFamily: 'Arial, sans-serif',
            fill: '#FFFFFF',
            alpha: 0.7
        });
        
        GameUtils.log('info', 'MenuScene created successfully');
    }
    
    createMenuButtons() {
        const centerX = GameConfig.GAME.WIDTH / 2;
        const startY = 320;
        const spacing = 80;
        
        // Play button
        this.playButton = this.add.image(centerX, startY, 'play-btn');
        this.playButton.setInteractive({ useHandCursor: true });
        this.playButton.setScale(0.9);
        
        // Settings button
        this.settingsButton = this.add.image(centerX, startY + spacing, 'settings-btn');
        this.settingsButton.setInteractive({ useHandCursor: true });
        this.settingsButton.setScale(0.9);
        
        // Store menu items for keyboard navigation
        this.menuItems = [this.playButton, this.settingsButton];
        
        // Add hover effects
        this.menuItems.forEach((button, index) => {
            button.on('pointerover', () => {
                this.selectMenuItem(index);
            });
            
            button.on('pointerout', () => {
                this.deselectMenuItem(index);
            });
            
            button.on('pointerdown', () => {
                this.activateMenuItem(index);
            });
        });
        
        // Highlight first item
        this.selectMenuItem(0);
    }
    
    createParticleEffects() {
        // Create simple particle system using graphics
        this.particles = [];
        
        for (let i = 0; i < 20; i++) {
            const particle = this.add.circle(
                Phaser.Math.Between(0, GameConfig.GAME.WIDTH),
                Phaser.Math.Between(0, GameConfig.GAME.HEIGHT),
                Phaser.Math.Between(2, 5),
                0xFFFFFF,
                Phaser.Math.FloatBetween(0.1, 0.3)
            );
            
            // Add floating animation
            this.tweens.add({
                targets: particle,
                y: particle.y - Phaser.Math.Between(50, 150),
                x: particle.x + Phaser.Math.Between(-30, 30),
                alpha: 0,
                duration: Phaser.Math.Between(3000, 6000),
                ease: 'Power2',
                repeat: -1,
                delay: Phaser.Math.Between(0, 3000),
                onRepeat: () => {
                    particle.x = Phaser.Math.Between(0, GameConfig.GAME.WIDTH);
                    particle.y = GameConfig.GAME.HEIGHT + 10;
                    particle.alpha = Phaser.Math.FloatBetween(0.1, 0.3);
                }
            });
            
            this.particles.push(particle);
        }
    }
    
    setupInput() {
        // Keyboard input
        this.cursors = this.input.keyboard.createCursorKeys();
        this.enterKey = this.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.ENTER);
        this.spaceKey = this.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.SPACE);
        
        // Handle keyboard navigation
        this.cursors.up.on('down', () => {
            this.navigateMenu(-1);
        });
        
        this.cursors.down.on('down', () => {
            this.navigateMenu(1);
        });
        
        this.enterKey.on('down', () => {
            this.activateMenuItem(this.selectedIndex);
        });
        
        this.spaceKey.on('down', () => {
            this.activateMenuItem(this.selectedIndex);
        });
    }
    
    navigateMenu(direction) {
        if (this.isTransitioning) return;
        
        this.deselectMenuItem(this.selectedIndex);
        this.selectedIndex = (this.selectedIndex + direction + this.menuItems.length) % this.menuItems.length;
        this.selectMenuItem(this.selectedIndex);
        
        // Play navigation sound
        this.playSound('menu-navigate');
    }
    
    selectMenuItem(index) {
        if (index < 0 || index >= this.menuItems.length) return;
        
        const item = this.menuItems[index];
        this.selectedIndex = index;
        
        // Add selection effect
        this.tweens.add({
            targets: item,
            scaleX: 1.0,
            scaleY: 1.0,
            duration: 200,
            ease: 'Back.easeOut'
        });
        
        // Add glow effect
        item.setTint(0xFFFFAA);
    }
    
    deselectMenuItem(index) {
        if (index < 0 || index >= this.menuItems.length) return;
        
        const item = this.menuItems[index];
        
        // Remove selection effect
        this.tweens.add({
            targets: item,
            scaleX: 0.9,
            scaleY: 0.9,
            duration: 200,
            ease: 'Back.easeOut'
        });
        
        // Remove glow effect
        item.clearTint();
    }
    
    activateMenuItem(index) {
        if (this.isTransitioning) return;
        
        this.isTransitioning = true;
        const item = this.menuItems[index];
        
        // Play selection sound
        this.playSound('menu-select');
        
        // Add press animation
        this.tweens.add({
            targets: item,
            scaleX: 0.85,
            scaleY: 0.85,
            duration: 100,
            ease: 'Power2',
            yoyo: true,
            onComplete: () => {
                this.handleMenuSelection(index);
            }
        });
    }
    
    handleMenuSelection(index) {
        switch (index) {
            case 0: // Play
                this.startGame();
                break;
            case 1: // Settings
                this.openSettings();
                break;
        }
    }
    
    startGame() {
        GameUtils.log('info', 'Starting game...');
        
        // Fade out effect
        this.cameras.main.fadeOut(500, 0, 0, 0);
        
        this.cameras.main.once('camerafadeoutcomplete', () => {
            this.scene.start(GameConfig.STATES.GAME);
        });
    }
    
    openSettings() {
        GameUtils.log('info', 'Opening settings...');
        
        // For now, just show an alert
        // In a full implementation, this would open a settings scene
        this.showMessage('Settings coming soon!');
        this.isTransitioning = false;
    }
    
    showMessage(text) {
        const messageBox = this.add.rectangle(
            GameConfig.GAME.WIDTH / 2, 
            GameConfig.GAME.HEIGHT / 2, 
            300, 100, 
            0x000000, 
            0.8
        );
        
        const messageText = this.add.text(
            GameConfig.GAME.WIDTH / 2, 
            GameConfig.GAME.HEIGHT / 2, 
            text, {
            fontSize: '20px',
            fontFamily: 'Arial, sans-serif',
            fill: '#FFFFFF',
            align: 'center'
        });
        messageText.setOrigin(0.5);
        
        // Auto-hide after 2 seconds
        this.time.delayedCall(2000, () => {
            messageBox.destroy();
            messageText.destroy();
        });
    }
    
    playBackgroundMusic() {
        if (this.sound.get('menu-music')) {
            const music = this.sound.add('menu-music', {
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
    
    update() {
        // Update particle effects or other animations if needed
        // This runs every frame
    }
}

// Export for use in main.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = MenuScene;
}
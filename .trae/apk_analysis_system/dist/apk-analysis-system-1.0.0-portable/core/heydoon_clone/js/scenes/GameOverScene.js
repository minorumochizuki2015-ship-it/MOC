// HeyDooon Clone - Game Over Scene

class GameOverScene extends Phaser.Scene {
    constructor() {
        super({ key: GameConfig.STATES.GAME_OVER });
        
        this.finalScore = 0;
        this.isNewHighScore = false;
        this.menuItems = [];
        this.selectedIndex = 0;
        this.isTransitioning = false;
    }
    
    init(data) {
        // Receive data from GameScene
        this.finalScore = data.score || 0;
        this.isNewHighScore = data.isNewHighScore || false;
        
        GameUtils.log('info', 'GameOverScene initialized with score:', this.finalScore);
    }
    
    preload() {
        // Create game over graphics
        this.load.image('game-over-bg', 'data:image/svg+xml;base64,' + btoa(`
            <svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <radialGradient id="gameOverBg" cx="50%" cy="50%" r="50%">
                        <stop offset="0%" style="stop-color:#2C3E50;stop-opacity:0.9" />
                        <stop offset="100%" style="stop-color:#000000;stop-opacity:0.95" />
                    </radialGradient>
                </defs>
                <rect width="800" height="600" fill="url(#gameOverBg)"/>
                <circle cx="400" cy="300" r="200" fill="none" stroke="#34495E" stroke-width="2" opacity="0.3"/>
                <circle cx="400" cy="300" r="150" fill="none" stroke="#34495E" stroke-width="1" opacity="0.2"/>
                <circle cx="400" cy="300" r="100" fill="none" stroke="#34495E" stroke-width="1" opacity="0.1"/>
            </svg>
        `));
        
        this.load.image('play-again-btn', 'data:image/svg+xml;base64,' + btoa(`
            <svg width="200" height="60" xmlns="http://www.w3.org/2000/svg">
                <rect width="200" height="60" rx="30" fill="#27AE60" stroke="#229954" stroke-width="2"/>
                <text x="100" y="40" font-family="Arial, sans-serif" font-size="18" font-weight="bold" 
                      text-anchor="middle" fill="white">PLAY AGAIN</text>
            </svg>
        `));
        
        this.load.image('menu-btn', 'data:image/svg+xml;base64,' + btoa(`
            <svg width="200" height="60" xmlns="http://www.w3.org/2000/svg">
                <rect width="200" height="60" rx="30" fill="#3498DB" stroke="#2980B9" stroke-width="2"/>
                <text x="100" y="40" font-family="Arial, sans-serif" font-size="18" font-weight="bold" 
                      text-anchor="middle" fill="white">MAIN MENU</text>
            </svg>
        `));
        
        // Load game over sound
        this.load.audio('game-over', ['data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIG2m98OScTgwOUarm7blmGgU7k9n1unEiBC13yO/eizEIHWq+8+OWT']);
        this.load.audio('new-high-score', ['data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIG2m98OScTgwOUarm7blmGgU7k9n1unEiBC13yO/eizEIHWq+8+OWT']);
        
        GameUtils.log('debug', 'GameOverScene preload completed');
    }
    
    create() {
        GameUtils.log('info', 'Creating GameOverScene...');
        
        // Add background
        this.background = this.add.image(GameConfig.GAME.WIDTH / 2, GameConfig.GAME.HEIGHT / 2, 'game-over-bg');
        this.background.setDisplaySize(GameConfig.GAME.WIDTH, GameConfig.GAME.HEIGHT);
        
        // Create game over title
        this.createGameOverTitle();
        
        // Create score display
        this.createScoreDisplay();
        
        // Create statistics
        this.createStatistics();
        
        // Create menu buttons
        this.createMenuButtons();
        
        // Setup input
        this.setupInput();
        
        // Add visual effects
        this.createVisualEffects();
        
        // Play appropriate sound
        this.playGameOverSound();
        
        // Animate entrance
        this.animateEntrance();
        
        GameUtils.log('info', 'GameOverScene created successfully');
    }
    
    createGameOverTitle() {
        // Main "GAME OVER" text
        this.gameOverText = this.add.text(GameConfig.GAME.WIDTH / 2, 120, 'GAME OVER', {
            fontSize: '48px',
            fontFamily: 'Arial, sans-serif',
            fill: '#E74C3C',
            stroke: '#000000',
            strokeThickness: 4,
            align: 'center',
            fontWeight: 'bold'
        });
        this.gameOverText.setOrigin(0.5);
        
        // Add glow effect
        this.gameOverText.setShadow(0, 0, '#E74C3C', 10, true, true);
        
        // Pulsing animation
        this.tweens.add({
            targets: this.gameOverText,
            scaleX: 1.05,
            scaleY: 1.05,
            duration: 1000,
            ease: 'Sine.easeInOut',
            yoyo: true,
            repeat: -1
        });
    }
    
    createScoreDisplay() {
        const centerX = GameConfig.GAME.WIDTH / 2;
        let currentY = 200;
        
        // Final score
        this.finalScoreText = this.add.text(centerX, currentY, 
            `Final Score: ${GameUtils.formatScore(this.finalScore)}`, {
            fontSize: '32px',
            fontFamily: 'Arial, sans-serif',
            fill: '#F39C12',
            stroke: '#000000',
            strokeThickness: 2,
            align: 'center',
            fontWeight: 'bold'
        });
        this.finalScoreText.setOrigin(0.5);
        currentY += 60;
        
        // High score status
        const highScore = GameUtils.getHighScore();
        if (this.isNewHighScore) {
            this.highScoreText = this.add.text(centerX, currentY, 
                '🎉 NEW HIGH SCORE! 🎉', {
                fontSize: '24px',
                fontFamily: 'Arial, sans-serif',
                fill: '#FFD700',
                stroke: '#000000',
                strokeThickness: 2,
                align: 'center',
                fontWeight: 'bold'
            });
            
            // Celebration animation
            this.tweens.add({
                targets: this.highScoreText,
                scaleX: 1.1,
                scaleY: 1.1,
                duration: 500,
                ease: 'Back.easeOut',
                yoyo: true,
                repeat: -1
            });
            
            // Rainbow color effect
            this.time.addEvent({
                delay: 200,
                callback: () => {
                    const colors = ['#FFD700', '#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7'];
                    const randomColor = colors[Math.floor(Math.random() * colors.length)];
                    this.highScoreText.setFill(randomColor);
                },
                loop: true
            });
        } else {
            this.highScoreText = this.add.text(centerX, currentY, 
                `High Score: ${GameUtils.formatScore(highScore)}`, {
                fontSize: '20px',
                fontFamily: 'Arial, sans-serif',
                fill: '#BDC3C7',
                stroke: '#000000',
                strokeThickness: 1,
                align: 'center'
            });
        }
        this.highScoreText.setOrigin(0.5);
    }
    
    createStatistics() {
        const centerX = GameConfig.GAME.WIDTH / 2;
        const startY = 320;
        
        // Get game statistics
        const stats = this.getGameStatistics();
        
        // Statistics container
        this.statsContainer = this.add.container(centerX, startY);
        
        // Statistics background
        const statsBg = this.add.rectangle(0, 0, 400, 120, 0x2C3E50, 0.8);
        statsBg.setStrokeStyle(2, 0x34495E);
        this.statsContainer.add(statsBg);
        
        // Statistics title
        const statsTitle = this.add.text(0, -40, 'Game Statistics', {
            fontSize: '18px',
            fontFamily: 'Arial, sans-serif',
            fill: '#ECF0F1',
            fontWeight: 'bold',
            align: 'center'
        });
        statsTitle.setOrigin(0.5);
        this.statsContainer.add(statsTitle);
        
        // Individual stats
        const statTexts = [
            `Time Played: ${stats.timePlayed}`,
            `Items Collected: ${stats.itemsCollected}`,
            `Enemies Defeated: ${stats.enemiesDefeated}`,
            `Levels Completed: ${stats.levelsCompleted}`
        ];
        
        statTexts.forEach((text, index) => {
            const statText = this.add.text(-150, -10 + (index * 20), text, {
                fontSize: '14px',
                fontFamily: 'Arial, sans-serif',
                fill: '#BDC3C7'
            });
            this.statsContainer.add(statText);
        });
    }
    
    createMenuButtons() {
        const centerX = GameConfig.GAME.WIDTH / 2;
        const startY = 480;
        const spacing = 80;
        
        // Play Again button
        this.playAgainButton = this.add.image(centerX - spacing, startY, 'play-again-btn');
        this.playAgainButton.setInteractive({ useHandCursor: true });
        this.playAgainButton.setScale(0.9);
        
        // Main Menu button
        this.mainMenuButton = this.add.image(centerX + spacing, startY, 'menu-btn');
        this.mainMenuButton.setInteractive({ useHandCursor: true });
        this.mainMenuButton.setScale(0.9);
        
        // Store menu items for keyboard navigation
        this.menuItems = [this.playAgainButton, this.mainMenuButton];
        
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
    
    setupInput() {
        // Keyboard input
        this.cursors = this.input.keyboard.createCursorKeys();
        this.enterKey = this.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.ENTER);
        this.spaceKey = this.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.SPACE);
        this.rKey = this.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.R);
        this.escKey = this.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.ESC);
        
        // Handle keyboard navigation
        this.cursors.left.on('down', () => {
            this.navigateMenu(-1);
        });
        
        this.cursors.right.on('down', () => {
            this.navigateMenu(1);
        });
        
        this.enterKey.on('down', () => {
            this.activateMenuItem(this.selectedIndex);
        });
        
        this.spaceKey.on('down', () => {
            this.activateMenuItem(this.selectedIndex);
        });
        
        // Quick restart with R key
        this.rKey.on('down', () => {
            this.activateMenuItem(0); // Play Again
        });
        
        // Quick menu with Escape
        this.escKey.on('down', () => {
            this.activateMenuItem(1); // Main Menu
        });
    }
    
    createVisualEffects() {
        // Floating particles
        this.createFloatingParticles();
        
        // Screen flash for new high score
        if (this.isNewHighScore) {
            this.createHighScoreEffect();
        }
    }
    
    createFloatingParticles() {
        this.particles = [];
        
        for (let i = 0; i < 15; i++) {
            const particle = this.add.circle(
                Phaser.Math.Between(0, GameConfig.GAME.WIDTH),
                Phaser.Math.Between(0, GameConfig.GAME.HEIGHT),
                Phaser.Math.Between(1, 3),
                0x34495E,
                0.5
            );
            
            // Slow floating animation
            this.tweens.add({
                targets: particle,
                y: particle.y - Phaser.Math.Between(100, 200),
                x: particle.x + Phaser.Math.Between(-50, 50),
                alpha: 0,
                duration: Phaser.Math.Between(5000, 8000),
                ease: 'Power1',
                repeat: -1,
                delay: Phaser.Math.Between(0, 5000),
                onRepeat: () => {
                    particle.x = Phaser.Math.Between(0, GameConfig.GAME.WIDTH);
                    particle.y = GameConfig.GAME.HEIGHT + 10;
                    particle.alpha = 0.5;
                }
            });
            
            this.particles.push(particle);
        }
    }
    
    createHighScoreEffect() {
        // Screen flash
        const flash = this.add.rectangle(
            GameConfig.GAME.WIDTH / 2, 
            GameConfig.GAME.HEIGHT / 2, 
            GameConfig.GAME.WIDTH, 
            GameConfig.GAME.HEIGHT, 
            0xFFD700, 
            0.3
        );
        
        this.tweens.add({
            targets: flash,
            alpha: 0,
            duration: 1000,
            onComplete: () => {
                flash.destroy();
            }
        });
        
        // Confetti effect
        for (let i = 0; i < 20; i++) {
            const confetti = this.add.rectangle(
                Phaser.Math.Between(0, GameConfig.GAME.WIDTH),
                -20,
                Phaser.Math.Between(5, 10),
                Phaser.Math.Between(5, 10),
                Phaser.Math.Between(0x000000, 0xFFFFFF)
            );
            
            this.tweens.add({
                targets: confetti,
                y: GameConfig.GAME.HEIGHT + 20,
                x: confetti.x + Phaser.Math.Between(-100, 100),
                rotation: Phaser.Math.Between(0, Math.PI * 4),
                duration: Phaser.Math.Between(2000, 4000),
                delay: Phaser.Math.Between(0, 2000),
                onComplete: () => {
                    confetti.destroy();
                }
            });
        }
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
            case 0: // Play Again
                this.restartGame();
                break;
            case 1: // Main Menu
                this.goToMainMenu();
                break;
        }
    }
    
    restartGame() {
        GameUtils.log('info', 'Restarting game from GameOverScene...');
        
        // Fade out effect
        this.cameras.main.fadeOut(500, 0, 0, 0);
        
        this.cameras.main.once('camerafadeoutcomplete', () => {
            this.scene.start(GameConfig.STATES.GAME);
        });
    }
    
    goToMainMenu() {
        GameUtils.log('info', 'Going to main menu from GameOverScene...');
        
        // Fade out effect
        this.cameras.main.fadeOut(500, 0, 0, 0);
        
        this.cameras.main.once('camerafadeoutcomplete', () => {
            this.scene.start(GameConfig.STATES.MENU);
        });
    }
    
    animateEntrance() {
        // Set initial states
        this.gameOverText.setAlpha(0);
        this.finalScoreText.setAlpha(0);
        this.highScoreText.setAlpha(0);
        this.statsContainer.setAlpha(0);
        this.menuItems.forEach(item => item.setAlpha(0));
        
        // Animate in sequence
        this.tweens.add({
            targets: this.gameOverText,
            alpha: 1,
            scaleX: 1.2,
            scaleY: 1.2,
            duration: 800,
            ease: 'Back.easeOut',
            onComplete: () => {
                this.tweens.add({
                    targets: this.gameOverText,
                    scaleX: 1,
                    scaleY: 1,
                    duration: 300
                });
            }
        });
        
        this.time.delayedCall(400, () => {
            this.tweens.add({
                targets: this.finalScoreText,
                alpha: 1,
                y: this.finalScoreText.y - 20,
                duration: 600,
                ease: 'Power2.easeOut'
            });
        });
        
        this.time.delayedCall(800, () => {
            this.tweens.add({
                targets: this.highScoreText,
                alpha: 1,
                duration: 400
            });
        });
        
        this.time.delayedCall(1200, () => {
            this.tweens.add({
                targets: this.statsContainer,
                alpha: 1,
                duration: 600,
                ease: 'Power2.easeOut'
            });
        });
        
        this.time.delayedCall(1600, () => {
            this.menuItems.forEach((item, index) => {
                this.time.delayedCall(index * 200, () => {
                    this.tweens.add({
                        targets: item,
                        alpha: 1,
                        y: item.y - 10,
                        duration: 400,
                        ease: 'Back.easeOut'
                    });
                });
            });
        });
    }
    
    getGameStatistics() {
        // Calculate game statistics
        const itemsCollected = Math.floor(this.finalScore / GameConfig.SCORING.COLLECTIBLE_POINTS);
        const enemiesDefeated = Math.floor(itemsCollected * 0.3); // Estimate
        const levelsCompleted = Math.floor(itemsCollected / GameConfig.LEVEL.COLLECTIBLES_TO_COMPLETE);
        const timePlayed = this.formatTime(GameConfig.LEVEL.TIME_LIMIT - (this.scene.get(GameConfig.STATES.GAME)?.gameState?.timeRemaining || 0));
        
        return {
            timePlayed,
            itemsCollected,
            enemiesDefeated,
            levelsCompleted
        };
    }
    
    formatTime(seconds) {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
    }
    
    playGameOverSound() {
        if (GameConfig.AUDIO.ENABLED) {
            if (this.isNewHighScore && this.sound.get('new-high-score')) {
                this.sound.play('new-high-score', { volume: GameConfig.AUDIO.SFX_VOLUME });
            } else if (this.sound.get('game-over')) {
                this.sound.play('game-over', { volume: GameConfig.AUDIO.SFX_VOLUME });
            }
        }
    }
    
    playSound(soundKey) {
        if (GameConfig.AUDIO.ENABLED && this.sound.get(soundKey)) {
            this.sound.play(soundKey, { volume: GameConfig.AUDIO.SFX_VOLUME });
        }
    }
    
    update() {
        // Update any animations or effects if needed
    }
}

// Export for use in main.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = GameOverScene;
}
/**
 * HeyDooon Clone - Reaction Speed Game
 * 元のHeyDooonゲームを忠実に再現したリアクションゲーム
 */

class HeyDooonGame {
    constructor() {
        this.gameState = 'loading';
        this.score = 0;
        this.currentChallenge = null;
        this.challengeIndex = 0;
        this.challenges = [];
        this.reactionTimes = [];
        this.challengeStartTime = 0;
        this.timerInterval = null;
        this.timeRemaining = 0;
        this.difficulty = 'normal';
        this.highScore = this.loadHighScore();
        this.tapCount = 0;
        this.correctAnswers = 0;
        
        // Challenge types
        this.challengeTypes = {
            COLOR: 'color',
            SHAPE: 'shape', 
            SPEED: 'speed',
            MULTI_TAP: 'multi_tap'
        };
        
        // Difficulty settings
        this.difficultySettings = {
            easy: { timeLimit: 3.0, challengeCount: 10 },
            normal: { timeLimit: 2.0, challengeCount: 15 },
            hard: { timeLimit: 1.5, challengeCount: 20 },
            expert: { timeLimit: 1.0, challengeCount: 25 }
        };
        
        this.colors = [
            { name: 'red', value: '#FF4444', rgb: [255, 68, 68] },
            { name: 'blue', value: '#4444FF', rgb: [68, 68, 255] },
            { name: 'green', value: '#44FF44', rgb: [68, 255, 68] },
            { name: 'yellow', value: '#FFFF44', rgb: [255, 255, 68] },
            { name: 'purple', value: '#FF44FF', rgb: [255, 68, 255] },
            { name: 'orange', value: '#FF8844', rgb: [255, 136, 68] }
        ];
        
        this.shapes = ['circle', 'square', 'triangle', 'diamond'];
        
        this.sounds = {
            correct: document.getElementById('correct-sound'),
            wrong: document.getElementById('wrong-sound')
        };
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.showScreen('loading');
        
        // Simulate loading
        setTimeout(() => {
            this.gameState = 'menu';
            this.showScreen('menu');
            this.updateUI();
        }, 1500);
    }
    
    setupEventListeners() {
        // Menu buttons
        document.getElementById('start-btn').addEventListener('click', () => this.startGame());
        document.getElementById('difficulty-btn').addEventListener('click', () => this.cycleDifficulty());
        
        // Game buttons
        document.getElementById('pause-btn').addEventListener('click', () => this.pauseGame());
        document.getElementById('resume-btn').addEventListener('click', () => this.resumeGame());
        document.getElementById('restart-btn').addEventListener('click', () => this.restartGame());
        document.getElementById('menu-btn').addEventListener('click', () => this.goToMenu());
        
        // Game over buttons
        document.getElementById('play-again-btn').addEventListener('click', () => this.startGame());
        document.getElementById('main-menu-btn').addEventListener('click', () => this.goToMenu());
        
        // Challenge area click
        document.getElementById('challenge-area').addEventListener('click', (e) => this.handleChallengeClick(e));
        
        // Keyboard controls
        document.addEventListener('keydown', (e) => this.handleKeyPress(e));
    }
    
    showScreen(screenName) {
        const screens = document.querySelectorAll('.screen');
        screens.forEach(screen => {
            screen.classList.remove('active');
        });
        
        const targetScreen = document.getElementById(`${screenName}-screen`);
        if (targetScreen) {
            targetScreen.classList.add('active');
        }
    }
    
    cycleDifficulty() {
        const difficulties = ['easy', 'normal', 'hard', 'expert'];
        const currentIndex = difficulties.indexOf(this.difficulty);
        this.difficulty = difficulties[(currentIndex + 1) % difficulties.length];
        this.updateUI();
    }
    
    startGame() {
        this.gameState = 'playing';
        this.score = 0;
        this.challengeIndex = 0;
        this.reactionTimes = [];
        this.correctAnswers = 0;
        this.generateChallenges();
        this.showScreen('game');
        this.startNextChallenge();
    }
    
    generateChallenges() {
        this.challenges = [];
        const settings = this.difficultySettings[this.difficulty];
        const challengeCount = settings.challengeCount;
        
        // Generate color challenges (40%)
        for (let i = 0; i < Math.floor(challengeCount * 0.4); i++) {
            const targetColor = this.colors[Math.floor(Math.random() * this.colors.length)];
            const distractorColors = this.colors.filter(c => c.name !== targetColor.name);
            
            this.challenges.push({
                type: this.challengeTypes.COLOR,
                instruction: `Tap ${targetColor.name.toUpperCase()}!`,
                targetColor: targetColor,
                distractorColors: this.shuffleArray(distractorColors).slice(0, 3),
                timeLimit: settings.timeLimit,
                points: 100
            });
        }
        
        // Generate shape challenges (30%)
        for (let i = 0; i < Math.floor(challengeCount * 0.3); i++) {
            const targetShape = this.shapes[Math.floor(Math.random() * this.shapes.length)];
            const distractorShapes = this.shapes.filter(s => s !== targetShape);
            
            this.challenges.push({
                type: this.challengeTypes.SHAPE,
                instruction: `Tap ${targetShape.toUpperCase()}!`,
                targetShape: targetShape,
                distractorShapes: this.shuffleArray(distractorShapes).slice(0, 2),
                timeLimit: settings.timeLimit,
                points: 150
            });
        }
        
        // Generate speed challenges (20%)
        for (let i = 0; i < Math.floor(challengeCount * 0.2); i++) {
            this.challenges.push({
                type: this.challengeTypes.SPEED,
                instruction: 'Tap when screen flashes!',
                timeLimit: settings.timeLimit * 0.8,
                points: 200
            });
        }
        
        // Generate multi-tap challenges (10%)
        for (let i = 0; i < Math.floor(challengeCount * 0.1); i++) {
            this.challenges.push({
                type: this.challengeTypes.MULTI_TAP,
                instruction: 'Triple tap quickly!',
                timeLimit: settings.timeLimit * 1.5,
                points: 300,
                requiredTaps: 3
            });
        }
        
        // Fill remaining slots with color challenges
        while (this.challenges.length < challengeCount) {
            const targetColor = this.colors[Math.floor(Math.random() * this.colors.length)];
            const distractorColors = this.colors.filter(c => c.name !== targetColor.name);
            
            this.challenges.push({
                type: this.challengeTypes.COLOR,
                instruction: `Tap ${targetColor.name.toUpperCase()}!`,
                targetColor: targetColor,
                distractorColors: this.shuffleArray(distractorColors).slice(0, 3),
                timeLimit: settings.timeLimit,
                points: 100
            });
        }
        
        this.challenges = this.shuffleArray(this.challenges);
    }
    
    startNextChallenge() {
        if (this.challengeIndex >= this.challenges.length) {
            this.endGame();
            return;
        }
        
        this.currentChallenge = this.challenges[this.challengeIndex];
        this.tapCount = 0;
        this.timeRemaining = this.currentChallenge.timeLimit;
        
        this.updateUI();
        this.displayChallenge();
        
        // Start timer after a brief delay
        setTimeout(() => {
            this.challengeStartTime = Date.now();
            this.startChallengeTimer();
        }, 500);
    }
    
    displayChallenge() {
        const instructionEl = document.getElementById('instruction-text');
        const contentEl = document.getElementById('challenge-content');
        const feedbackEl = document.getElementById('reaction-feedback');
        
        instructionEl.textContent = this.currentChallenge.instruction;
        feedbackEl.textContent = '';
        contentEl.innerHTML = '';
        
        switch (this.currentChallenge.type) {
            case this.challengeTypes.COLOR:
                this.displayColorChallenge(contentEl);
                break;
            case this.challengeTypes.SHAPE:
                this.displayShapeChallenge(contentEl);
                break;
            case this.challengeTypes.SPEED:
                this.displaySpeedChallenge(contentEl);
                break;
            case this.challengeTypes.MULTI_TAP:
                this.displayMultiTapChallenge(contentEl);
                break;
        }
    }
    
    displayColorChallenge(container) {
        const allColors = [this.currentChallenge.targetColor, ...this.currentChallenge.distractorColors];
        const shuffledColors = this.shuffleArray(allColors);
        
        shuffledColors.forEach(color => {
            const colorDiv = document.createElement('div');
            colorDiv.className = 'color-option';
            colorDiv.style.backgroundColor = color.value;
            colorDiv.dataset.colorName = color.name;
            container.appendChild(colorDiv);
        });
    }
    
    displayShapeChallenge(container) {
        const allShapes = [this.currentChallenge.targetShape, ...this.currentChallenge.distractorShapes];
        const shuffledShapes = this.shuffleArray(allShapes);
        
        shuffledShapes.forEach(shape => {
            const shapeDiv = document.createElement('div');
            shapeDiv.className = `shape-option shape-${shape}`;
            shapeDiv.dataset.shapeName = shape;
            container.appendChild(shapeDiv);
        });
    }
    
    displaySpeedChallenge(container) {
        const speedDiv = document.createElement('div');
        speedDiv.className = 'speed-challenge';
        speedDiv.textContent = 'Wait for flash...';
        container.appendChild(speedDiv);
        
        // Flash after random delay
        const flashDelay = 1000 + Math.random() * 2000;
        setTimeout(() => {
            if (this.gameState === 'playing') {
                speedDiv.classList.add('flash');
                speedDiv.textContent = 'TAP NOW!';
            }
        }, flashDelay);
    }
    
    displayMultiTapChallenge(container) {
        const multiTapDiv = document.createElement('div');
        multiTapDiv.className = 'multi-tap-challenge';
        multiTapDiv.innerHTML = `
            <div class="tap-target">TAP HERE</div>
            <div class="tap-counter">Taps: <span id="tap-count">0</span>/${this.currentChallenge.requiredTaps}</div>
        `;
        container.appendChild(multiTapDiv);
    }
    
    handleChallengeClick(event) {
        if (this.gameState !== 'playing' || !this.currentChallenge) return;
        
        const reactionTime = (Date.now() - this.challengeStartTime) / 1000;
        let success = false;
        
        switch (this.currentChallenge.type) {
            case this.challengeTypes.COLOR:
                const clickedColor = event.target.dataset.colorName;
                success = clickedColor === this.currentChallenge.targetColor.name;
                break;
                
            case this.challengeTypes.SHAPE:
                const clickedShape = event.target.dataset.shapeName;
                success = clickedShape === this.currentChallenge.targetShape;
                break;
                
            case this.challengeTypes.SPEED:
                const speedEl = document.querySelector('.speed-challenge');
                success = speedEl && speedEl.classList.contains('flash');
                break;
                
            case this.challengeTypes.MULTI_TAP:
                if (event.target.classList.contains('tap-target') || event.target.closest('.multi-tap-challenge')) {
                    this.tapCount++;
                    document.getElementById('tap-count').textContent = this.tapCount;
                    
                    if (this.tapCount >= this.currentChallenge.requiredTaps) {
                        success = true;
                    } else {
                        return; // Don't complete challenge yet
                    }
                }
                break;
        }
        
        this.completeChallenge(success, reactionTime);
    }
    
    completeChallenge(success, reactionTime) {
        this.clearChallengeTimer();
        
        const feedbackEl = document.getElementById('reaction-feedback');
        
        if (success && reactionTime <= this.currentChallenge.timeLimit) {
            // Success
            const timeBonus = Math.max(0, 1 - (reactionTime / this.currentChallenge.timeLimit));
            const points = Math.floor(this.currentChallenge.points * (0.5 + timeBonus * 0.5));
            this.score += points;
            this.correctAnswers++;
            this.reactionTimes.push(reactionTime);
            
            feedbackEl.textContent = `+${points} points! (${reactionTime.toFixed(3)}s)`;
            feedbackEl.className = 'reaction-feedback success';
            
            if (this.sounds.correct) {
                this.sounds.correct.play().catch(() => {});
            }
        } else {
            // Failure
            feedbackEl.textContent = success ? 'Too slow!' : 'Wrong!';
            feedbackEl.className = 'reaction-feedback failure';
            
            if (this.sounds.wrong) {
                this.sounds.wrong.play().catch(() => {});
            }
        }
        
        // Move to next challenge after delay
        setTimeout(() => {
            this.challengeIndex++;
            this.startNextChallenge();
        }, 1500);
    }
    
    startChallengeTimer() {
        this.timerInterval = setInterval(() => {
            this.timeRemaining -= 0.1;
            
            if (this.timeRemaining <= 0) {
                this.completeChallenge(false, this.currentChallenge.timeLimit + 0.1);
            } else {
                this.updateTimerDisplay();
            }
        }, 100);
    }
    
    clearChallengeTimer() {
        if (this.timerInterval) {
            clearInterval(this.timerInterval);
            this.timerInterval = null;
        }
    }
    
    updateTimerDisplay() {
        const timerEl = document.getElementById('challenge-timer');
        const progressEl = document.getElementById('time-fill');
        
        if (timerEl) {
            timerEl.textContent = Math.max(0, this.timeRemaining).toFixed(1);
        }
        
        if (progressEl && this.currentChallenge) {
            const progress = Math.max(0, this.timeRemaining / this.currentChallenge.timeLimit);
            progressEl.style.width = `${progress * 100}%`;
            
            // Change color based on remaining time
            if (progress < 0.3) {
                progressEl.style.backgroundColor = '#ff4444';
            } else if (progress < 0.6) {
                progressEl.style.backgroundColor = '#ffaa44';
            } else {
                progressEl.style.backgroundColor = '#44ff44';
            }
        }
    }
    
    pauseGame() {
        if (this.gameState === 'playing') {
            this.gameState = 'paused';
            this.clearChallengeTimer();
            this.showScreen('pause');
        }
    }
    
    resumeGame() {
        if (this.gameState === 'paused') {
            this.gameState = 'playing';
            this.showScreen('game');
            this.challengeStartTime = Date.now(); // Reset timer
            this.startChallengeTimer();
        }
    }
    
    restartGame() {
        this.clearChallengeTimer();
        this.startGame();
    }
    
    goToMenu() {
        this.clearChallengeTimer();
        this.gameState = 'menu';
        this.showScreen('menu');
        this.updateUI();
    }
    
    endGame() {
        this.clearChallengeTimer();
        this.gameState = 'gameover';
        
        // Check for high score
        const isNewHighScore = this.score > this.highScore;
        if (isNewHighScore) {
            this.highScore = this.score;
            this.saveHighScore();
        }
        
        this.showGameOverScreen(isNewHighScore);
        this.showScreen('gameover');
    }
    
    showGameOverScreen(isNewHighScore) {
        const accuracy = this.challenges.length > 0 ? (this.correctAnswers / this.challenges.length * 100) : 0;
        const avgReaction = this.reactionTimes.length > 0 ? 
            this.reactionTimes.reduce((a, b) => a + b, 0) / this.reactionTimes.length : 0;
        
        document.getElementById('final-score').textContent = this.score;
        document.getElementById('accuracy-stat').textContent = `${accuracy.toFixed(1)}%`;
        document.getElementById('reaction-stat').textContent = `${avgReaction.toFixed(3)}s`;
        document.getElementById('challenges-stat').textContent = `${this.correctAnswers}/${this.challenges.length}`;
        
        const newHighScoreEl = document.getElementById('new-highscore');
        if (isNewHighScore) {
            newHighScoreEl.classList.remove('hidden');
        } else {
            newHighScoreEl.classList.add('hidden');
        }
    }
    
    updateUI() {
        // Update menu
        document.getElementById('difficulty-text').textContent = this.difficulty.toUpperCase();
        document.getElementById('highscore-text').textContent = this.highScore;
        
        // Update game UI
        if (document.getElementById('current-score')) {
            document.getElementById('current-score').textContent = this.score;
        }
        
        if (document.getElementById('challenge-progress') && this.challenges.length > 0) {
            document.getElementById('challenge-progress').textContent = 
                `${this.challengeIndex + 1}/${this.challenges.length}`;
        }
    }
    
    handleKeyPress(event) {
        switch (event.code) {
            case 'Space':
                event.preventDefault();
                if (this.gameState === 'menu') {
                    this.startGame();
                } else if (this.gameState === 'playing') {
                    // Space can be used for challenges
                    this.handleChallengeClick({ target: document.getElementById('challenge-content') });
                }
                break;
            case 'Escape':
                if (this.gameState === 'playing') {
                    this.pauseGame();
                } else if (this.gameState === 'paused') {
                    this.resumeGame();
                }
                break;
        }
    }
    
    shuffleArray(array) {
        const shuffled = [...array];
        for (let i = shuffled.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        return shuffled;
    }
    
    loadHighScore() {
        return parseInt(localStorage.getItem('heydoon-highscore') || '0');
    }
    
    saveHighScore() {
        localStorage.setItem('heydoon-highscore', this.highScore.toString());
    }
}

// Initialize game when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.game = new HeyDooonGame();
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (document.hidden && window.game && window.game.gameState === 'playing') {
        window.game.pauseGame();
    }
});
using UnityEngine;
using UnityEngine.SceneManagement;

public class GameManager : MonoBehaviour
{
    public static GameManager Instance { get; private set; }
    
    [Header("Game Settings")]
    public int targetFrameRate = 60;
    public bool debugMode = false;
    
    [Header("Game State")]
    public GameState currentState = GameState.Menu;
    public int currentScore = 0;
    public int currentLevel = 1;
    
    public enum GameState
    {
        Menu,
        Playing,
        Paused,
        GameOver
    }
    
    private void Awake()
    {
        if (Instance == null)
        {
            Instance = this;
            DontDestroyOnLoad(gameObject);
            InitializeGame();
        }
        else
        {
            Destroy(gameObject);
        }
    }
    
    private void InitializeGame()
    {
        Application.targetFrameRate = targetFrameRate;
        
        // Initialize game systems
        Debug.Log("Game Manager initialized");
    }
    
    public void StartGame()
    {
        currentState = GameState.Playing;
        currentScore = 0;
        currentLevel = 1;
        
        // Load game scene
        SceneManager.LoadScene("GameScene");
    }
    
    public void PauseGame()
    {
        if (currentState == GameState.Playing)
        {
            currentState = GameState.Paused;
            Time.timeScale = 0f;
        }
    }
    
    public void ResumeGame()
    {
        if (currentState == GameState.Paused)
        {
            currentState = GameState.Playing;
            Time.timeScale = 1f;
        }
    }
    
    public void GameOver()
    {
        currentState = GameState.GameOver;
        Time.timeScale = 0f;
        
        // Show game over UI
        if (UIManager.Instance != null)
        {
            UIManager.Instance.ShowGameOverScreen();
        }
    }
    
    public void AddScore(int points)
    {
        currentScore += points;
        
        // Update UI
        if (UIManager.Instance != null)
        {
            UIManager.Instance.UpdateScore(currentScore);
        }
    }
    
    public void NextLevel()
    {
        currentLevel++;
        
        // Level progression logic
        Debug.Log($"Advanced to level {currentLevel}");
    }
}
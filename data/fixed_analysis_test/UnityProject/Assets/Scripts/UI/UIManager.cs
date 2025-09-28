using UnityEngine;
using UnityEngine.UI;
using TMPro;

public class UIManager : MonoBehaviour
{
    public static UIManager Instance { get; private set; }
    
    [Header("UI Panels")]
    public GameObject mainMenuPanel;
    public GameObject gameplayPanel;
    public GameObject pausePanel;
    public GameObject gameOverPanel;
    
    [Header("UI Elements")]
    public TextMeshProUGUI scoreText;
    public TextMeshProUGUI levelText;
    public Button startButton;
    public Button pauseButton;
    public Button resumeButton;
    public Button restartButton;
    
    private void Awake()
    {
        if (Instance == null)
        {
            Instance = this;
            InitializeUI();
        }
        else
        {
            Destroy(gameObject);
        }
    }
    
    private void InitializeUI()
    {
        // Setup button listeners
        if (startButton != null)
            startButton.onClick.AddListener(StartGame);
        
        if (pauseButton != null)
            pauseButton.onClick.AddListener(PauseGame);
        
        if (resumeButton != null)
            resumeButton.onClick.AddListener(ResumeGame);
        
        if (restartButton != null)
            restartButton.onClick.AddListener(RestartGame);
        
        // Show main menu initially
        ShowMainMenu();
    }
    
    public void ShowMainMenu()
    {
        SetPanelActive(mainMenuPanel, true);
        SetPanelActive(gameplayPanel, false);
        SetPanelActive(pausePanel, false);
        SetPanelActive(gameOverPanel, false);
    }
    
    public void ShowGameplayUI()
    {
        SetPanelActive(mainMenuPanel, false);
        SetPanelActive(gameplayPanel, true);
        SetPanelActive(pausePanel, false);
        SetPanelActive(gameOverPanel, false);
    }
    
    public void ShowPauseScreen()
    {
        SetPanelActive(pausePanel, true);
    }
    
    public void ShowGameOverScreen()
    {
        SetPanelActive(gameOverPanel, true);
    }
    
    public void UpdateScore(int score)
    {
        if (scoreText != null)
        {
            scoreText.text = "Score: " + score.ToString();
        }
    }
    
    public void UpdateLevel(int level)
    {
        if (levelText != null)
        {
            levelText.text = "Level: " + level.ToString();
        }
    }
    
    private void SetPanelActive(GameObject panel, bool active)
    {
        if (panel != null)
        {
            panel.SetActive(active);
        }
    }
    
    // Button event handlers
    private void StartGame()
    {
        GameManager.Instance.StartGame();
        ShowGameplayUI();
    }
    
    private void PauseGame()
    {
        GameManager.Instance.PauseGame();
        ShowPauseScreen();
    }
    
    private void ResumeGame()
    {
        GameManager.Instance.ResumeGame();
        SetPanelActive(pausePanel, false);
    }
    
    private void RestartGame()
    {
        Time.timeScale = 1f;
        GameManager.Instance.StartGame();
    }
}
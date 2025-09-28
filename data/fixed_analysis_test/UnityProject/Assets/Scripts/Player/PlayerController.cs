using UnityEngine;

public class PlayerController : MonoBehaviour
{
    [Header("Movement Settings")]
    public float moveSpeed = 5f;
    public float jumpForce = 10f;
    
    [Header("Input Settings")]
    public KeyCode jumpKey = KeyCode.Space;
    public KeyCode leftKey = KeyCode.A;
    public KeyCode rightKey = KeyCode.D;
    
    private Rigidbody2D rb;
    private bool isGrounded = false;
    private bool canMove = true;
    
    private void Start()
    {
        rb = GetComponent<Rigidbody2D>();
        if (rb == null)
        {
            Debug.LogError("Rigidbody2D component not found!");
        }
    }
    
    private void Update()
    {
        if (!canMove || GameManager.Instance.currentState != GameManager.GameState.Playing)
            return;
        
        HandleInput();
    }
    
    private void HandleInput()
    {
        // Horizontal movement
        float horizontalInput = 0f;
        
        if (Input.GetKey(leftKey))
            horizontalInput = -1f;
        else if (Input.GetKey(rightKey))
            horizontalInput = 1f;
        
        // Apply movement
        if (rb != null)
        {
            rb.velocity = new Vector2(horizontalInput * moveSpeed, rb.velocity.y);
        }
        
        // Jump
        if (Input.GetKeyDown(jumpKey) && isGrounded)
        {
            Jump();
        }
    }
    
    private void Jump()
    {
        if (rb != null)
        {
            rb.velocity = new Vector2(rb.velocity.x, jumpForce);
            isGrounded = false;
        }
    }
    
    private void OnCollisionEnter2D(Collision2D collision)
    {
        if (collision.gameObject.CompareTag("Ground"))
        {
            isGrounded = true;
        }
    }
    
    private void OnTriggerEnter2D(Collider2D other)
    {
        if (other.CompareTag("Collectible"))
        {
            // Handle collectible
            GameManager.Instance.AddScore(10);
            Destroy(other.gameObject);
        }
        else if (other.CompareTag("Enemy"))
        {
            // Handle enemy collision
            TakeDamage();
        }
    }
    
    private void TakeDamage()
    {
        // Damage logic
        Debug.Log("Player took damage!");
        GameManager.Instance.GameOver();
    }
    
    public void SetCanMove(bool canMove)
    {
        this.canMove = canMove;
    }
}
# ORCH-Next API Reference

## Overview

The ORCH-Next API provides a comprehensive REST interface for task orchestration, monitoring, and system management. All endpoints support JSON request/response format and include comprehensive error handling.

**Base URL**: `http://localhost:8000` (development)  
**API Version**: v1  
**Content-Type**: `application/json`

## Authentication

### JWT Authentication

Most endpoints require JWT authentication. Include the token in the Authorization header:

```http
Authorization: Bearer <jwt_token>
```

### Obtaining JWT Token

**Endpoint**: `POST /auth/login`

**Request**:
```json
{
  "username": "your_username",
  "password": "your_password"
}
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "user_id": "user-123",
    "username": "your_username",
    "email": "user@example.com",
    "role": "operator"
  }
}
```

### User Roles

- **admin**: Full system access, user management
- **operator**: Task management, monitoring access
- **viewer**: Read-only access to tasks and metrics
- **system**: Internal system operations

## Core Endpoints

### Health Check

**Endpoint**: `GET /health`  
**Authentication**: None required

Returns system health status and basic metrics.

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "components": {
    "database": "healthy",
    "lock_manager": "healthy",
    "monitor": "healthy",
    "security": "healthy"
  },
  "metrics": {
    "uptime_seconds": 3600,
    "total_requests": 12345,
    "active_tasks": 5,
    "active_locks": 2
  }
}
```

**Status Codes**:
- `200`: System healthy
- `503`: System unhealthy (check components for details)

### Metrics

**Endpoint**: `GET /metrics`  
**Authentication**: Required (viewer+ role)

Returns Prometheus-formatted metrics for monitoring and alerting.

**Response**: Plain text in Prometheus format
```
# HELP orch_http_requests_total Total HTTP requests
# TYPE orch_http_requests_total counter
orch_http_requests_total{method="POST",status="200",endpoint="/dispatch"} 1234

# HELP orch_task_duration_seconds Task execution duration
# TYPE orch_task_duration_seconds histogram
orch_task_duration_seconds_bucket{core_id="WORK_AI_01",le="1.0"} 100
orch_task_duration_seconds_bucket{core_id="WORK_AI_01",le="5.0"} 200
orch_task_duration_seconds_bucket{core_id="WORK_AI_01",le="+Inf"} 250
orch_task_duration_seconds_sum{core_id="WORK_AI_01"} 567.89
orch_task_duration_seconds_count{core_id="WORK_AI_01"} 250

# HELP orch_sse_connections_active Active SSE connections
# TYPE orch_sse_connections_active gauge
orch_sse_connections_active 42

# HELP orch_webhook_signatures_verified_total Webhook signature verifications
# TYPE orch_webhook_signatures_verified_total counter
orch_webhook_signatures_verified_total{status="success"} 1500
orch_webhook_signatures_verified_total{status="failure"} 23
```

**Status Codes**:
- `200`: Metrics retrieved successfully
- `401`: Authentication required
- `403`: Insufficient permissions

## Task Management

### Dispatch Task

**Endpoint**: `POST /dispatch`  
**Authentication**: Required (operator+ role)

Dispatches a new task to the orchestration system.

**Request**:
```json
{
  "coreId": "WORK_AI_01",
  "stay": false,
  "priority": 2,
  "timeout": 300,
  "metadata": {
    "source": "api",
    "user_id": "user-123",
    "tags": ["urgent", "production"],
    "description": "Process customer data batch",
    "callback_url": "https://api.example.com/callbacks/task-complete"
  }
}
```

**Request Parameters**:
- `coreId` (string, required): Identifier for the target core/worker
- `stay` (boolean, optional): Whether the task should stay active after completion (default: false)
- `priority` (integer, optional): Task priority 1-10, higher numbers = higher priority (default: 1)
- `timeout` (integer, optional): Task timeout in seconds (default: 300)
- `metadata` (object, optional): Additional task metadata

**Response**:
```json
{
  "task_id": "task-123e4567-e89b-12d3-a456-426614174000",
  "status": "queued",
  "core_id": "WORK_AI_01",
  "priority": 2,
  "timeout": 300,
  "created_at": "2024-01-15T10:30:00Z",
  "estimated_start": "2024-01-15T10:31:00Z",
  "queue_position": 3
}
```

**Status Codes**:
- `200`: Task dispatched successfully
- `202`: Task queued for processing
- `400`: Invalid request parameters
- `401`: Authentication required
- `403`: Insufficient permissions
- `429`: Rate limit exceeded

### Get Job Events

**Endpoint**: `GET /jobs/{task_id}/events`  
**Authentication**: Required (viewer+ role)

Retrieves all events for a specific task.

**Path Parameters**:
- `task_id` (string, required): Task identifier

**Query Parameters**:
- `limit` (integer, optional): Maximum number of events to return (default: 100)
- `offset` (integer, optional): Number of events to skip (default: 0)
- `event_type` (string, optional): Filter by event type
- `since` (string, optional): ISO timestamp to filter events after

**Response**:
```json
{
  "task_id": "task-123e4567-e89b-12d3-a456-426614174000",
  "total_events": 5,
  "events": [
    {
      "event_id": "event-456",
      "task_id": "task-123e4567-e89b-12d3-a456-426614174000",
      "event_type": "task.created",
      "timestamp": "2024-01-15T10:30:00Z",
      "data": {
        "core_id": "WORK_AI_01",
        "priority": 2,
        "timeout": 300
      }
    },
    {
      "event_id": "event-457",
      "task_id": "task-123e4567-e89b-12d3-a456-426614174000",
      "event_type": "task.started",
      "timestamp": "2024-01-15T10:31:00Z",
      "data": {
        "worker_id": "worker-789",
        "start_time": "2024-01-15T10:31:00Z"
      }
    },
    {
      "event_id": "event-458",
      "task_id": "task-123e4567-e89b-12d3-a456-426614174000",
      "event_type": "task.progress",
      "timestamp": "2024-01-15T10:32:00Z",
      "data": {
        "progress": 50,
        "message": "Processing data batch 1 of 2",
        "details": {
          "processed_records": 1000,
          "total_records": 2000
        }
      }
    },
    {
      "event_id": "event-459",
      "task_id": "task-123e4567-e89b-12d3-a456-426614174000",
      "event_type": "task.completed",
      "timestamp": "2024-01-15T10:35:00Z",
      "data": {
        "status": "success",
        "duration": 240.5,
        "result": {
          "processed_records": 2000,
          "output_file": "/data/output/batch_123.json"
        }
      }
    }
  ],
  "pagination": {
    "limit": 100,
    "offset": 0,
    "has_more": false
  }
}
```

**Status Codes**:
- `200`: Events retrieved successfully
- `404`: Task not found
- `401`: Authentication required
- `403`: Insufficient permissions

### Update Job Status

**Endpoint**: `PUT /jobs/{task_id}/status`  
**Authentication**: Required (operator+ role)

Updates the status of a running task.

**Path Parameters**:
- `task_id` (string, required): Task identifier

**Request**:
```json
{
  "status": "running",
  "progress": 75,
  "message": "Processing final batch",
  "metadata": {
    "current_step": "data_validation",
    "completion_percentage": 75,
    "estimated_completion": "2024-01-15T10:40:00Z",
    "worker_metrics": {
      "cpu_usage": 45.2,
      "memory_usage": 67.8,
      "disk_io": 12.3
    }
  }
}
```

**Request Parameters**:
- `status` (string, required): New task status (running, completed, failed, cancelled)
- `progress` (integer, optional): Progress percentage 0-100
- `message` (string, optional): Human-readable status message
- `metadata` (object, optional): Additional status metadata

**Response**:
```json
{
  "status": "updated",
  "task_id": "task-123e4567-e89b-12d3-a456-426614174000",
  "updated_at": "2024-01-15T10:35:00Z",
  "event_id": "event-460"
}
```

**Status Codes**:
- `200`: Status updated successfully
- `404`: Task not found
- `400`: Invalid status or parameters
- `401`: Authentication required
- `403`: Insufficient permissions

### List Tasks

**Endpoint**: `GET /tasks`  
**Authentication**: Required (viewer+ role)

Retrieves a list of tasks with filtering and pagination.

**Query Parameters**:
- `status` (string, optional): Filter by task status
- `core_id` (string, optional): Filter by core ID
- `priority` (integer, optional): Filter by priority
- `limit` (integer, optional): Maximum number of tasks to return (default: 50)
- `offset` (integer, optional): Number of tasks to skip (default: 0)
- `sort` (string, optional): Sort field (created_at, updated_at, priority) (default: created_at)
- `order` (string, optional): Sort order (asc, desc) (default: desc)

**Response**:
```json
{
  "total_tasks": 150,
  "tasks": [
    {
      "task_id": "task-123",
      "core_id": "WORK_AI_01",
      "status": "completed",
      "priority": 2,
      "timeout": 300,
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:35:00Z",
      "duration": 240.5,
      "metadata": {
        "source": "api",
        "tags": ["production"]
      }
    }
  ],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "has_more": true
  }
}
```

**Status Codes**:
- `200`: Tasks retrieved successfully
- `401`: Authentication required
- `403`: Insufficient permissions

## Webhook Management

### Receive Webhook

**Endpoint**: `POST /webhook`  
**Authentication**: HMAC signature verification

Receives webhook notifications from external systems.

**Headers**:
```http
Content-Type: application/json
X-Signature: t=1642248600,v1=sha256_signature_hash
```

**Request**:
```json
{
  "event": "task.completed",
  "task_id": "task-123e4567-e89b-12d3-a456-426614174000",
  "core_id": "WORK_AI_01",
  "status": "success",
  "timestamp": 1642248600,
  "data": {
    "duration": 123.45,
    "output": "Task completed successfully",
    "metrics": {
      "cpu_usage": 45.2,
      "memory_usage": 67.8,
      "disk_io": 12.3
    },
    "result": {
      "processed_items": 1000,
      "output_file": "/data/results/task_123.json"
    }
  }
}
```

**HMAC Signature Calculation**:
```python
import hmac
import hashlib
import json
import time

# Webhook payload
payload = {...}
timestamp = str(int(time.time()))
webhook_secret = "your-webhook-secret"

# Create signature
payload_str = json.dumps(payload, sort_keys=True, separators=(',', ':'))
message = f"{timestamp}.{payload_str}"
signature = hmac.new(
    webhook_secret.encode('utf-8'),
    message.encode('utf-8'),
    hashlib.sha256
).hexdigest()

# Header format
headers = {
    "X-Signature": f"t={timestamp},v1={signature}"
}
```

**Response**:
```json
{
  "status": "received",
  "event_id": "event-789",
  "processed_at": "2024-01-15T10:35:00Z",
  "webhook_id": "webhook-456"
}
```

**Status Codes**:
- `200`: Webhook processed successfully
- `400`: Invalid webhook payload
- `401`: Invalid or missing signature
- `408`: Request timeout (timestamp too old/new)

## Real-time Events

### Server-Sent Events (SSE)

**Endpoint**: `GET /sse/events`  
**Authentication**: Required (viewer+ role)

Establishes a Server-Sent Events connection for real-time updates.

**Query Parameters**:
- `filter` (string, optional): Event type filter (comma-separated)
- `task_id` (string, optional): Filter events for specific task
- `core_id` (string, optional): Filter events for specific core

**Response**: Text/event-stream
```
data: {"event_type": "task.created", "task_id": "task-123", "timestamp": "2024-01-15T10:30:00Z", "data": {...}}

data: {"event_type": "task.progress", "task_id": "task-123", "timestamp": "2024-01-15T10:32:00Z", "data": {"progress": 50}}

data: {"event_type": "system.alert", "timestamp": "2024-01-15T10:33:00Z", "data": {"level": "warning", "message": "High CPU usage detected"}}
```

**Event Types**:
- `task.created`: New task dispatched
- `task.started`: Task execution started
- `task.progress`: Task progress update
- `task.completed`: Task completed
- `task.failed`: Task failed
- `system.alert`: System alert/warning
- `heartbeat`: Connection keepalive

**Status Codes**:
- `200`: SSE connection established
- `401`: Authentication required
- `403`: Insufficient permissions

## Lock Management

### List Locks

**Endpoint**: `GET /locks`  
**Authentication**: Required (operator+ role)

Retrieves information about active resource locks.

**Query Parameters**:
- `resource` (string, optional): Filter by resource name
- `owner` (string, optional): Filter by lock owner
- `expired` (boolean, optional): Include expired locks

**Response**:
```json
{
  "total_locks": 5,
  "locks": [
    {
      "resource": "database-migration",
      "owner": "worker-123",
      "priority": 5,
      "ttl": 3600,
      "acquired_at": "2024-01-15T10:30:00Z",
      "expires_at": "2024-01-15T11:30:00Z",
      "remaining_ttl": 2400
    },
    {
      "resource": "file-processing",
      "owner": "worker-456",
      "priority": 2,
      "ttl": 1800,
      "acquired_at": "2024-01-15T10:45:00Z",
      "expires_at": "2024-01-15T11:15:00Z",
      "remaining_ttl": 900
    }
  ],
  "queue_status": {
    "total_waiting": 3,
    "by_resource": {
      "database-migration": 2,
      "file-processing": 1
    }
  }
}
```

**Status Codes**:
- `200`: Locks retrieved successfully
- `401`: Authentication required
- `403`: Insufficient permissions

### Acquire Lock

**Endpoint**: `POST /locks`  
**Authentication**: Required (operator+ role)

Attempts to acquire a resource lock.

**Request**:
```json
{
  "resource": "critical-resource",
  "owner": "worker-789",
  "ttl": 1800,
  "priority": 3,
  "timeout": 30
}
```

**Request Parameters**:
- `resource` (string, required): Resource identifier
- `owner` (string, required): Lock owner identifier
- `ttl` (integer, required): Time-to-live in seconds
- `priority` (integer, optional): Lock priority 1-10 (default: 1)
- `timeout` (integer, optional): Acquisition timeout in seconds (default: 0)

**Response**:
```json
{
  "status": "acquired",
  "resource": "critical-resource",
  "owner": "worker-789",
  "acquired_at": "2024-01-15T10:30:00Z",
  "expires_at": "2024-01-15T11:00:00Z",
  "lock_id": "lock-123"
}
```

**Status Codes**:
- `200`: Lock acquired successfully
- `409`: Resource already locked
- `408`: Acquisition timeout
- `400`: Invalid request parameters
- `401`: Authentication required
- `403`: Insufficient permissions

### Release Lock

**Endpoint**: `DELETE /locks/{resource}`  
**Authentication**: Required (operator+ role)

Releases a resource lock.

**Path Parameters**:
- `resource` (string, required): Resource identifier

**Query Parameters**:
- `owner` (string, required): Lock owner identifier

**Response**:
```json
{
  "status": "released",
  "resource": "critical-resource",
  "owner": "worker-789",
  "released_at": "2024-01-15T10:45:00Z"
}
```

**Status Codes**:
- `200`: Lock released successfully
- `404`: Lock not found
- `403`: Not lock owner or insufficient permissions
- `401`: Authentication required

## User Management

### Create User

**Endpoint**: `POST /users`  
**Authentication**: Required (admin role)

Creates a new user account.

**Request**:
```json
{
  "username": "new_user",
  "email": "new_user@example.com",
  "password": "secure_password_123",
  "role": "operator",
  "metadata": {
    "department": "engineering",
    "team": "platform"
  }
}
```

**Response**:
```json
{
  "user_id": "user-789",
  "username": "new_user",
  "email": "new_user@example.com",
  "role": "operator",
  "created_at": "2024-01-15T10:30:00Z",
  "is_active": true
}
```

**Status Codes**:
- `201`: User created successfully
- `400`: Invalid request parameters
- `409`: Username or email already exists
- `401`: Authentication required
- `403`: Insufficient permissions

### List Users

**Endpoint**: `GET /users`  
**Authentication**: Required (admin role)

Retrieves a list of user accounts.

**Query Parameters**:
- `role` (string, optional): Filter by user role
- `is_active` (boolean, optional): Filter by active status
- `limit` (integer, optional): Maximum number of users (default: 50)
- `offset` (integer, optional): Number of users to skip (default: 0)

**Response**:
```json
{
  "total_users": 25,
  "users": [
    {
      "user_id": "user-123",
      "username": "admin_user",
      "email": "admin@example.com",
      "role": "admin",
      "created_at": "2024-01-01T00:00:00Z",
      "last_login": "2024-01-15T09:30:00Z",
      "is_active": true
    }
  ],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "has_more": false
  }
}
```

**Status Codes**:
- `200`: Users retrieved successfully
- `401`: Authentication required
- `403`: Insufficient permissions

## Error Handling

### Error Response Format

All API errors follow a consistent format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": {
      "field": "coreId",
      "issue": "Field is required"
    },
    "request_id": "req-123e4567-e89b-12d3-a456-426614174000",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### Error Codes

**Authentication Errors**:
- `AUTHENTICATION_REQUIRED`: Missing or invalid authentication
- `INVALID_TOKEN`: JWT token is invalid or expired
- `INSUFFICIENT_PERMISSIONS`: User lacks required permissions

**Validation Errors**:
- `VALIDATION_ERROR`: Request validation failed
- `INVALID_PARAMETER`: Parameter value is invalid
- `MISSING_PARAMETER`: Required parameter is missing

**Resource Errors**:
- `RESOURCE_NOT_FOUND`: Requested resource does not exist
- `RESOURCE_CONFLICT`: Resource conflict (e.g., lock already held)
- `RESOURCE_LOCKED`: Resource is currently locked

**System Errors**:
- `INTERNAL_ERROR`: Internal server error
- `SERVICE_UNAVAILABLE`: Service temporarily unavailable
- `RATE_LIMIT_EXCEEDED`: Request rate limit exceeded
- `TIMEOUT`: Request timeout

### HTTP Status Codes

- `200`: Success
- `201`: Created
- `202`: Accepted (async processing)
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `409`: Conflict
- `408`: Request Timeout
- `429`: Too Many Requests
- `500`: Internal Server Error
- `503`: Service Unavailable

## Rate Limiting

### Rate Limit Headers

All responses include rate limiting headers:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642248660
X-RateLimit-Window: 60
```

### Rate Limit Configuration

Default rate limits by role:
- **admin**: 1000 requests/minute
- **operator**: 500 requests/minute
- **viewer**: 200 requests/minute
- **system**: 2000 requests/minute

### Rate Limit Exceeded Response

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded",
    "details": {
      "limit": 100,
      "window": 60,
      "retry_after": 30
    },
    "request_id": "req-123",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

## SDK Examples

### Python SDK Example

```python
import httpx
import json
from typing import Optional, Dict, Any

class ORCHClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.client = httpx.Client(
            headers={"Authorization": f"Bearer {token}"}
        )
    
    def dispatch_task(
        self, 
        core_id: str, 
        stay: bool = False, 
        priority: int = 1,
        timeout: int = 300,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Dispatch a new task"""
        response = self.client.post(
            f"{self.base_url}/dispatch",
            json={
                "coreId": core_id,
                "stay": stay,
                "priority": priority,
                "timeout": timeout,
                "metadata": metadata or {}
            }
        )
        response.raise_for_status()
        return response.json()
    
    def get_task_events(self, task_id: str) -> Dict[str, Any]:
        """Get events for a task"""
        response = self.client.get(f"{self.base_url}/jobs/{task_id}/events")
        response.raise_for_status()
        return response.json()
    
    def update_task_status(
        self, 
        task_id: str, 
        status: str, 
        progress: Optional[int] = None,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Update task status"""
        data = {"status": status}
        if progress is not None:
            data["progress"] = progress
        if message:
            data["message"] = message
        if metadata:
            data["metadata"] = metadata
            
        response = self.client.put(
            f"{self.base_url}/jobs/{task_id}/status",
            json=data
        )
        response.raise_for_status()
        return response.json()

# Usage example
client = ORCHClient("http://localhost:8000", "your-jwt-token")

# Dispatch a task
task = client.dispatch_task(
    core_id="WORK_AI_01",
    priority=2,
    metadata={"source": "python_sdk", "batch_id": "batch_123"}
)

print(f"Task dispatched: {task['task_id']}")

# Update task status
client.update_task_status(
    task["task_id"],
    status="running",
    progress=50,
    message="Processing batch data"
)

# Get task events
events = client.get_task_events(task["task_id"])
print(f"Task has {len(events['events'])} events")
```

### JavaScript SDK Example

```javascript
class ORCHClient {
    constructor(baseUrl, token) {
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.token = token;
    }

    async request(method, endpoint, data = null) {
        const url = `${this.baseUrl}${endpoint}`;
        const options = {
            method,
            headers: {
                'Authorization': `Bearer ${this.token}`,
                'Content-Type': 'application/json'
            }
        };

        if (data) {
            options.body = JSON.stringify(data);
        }

        const response = await fetch(url, options);
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(`API Error: ${error.error.message}`);
        }

        return response.json();
    }

    async dispatchTask(coreId, options = {}) {
        return this.request('POST', '/dispatch', {
            coreId,
            stay: options.stay || false,
            priority: options.priority || 1,
            timeout: options.timeout || 300,
            metadata: options.metadata || {}
        });
    }

    async getTaskEvents(taskId) {
        return this.request('GET', `/jobs/${taskId}/events`);
    }

    async updateTaskStatus(taskId, status, options = {}) {
        const data = { status };
        if (options.progress !== undefined) data.progress = options.progress;
        if (options.message) data.message = options.message;
        if (options.metadata) data.metadata = options.metadata;

        return this.request('PUT', `/jobs/${taskId}/status`, data);
    }

    // SSE connection for real-time events
    subscribeToEvents(callback, filter = null) {
        let url = `${this.baseUrl}/sse/events`;
        if (filter) {
            url += `?filter=${encodeURIComponent(filter)}`;
        }

        const eventSource = new EventSource(url, {
            headers: {
                'Authorization': `Bearer ${this.token}`
            }
        });

        eventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);
            callback(data);
        };

        eventSource.onerror = (error) => {
            console.error('SSE connection error:', error);
        };

        return eventSource;
    }
}

// Usage example
const client = new ORCHClient('http://localhost:8000', 'your-jwt-token');

// Dispatch a task
const task = await client.dispatchTask('WORK_AI_01', {
    priority: 2,
    metadata: { source: 'javascript_sdk', batch_id: 'batch_123' }
});

console.log(`Task dispatched: ${task.task_id}`);

// Subscribe to real-time events
const eventSource = client.subscribeToEvents((event) => {
    console.log('Received event:', event);
}, 'task.progress,task.completed');

// Update task status
await client.updateTaskStatus(task.task_id, 'running', {
    progress: 75,
    message: 'Nearly complete'
});
```

## Webhook Integration

### Setting up Webhooks

1. **Configure webhook endpoint** in your application
2. **Set webhook secret** in ORCH-Next configuration
3. **Implement HMAC verification** in your webhook handler
4. **Handle webhook events** based on event type

### Webhook Handler Example

```python
import hmac
import hashlib
import json
from flask import Flask, request, jsonify

app = Flask(__name__)
WEBHOOK_SECRET = "your-webhook-secret"

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    # Verify HMAC signature
    signature_header = request.headers.get('X-Signature')
    if not signature_header:
        return jsonify({'error': 'Missing signature'}), 401
    
    # Parse signature
    parts = signature_header.split(',')
    timestamp = None
    signature = None
    
    for part in parts:
        if part.startswith('t='):
            timestamp = part[2:]
        elif part.startswith('v1='):
            signature = part[3:]
    
    if not timestamp or not signature:
        return jsonify({'error': 'Invalid signature format'}), 401
    
    # Verify signature
    payload = request.get_data()
    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode('utf-8'),
        f"{timestamp}.{payload.decode('utf-8')}".encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected_signature):
        return jsonify({'error': 'Invalid signature'}), 401
    
    # Process webhook
    data = request.json
    event_type = data.get('event')
    
    if event_type == 'task.completed':
        handle_task_completed(data)
    elif event_type == 'task.failed':
        handle_task_failed(data)
    
    return jsonify({'status': 'processed'})

def handle_task_completed(data):
    task_id = data['task_id']
    result = data['data']
    print(f"Task {task_id} completed successfully")
    # Process completion logic here

def handle_task_failed(data):
    task_id = data['task_id']
    error = data['data']
    print(f"Task {task_id} failed: {error}")
    # Process failure logic here

if __name__ == '__main__':
    app.run(port=5000)
```

---

This API reference provides comprehensive documentation for integrating with the ORCH-Next system. For additional examples and advanced usage patterns, refer to the SDK documentation and example applications.
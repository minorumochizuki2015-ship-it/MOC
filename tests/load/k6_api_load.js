// k6 Load Test Script for ORCH-Next API
// Tests HTTP API endpoints under various load conditions

import http from 'k6/http';
import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const responseTime = new Trend('response_time');
const apiCalls = new Counter('api_calls');
const webhookVerifications = new Counter('webhook_verifications');
const sseConnections = new Counter('sse_connections');

// Test configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const JWT_TOKEN = __ENV.JWT_TOKEN || 'test-jwt-token';
const WEBHOOK_SECRET = __ENV.WEBHOOK_SECRET || 'test-webhook-secret-for-testing-only';

// Load test scenarios
export const options = {
  scenarios: {
    // Smoke test - basic functionality
    smoke_test: {
      executor: 'constant-vus',
      vus: 1,
      duration: '30s',
      tags: { test_type: 'smoke' },
    },
    
    // Load test - normal expected load
    load_test: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '2m', target: 20 },  // Ramp up
        { duration: '5m', target: 20 },  // Stay at 20 users
        { duration: '2m', target: 0 },   // Ramp down
      ],
      tags: { test_type: 'load' },
    },
    
    // Stress test - beyond normal capacity
    stress_test: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '2m', target: 50 },  // Ramp up to stress level
        { duration: '5m', target: 50 },  // Maintain stress
        { duration: '2m', target: 100 }, // Peak stress
        { duration: '3m', target: 100 }, // Hold peak
        { duration: '2m', target: 0 },   // Ramp down
      ],
      tags: { test_type: 'stress' },
    },
    
    // Spike test - sudden traffic spikes
    spike_test: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '1m', target: 10 },  // Normal load
        { duration: '30s', target: 100 }, // Sudden spike
        { duration: '1m', target: 100 },  // Hold spike
        { duration: '30s', target: 10 },  // Drop back
        { duration: '1m', target: 10 },   // Normal load
        { duration: '30s', target: 0 },   // Ramp down
      ],
      tags: { test_type: 'spike' },
    },
    
    // SSE connection test
    sse_test: {
      executor: 'constant-vus',
      vus: 50,
      duration: '3m',
      tags: { test_type: 'sse' },
    },
  },
  
  thresholds: {
    // Overall performance requirements
    http_req_duration: ['p(95)<2000'], // 95% of requests under 2s
    http_req_failed: ['rate<0.05'],    // Error rate under 5%
    
    // Specific endpoint requirements
    'http_req_duration{endpoint:metrics}': ['p(95)<500'], // Metrics endpoint under 500ms
    'http_req_duration{endpoint:dispatch}': ['p(95)<1000'], // Dispatch under 1s
    'http_req_duration{endpoint:webhook}': ['p(95)<1000'], // Webhook under 1s
    
    // Custom metrics thresholds
    errors: ['rate<0.05'],
    'sse_connections': ['count>100'], // At least 100 SSE connections established
  },
};

// Helper function to create HMAC signature
function createHMACSignature(payload, secret, timestamp) {
  const crypto = require('crypto');
  const message = `${timestamp}.${payload}`;
  const signature = crypto.createHmac('sha256', secret).update(message).digest('hex');
  return `t=${timestamp},v1=${signature}`;
}

// Helper function to generate test data
function generateTestPayload() {
  return JSON.stringify({
    event: 'task.completed',
    task_id: `test-task-${Math.random().toString(36).substr(2, 9)}`,
    core_id: `TEST_CORE_${Math.floor(Math.random() * 10).toString().padStart(2, '0')}`,
    timestamp: new Date().toISOString(),
    data: {
      status: 'success',
      duration: Math.random() * 100,
      output: 'Task completed successfully'
    }
  });
}

// Test functions for different scenarios
export function smoke_test() {
  const testName = 'smoke_test';
  
  // Test health check
  let response = http.get(`${BASE_URL}/health`);
  check(response, {
    'health check status is 200': (r) => r.status === 200,
    'health check response time < 500ms': (r) => r.timings.duration < 500,
  }) || errorRate.add(1);
  
  apiCalls.add(1);
  responseTime.add(response.timings.duration);
  
  sleep(1);
}

export function load_test() {
  const testName = 'load_test';
  
  // Test metrics endpoint
  let response = http.get(`${BASE_URL}/metrics`, {
    headers: { 'Authorization': `Bearer ${JWT_TOKEN}` },
    tags: { endpoint: 'metrics' },
  });
  
  check(response, {
    'metrics status is 200': (r) => r.status === 200,
    'metrics contains prometheus format': (r) => r.body.includes('orch_'),
    'metrics response time < 1s': (r) => r.timings.duration < 1000,
  }) || errorRate.add(1);
  
  apiCalls.add(1);
  responseTime.add(response.timings.duration);
  
  // Test dispatch endpoint
  const dispatchPayload = {
    coreId: `TEST_CORE_${Math.floor(Math.random() * 10).toString().padStart(2, '0')}`,
    stay: false,
    priority: Math.floor(Math.random() * 3) + 1,
    timeout: 300,
    metadata: {
      source: 'k6-load-test',
      test_run: testName
    }
  };
  
  response = http.post(`${BASE_URL}/dispatch`, JSON.stringify(dispatchPayload), {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${JWT_TOKEN}`,
    },
    tags: { endpoint: 'dispatch' },
  });
  
  check(response, {
    'dispatch status is 200 or 202': (r) => [200, 202].includes(r.status),
    'dispatch returns task_id': (r) => {
      try {
        const data = JSON.parse(r.body);
        return data.task_id !== undefined;
      } catch (e) {
        return false;
      }
    },
    'dispatch response time < 2s': (r) => r.timings.duration < 2000,
  }) || errorRate.add(1);
  
  apiCalls.add(1);
  responseTime.add(response.timings.duration);
  
  sleep(Math.random() * 2 + 1); // Random sleep 1-3 seconds
}

export function stress_test() {
  const testName = 'stress_test';
  
  // Rapid-fire requests to test system limits
  for (let i = 0; i < 3; i++) {
    // Test webhook endpoint with HMAC verification
    const payload = generateTestPayload();
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const signature = createHMACSignature(payload, WEBHOOK_SECRET, timestamp);
    
    let response = http.post(`${BASE_URL}/webhook`, payload, {
      headers: {
        'Content-Type': 'application/json',
        'X-Signature': signature,
      },
      tags: { endpoint: 'webhook' },
    });
    
    check(response, {
      'webhook status is 200': (r) => r.status === 200,
      'webhook HMAC verified': (r) => !r.body.includes('signature'),
      'webhook response time < 2s': (r) => r.timings.duration < 2000,
    }) || errorRate.add(1);
    
    apiCalls.add(1);
    webhookVerifications.add(1);
    responseTime.add(response.timings.duration);
    
    sleep(0.1); // Brief pause between rapid requests
  }
  
  sleep(1);
}

export function spike_test() {
  const testName = 'spike_test';
  
  // Simulate sudden spike in activity
  const endpoints = ['/health', '/metrics', '/dispatch'];
  const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
  
  let response;
  if (endpoint === '/dispatch') {
    const payload = {
      coreId: `SPIKE_CORE_${Math.floor(Math.random() * 5).toString().padStart(2, '0')}`,
      stay: false,
      priority: 3, // High priority for spike test
      timeout: 60,
      metadata: { source: 'k6-spike-test' }
    };
    
    response = http.post(`${BASE_URL}${endpoint}`, JSON.stringify(payload), {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${JWT_TOKEN}`,
      },
      tags: { endpoint: endpoint.substring(1) },
    });
  } else {
    response = http.get(`${BASE_URL}${endpoint}`, {
      headers: { 'Authorization': `Bearer ${JWT_TOKEN}` },
      tags: { endpoint: endpoint.substring(1) },
    });
  }
  
  check(response, {
    'spike test status is success': (r) => r.status < 400,
    'spike test response time < 5s': (r) => r.timings.duration < 5000,
  }) || errorRate.add(1);
  
  apiCalls.add(1);
  responseTime.add(response.timings.duration);
  
  sleep(0.5); // Short sleep for spike test
}

export function sse_test() {
  const testName = 'sse_test';
  
  // Test Server-Sent Events connection
  const clientId = `k6-client-${__VU}-${Math.random().toString(36).substr(2, 9)}`;
  
  const response = http.get(`${BASE_URL}/events`, {
    headers: {
      'Accept': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'X-Client-ID': clientId,
      'Authorization': `Bearer ${JWT_TOKEN}`,
    },
    tags: { endpoint: 'events' },
  });
  
  check(response, {
    'SSE connection established': (r) => r.status === 200,
    'SSE content type correct': (r) => r.headers['Content-Type'] && r.headers['Content-Type'].includes('text/event-stream'),
    'SSE connection time < 3s': (r) => r.timings.duration < 3000,
  }) || errorRate.add(1);
  
  sseConnections.add(1);
  responseTime.add(response.timings.duration);
  
  // For SSE, we can't easily test the streaming in k6, so we test connection establishment
  sleep(2);
}

// Setup function - runs once per VU
export function setup() {
  console.log('Starting ORCH-Next API load tests...');
  
  // Verify API is accessible
  const response = http.get(`${BASE_URL}/health`);
  if (response.status !== 200) {
    throw new Error(`API not accessible: ${response.status}`);
  }
  
  console.log('API health check passed, starting load tests');
  return { baseUrl: BASE_URL };
}

// Teardown function - runs once after all VUs finish
export function teardown(data) {
  console.log('Load tests completed');
  
  // Optional: Send test completion notification
  const summary = {
    test_completed: new Date().toISOString(),
    base_url: data.baseUrl,
    total_api_calls: apiCalls.count,
    total_sse_connections: sseConnections.count,
    total_webhook_verifications: webhookVerifications.count,
  };
  
  console.log('Test Summary:', JSON.stringify(summary, null, 2));
}

// Default function - runs for VUs not assigned to specific scenarios
export default function() {
  // This runs for any VUs not covered by named scenarios
  load_test();
}

// Handle different test types based on environment variable
export function handleRequest() {
  const testType = __ENV.TEST_TYPE || 'load';
  
  switch (testType) {
    case 'smoke':
      smoke_test();
      break;
    case 'load':
      load_test();
      break;
    case 'stress':
      stress_test();
      break;
    case 'spike':
      spike_test();
      break;
    case 'sse':
      sse_test();
      break;
    default:
      load_test();
  }
}
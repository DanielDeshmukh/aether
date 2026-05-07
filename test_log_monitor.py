"""Test script for LogMonitor functionality."""

import asyncio
import sys
sys.path.insert(0, "d:\\Vs Code\\Aether\\aether\\backend")

from app.services.log_monitor import LogMonitor, SafetyAuditSnapshot


async def test_log_monitor():
    """Test the LogMonitor implementation."""
    monitor = LogMonitor('test-scan-id', 'test-user-id', max_rps=2.0)
    
    # Test marking scan start/end
    await monitor.mark_scan_start()
    
    # Test logging requests
    await monitor.log_request(
        request_url='http://localhost:8000/api/test',
        safety_token='test-token-123',
        status='success',
        status_code=200,
        latency_ms=150,
        notes='test_request'
    )
    
    await monitor.log_request(
        request_url='http://localhost:8000/api/blocked',
        safety_token='test-token-456',
        status='blocked',
        status_code=403,
        latency_ms=75,
        notes='safety_gate_blocking'
    )
    
    await monitor.mark_scan_end()
    
    # Generate audit report
    audit = await monitor.generate_safety_audit_report([1.0, 2.0, 3.0])
    audit_dict = monitor.to_dict(audit)
    
    print('✓ LogMonitor test passed')
    print(f'  - Total requests: {audit_dict["total_requests"]}')
    print(f'  - Successful requests: {audit_dict["successful_requests"]}')
    print(f'  - Blocked requests: {audit_dict["blocked_requests"]}')
    print(f'  - Success rate: {audit_dict["success_rate_percent"]}%')
    print(f'  - Average latency: {audit_dict["average_latency_ms"]}ms')
    print(f'  - RPS compliant: {audit_dict["rps_compliant"]}')
    print(f'  - Verdict: {audit_dict["verdict"]}')
    
    print('\n✓ All tests passed!')


if __name__ == '__main__':
    asyncio.run(test_log_monitor())

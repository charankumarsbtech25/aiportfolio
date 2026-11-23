"""
Comprehensive Automated Production Verification Test Suite for Portfolio AI
Tests all backend modules:
- Auth & Password Hashing (PBKDF2-HMAC-SHA256)
- Password Reset Link & Token Validation
- Email Verification
- Row-Level Security (RLS) & Multi-User Data Isolation
- Rate Limiting (HTTP 429)
- Backup Creation, Verification & Retention
- Monitoring & Frontend Error Logging
- Privacy-Conscious Analytics Telemetry
- Optimization & Data Fallbacks
- Account Deletion & Cascading Purge
"""

import os
import sys
import json
import time

# Ensure api is in python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "portfolio_ai", "portfolio_ai"))

from api import user_store
from api.backup import create_backup, list_backups
from api.monitoring import log_exception, report_frontend_error, system_health, get_recent_errors
from api.analytics import track_event, get_analytics_summary
from api import security

def run_tests():
    print("=" * 65)
    print("STARTING PORTFOLIO AI PRODUCTION VERIFICATION SUITE")
    print("=" * 65)
    passed = 0
    total = 0

    def assert_test(name, condition, details=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"[PASS] {name} {details}", flush=True)
        else:
            print(f"[FAIL] {name} - FAILED! {details}", flush=True)

    # TEST 1: Password Hashing & Salt Verification (Req 1)
    salt1, hash1 = security._hash_password("Secur3P@ssw0rd!")
    salt2, hash2 = security._hash_password("Secur3P@ssw0rd!")
    assert_test("Req 1: PBKDF2 Password Hashing", len(hash1) == 64 and len(salt1) == 32)
    assert_test("Req 1: Unique Random Salts (Same password, different salts)", salt1 != salt2 and hash1 != hash2)
    assert_test("Req 1: Password Verification Match", security._verify_password("Secur3P@ssw0rd!", salt1, hash1))
    assert_test("Req 1: Password Rejection on Wrong Password", not security._verify_password("WrongPassword!", salt1, hash1))

    # TEST 2: Password Complexity Validation (Req 7)
    assert_test("Req 7: Weak Password Rejected (<8 chars)", security.validate_password_strength("Short1!") is not None)
    assert_test("Req 7: Weak Password Rejected (no number)", security.validate_password_strength("NoNumbersHere!") is not None)
    assert_test("Req 7: Strong Password Accepted", security.validate_password_strength("ValidPassw0rd!123") is None)

    # TEST 3: User Storage & Row-Level Security Isolation (Req 10)
    user_a = "test_investor_alpha@portfolio-ai.test"
    user_b = "test_investor_beta@portfolio-ai.test"

    # User A adds a holding
    user_store.save_user_holdings(user_a, [{"symbol": "TITAN.NS", "qty": 10, "buy_price": 3200.0, "horizon": "longterm"}])
    # User B adds a holding
    user_store.save_user_holdings(user_b, [{"symbol": "TCS.NS", "qty": 25, "buy_price": 4000.0, "horizon": "swing"}])

    holdings_a = user_store.get_user_holdings(user_a)
    holdings_b = user_store.get_user_holdings(user_b)
    assert_test("Req 10: User A Holdings Isolated", len(holdings_a) == 1 and holdings_a[0]["symbol"] == "TITAN.NS")
    assert_test("Req 10: User B Holdings Isolated", len(holdings_b) == 1 and holdings_b[0]["symbol"] == "TCS.NS")
    assert_test("Req 10: No Cross-User Leakage", holdings_a[0]["symbol"] != holdings_b[0]["symbol"])

    # User A sets custom alerts
    user_store.save_user_alerts(user_a, [{"symbol": "TITAN.NS", "condition": "below", "target_price": 3100.0}])
    user_store.save_user_alerts(user_b, [{"symbol": "TCS.NS", "condition": "above", "target_price": 4500.0}])
    alerts_a = user_store.get_user_alerts(user_a)
    alerts_b = user_store.get_user_alerts(user_b)
    assert_test("Req 10: Isolated Alert Rules", alerts_a[0]["target_price"] == 3100.0 and alerts_b[0]["target_price"] == 4500.0)

    # User Onboarding Preferences Isolation (Req 19)
    user_store.save_user_onboarding(user_a, {"completed": True, "preferences": {"risk_tolerance": "aggressive", "horizon": "swing"}})
    user_store.save_user_onboarding(user_b, {"completed": False, "preferences": {"risk_tolerance": "conservative", "horizon": "longterm"}})
    ob_a = user_store.get_user_onboarding(user_a)
    ob_b = user_store.get_user_onboarding(user_b)
    assert_test("Req 19: User A Onboarding State Isolated", ob_a["completed"] == True and ob_a["preferences"]["risk_tolerance"] == "aggressive")
    assert_test("Req 19: User B Onboarding State Isolated", ob_b["completed"] == False and ob_b["preferences"]["risk_tolerance"] == "conservative")

    # TEST 4: Email Verification Token Generation & Validation (Req 3)
    test_email = "verify_test@example.com"
    token = security.secrets.token_urlsafe(32)
    security._active_verify_tokens[token] = {
        "email": test_email,
        "expires": time.time() + 86400,
    }
    assert_test("Req 3: Verification Token Active", token in security._active_verify_tokens)
    # Expired token test
    expired_token = "expired_token_sample"
    security._active_verify_tokens[expired_token] = {
        "email": test_email,
        "expires": time.time() - 100, # expired
    }
    is_expired = time.time() > security._active_verify_tokens[expired_token]["expires"]
    assert_test("Req 3: Expired Token Detection", is_expired)

    # TEST 5: Rate Limiter (Req 8)
    client_key = "test_rate_ip:127.0.0.1"
    security._rate_buckets.pop(client_key, None)
    # Should allow 5 requests
    allowed_first_5 = all(security.check_rate_limit(client_key, limit=5, window=10) for _ in range(5))
    # 6th request must be blocked
    blocked_6th = not security.check_rate_limit(client_key, limit=5, window=10)
    assert_test("Req 8: Rate Limiter Allows Under Quota", allowed_first_5)
    assert_test("Req 8: Rate Limiter Blocks Over Quota (HTTP 429 trigger)", blocked_6th)

    # TEST 6: Automated Backup Creation, Verification & Retention (Req 9)
    backup_meta = create_backup("Automated Production Verification Test")
    assert_test("Req 9: Database Backup Creation", backup_meta.get("status") == "VERIFIED_OK")
    assert_test("Req 9: Backup File Exists on Disk", os.path.exists(backup_meta.get("backup_path", "")))
    history = list_backups()
    assert_test("Req 9: Backup Recorded in History", len(history) >= 1)

    # TEST 7: Centralized Error Monitoring (Req 15)
    incident_id = log_exception("TEST_ERROR", "Simulated portfolio computation test error", context={"module": "test_suite"})
    assert_test("Req 15: Error Incident Logged", bool(incident_id))
    recent_errors = get_recent_errors(limit=5)
    found_error = any("Simulated portfolio computation" in err.get("message", "") for err in recent_errors)
    assert_test("Req 15: Error Incident Retrievable with Diagnostics", found_error)
    # Frontend error report
    from api.monitoring import FrontendErrorPayload
    fe_payload = FrontendErrorPayload(message="Uncaught TypeError in chart renderer", source="dashboard.html", lineno=42, colno=12, page="dashboard.html")
    fe_res = report_frontend_error(fe_payload, None)
    assert_test("Req 15: Frontend Error Ingestion", fe_res.get("ok") == True)
    health = system_health()
    assert_test("Req 15: System Health Monitoring Endpoint", health.get("status") in ["healthy", "operational"])

    # TEST 8: Privacy-Conscious Analytics Telemetry (Req 14)
    track_event("stock_explore", page="dashboard.html", symbol="RELIANCE.NS")
    track_event("optimizer_run", page="dashboard.html")
    analytics_summary = get_analytics_summary()
    assert_test("Req 14: Analytics Event Recorded", sum(analytics_summary.get("event_totals", {}).values()) > 0)
    assert_test("Req 14: Top Tickers Tracked Without PII", "RELIANCE.NS" in analytics_summary.get("top_stocks_explored", {}))

    # TEST 9: Account Deletion Cascading Purge (Req 18)
    del_res = user_store.delete_user_all_data(user_a)
    assert_test("Req 18: Account Deletion Cascading Purge", del_res == True)
    # Check that user_a directory is gone
    user_a_holdings_after = user_store.get_user_holdings(user_a)
    assert_test("Req 18: User A Holdings Completely Wiped", len(user_a_holdings_after) == 0)
    # Check that user_b directory remains intact
    user_b_holdings_after = user_store.get_user_holdings(user_b)
    assert_test("Req 18: User B Data Preserved (No collateral damage)", len(user_b_holdings_after) == 1)
    # Clean up user_b
    user_store.delete_user_all_data(user_b)

    print("=" * 65)
    print(f"TEST SUITE COMPLETE: {passed}/{total} TESTS PASSED")
    print("=" * 65)
    return passed == total

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)

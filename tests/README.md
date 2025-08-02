# Test Suite

This directory contains comprehensive test suites for validating the AWS Organization Migration Analysis Platform functionality.

## Test Files

### Core Functionality Tests
- **`test_org_analyzer.py`** - Original comprehensive test suite validating basic OrganizationAnalyzer functionality, logging integration, and JSON export capabilities

### Phase-Specific Tests
- **`test_ou_capabilities.py`** - Phase 1: Organizational Structure analysis validation
  - Tests OU data structures, hierarchy building, and account assignment mapping
  - Validates JSON export with organizational structure data
  - Confirms migration summary includes OU-specific metrics

- **`test_scp_capabilities.py`** - Phase 2: Service Control Policies analysis validation
  - Tests SCP data structures, policy content extraction, and attachment mapping
  - Validates SCP inheritance analysis and target type detection
  - Confirms JSON export with comprehensive SCP data

- **`test_service_config_capabilities.py`** - Phase 3: Service Configuration analysis validation
  - Tests service configuration data structures and complexity assessment
  - Validates service dependency analysis and trusted access settings
  - Confirms JSON export with service configuration intelligence

### Bug Fix Tests
- **`test_hierarchy_fix.py`** - Validates the fix for OU hierarchy report variable name error

## Running Tests

Run individual test suites:
```bash
python3 tests/test_org_analyzer.py
python3 tests/test_ou_capabilities.py
python3 tests/test_scp_capabilities.py
python3 tests/test_service_config_capabilities.py
python3 tests/test_hierarchy_fix.py
```

Run all tests:
```bash
for test in tests/test_*.py; do python3 "$test"; done
```

## Test Coverage

The test suites validate:
- ✅ Data structure initialization and integrity
- ✅ Method existence and functionality
- ✅ JSON export capabilities with proper data inclusion
- ✅ Logic correctness for complex analysis algorithms
- ✅ Error handling and edge case management
- ✅ Migration-specific warning and planning features

All tests are designed to run without requiring actual AWS credentials or live AWS Organizations data.

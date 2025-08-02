#!/usr/bin/env python3
"""
Test script to validate the improved list-org-info.py
This tests the OrganizationAnalyzer class and its methods
"""

import sys
import os
import tempfile
import json
from unittest.mock import Mock, patch

# Add the current directory to the path so we can import the module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_organization_analyzer_class():
    """Test the OrganizationAnalyzer class initialization"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Test OrganizationAnalyzer initialization
        analyzer = import_module.OrganizationAnalyzer()
        
        # Test that it initializes with empty collections
        if (analyzer.organization_id is None and
            len(analyzer.accounts) == 0 and
            len(analyzer.enabled_services) == 0 and
            len(analyzer.delegated_administrators) == 0 and
            len(analyzer.enabled_policy_types) == 0 and
            'policies' in analyzer.iam_dependencies and
            'roles' in analyzer.iam_dependencies):
            print("✓ OrganizationAnalyzer class initializes correctly")
            return True
        else:
            print("✗ OrganizationAnalyzer class initialization failed")
            return False
            
    except Exception as e:
        print(f"✗ OrganizationAnalyzer test failed: {e}")
        return False

def test_proper_structure():
    """Test that the script has proper structure with all required components"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Check for required functions
        required_functions = [
            'main'
        ]
        
        missing_functions = []
        for func_name in required_functions:
            if not hasattr(import_module, func_name):
                missing_functions.append(func_name)
        
        if missing_functions:
            print(f"✗ Missing functions: {missing_functions}")
            return False
        
        # Check for OrganizationAnalyzer class
        if not hasattr(import_module, 'OrganizationAnalyzer'):
            print("✗ OrganizationAnalyzer class not found")
            return False
        
        # Check OrganizationAnalyzer methods
        analyzer_methods = [
            'initialize_clients',
            'get_organization_info',
            'get_organization_accounts',
            'get_enabled_services',
            'get_delegated_administrators',
            'get_enabled_policy_types',
            'analyze_iam_dependencies',
            'generate_console_report',
            'export_to_json',
            'run_complete_analysis'
        ]
        
        missing_methods = []
        for method_name in analyzer_methods:
            if not hasattr(import_module.OrganizationAnalyzer, method_name):
                missing_methods.append(method_name)
        
        if missing_methods:
            print(f"✗ Missing OrganizationAnalyzer methods: {missing_methods}")
            return False
        
        # Check for logger
        if not hasattr(import_module, 'logger'):
            print("✗ No logger found")
            return False
        
        print(f"✓ Proper structure with OrganizationAnalyzer class, {len(analyzer_methods)} methods, and logging")
        return True
        
    except Exception as e:
        print(f"✗ Structure test failed: {e}")
        return False

def test_json_export_capability():
    """Test that the script can export analysis data to JSON"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Create analyzer with some test data
        analyzer = import_module.OrganizationAnalyzer()
        analyzer.organization_id = 'o-test123456'
        analyzer.organization_info = {'Id': 'o-test123456', 'FeatureSet': 'ALL'}
        analyzer.accounts = [{'Id': '123456789012', 'Name': 'Test Account', 'Email': 'test@example.com', 'Status': 'ACTIVE'}]
        analyzer.enabled_services = [{'ServicePrincipal': 'sso.amazonaws.com', 'DateEnabled': '2023-01-01'}]
        
        # Test JSON export to a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_file_path = temp_file.name
        
        try:
            result = analyzer.export_to_json(temp_file_path)
            
            if result and os.path.exists(temp_file_path):
                # Verify the JSON content
                with open(temp_file_path, 'r') as f:
                    exported_data = json.load(f)
                
                if (exported_data.get('analysis_metadata', {}).get('organization_id') == 'o-test123456' and
                    len(exported_data.get('accounts', [])) == 1 and
                    len(exported_data.get('enabled_services', [])) == 1 and
                    'migration_summary' in exported_data):
                    print("✓ JSON export capability works correctly")
                    return True
                else:
                    print("✗ JSON export content validation failed")
                    return False
            else:
                print("✗ JSON export failed")
                return False
                
        finally:
            # Clean up temp file
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
            
    except Exception as e:
        print(f"✗ JSON export test failed: {e}")
        return False

def test_dependency_checking_logic():
    """Test the organization dependency checking logic"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Create analyzer
        analyzer = import_module.OrganizationAnalyzer()
        analyzer.organization_id = 'o-test123456'
        
        # Test policy document with organization ID
        policy_with_org_id = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::example-bucket/*",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalOrgID": "o-test123456"
                        }
                    }
                }
            ]
        }
        
        # Test policy document without organization dependency
        policy_without_org_id = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::example-bucket/*"
                }
            ]
        }
        
        # Test the dependency checking
        has_dependency = analyzer._check_organization_dependency(policy_with_org_id)
        no_dependency = analyzer._check_organization_dependency(policy_without_org_id)
        
        if has_dependency and not no_dependency:
            print("✓ Organization dependency checking logic works correctly")
            return True
        else:
            print(f"✗ Dependency checking failed. With org: {has_dependency}, Without org: {no_dependency}")
            return False
            
    except Exception as e:
        print(f"✗ Dependency checking test failed: {e}")
        return False

def test_error_handling_structure():
    """Test that the script has proper error handling structure"""
    try:
        # Read the script file and check for error handling patterns
        with open("list-org-info.py", 'r') as f:
            content = f.read()
        
        # Check for proper error handling patterns
        error_patterns = [
            'ClientError',
            'NoCredentialsError',
            'logger.error',
            'logger.warning',
            'try:',
            'except'
        ]
        
        missing_patterns = []
        for pattern in error_patterns:
            if pattern not in content:
                missing_patterns.append(pattern)
        
        if missing_patterns:
            print(f"✗ Missing error handling patterns: {missing_patterns}")
            return False
        
        # Check that we don't have bare except clauses
        if 'except:' in content:
            print("✗ Found bare except: clauses (should be specific)")
            return False
        
        print("✓ Proper error handling structure found")
        return True
        
    except Exception as e:
        print(f"✗ Error handling structure test failed: {e}")
        return False

def test_logging_integration():
    """Test that logging is properly integrated"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Check that logger exists and is configured
        if hasattr(import_module, 'logger'):
            logger = import_module.logger
            print(f"Debug: Logger name: {logger.name}, Handlers: {len(logger.handlers)}, Level: {logger.level}")
            
            # Check if logging is configured at the root level (which it is via basicConfig)
            import logging
            root_logger = logging.getLogger()
            print(f"Debug: Root logger handlers: {len(root_logger.handlers)}")
            
            # The logger should exist and logging should be configured
            if logger and (len(logger.handlers) > 0 or len(root_logger.handlers) > 0):
                print("✓ Logging is properly integrated")
                return True
            else:
                print("✗ Logger not properly configured")
                return False
        else:
            print("✗ Logger not found")
            return False
            
    except Exception as e:
        print(f"✗ Logging integration test failed: {e}")
        return False

def main():
    """Run organization analyzer tests"""
    print("Testing AWS Organization Analyzer improvements...")
    print("=" * 70)
    
    tests_passed = 0
    total_tests = 6
    
    if test_organization_analyzer_class():
        tests_passed += 1
    
    if test_proper_structure():
        tests_passed += 1
    
    if test_json_export_capability():
        tests_passed += 1
    
    if test_dependency_checking_logic():
        tests_passed += 1
    
    if test_error_handling_structure():
        tests_passed += 1
    
    if test_logging_integration():
        tests_passed += 1
    
    print("=" * 70)
    print(f"Tests passed: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        print("✓ All organization analyzer tests passed! The script is much more professional and capable.")
        return True
    else:
        print("✗ Some tests failed. Please check the implementation.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

#!/usr/bin/env python3
"""
Quick test to validate the OU hierarchy fix
"""

import sys
import os

# Add the current directory to the path so we can import the module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_hierarchy_report_fix():
    """Test that the OU hierarchy report doesn't crash"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Create analyzer with test data
        analyzer = import_module.OrganizationAnalyzer()
        
        # Set up test data that would trigger the bug
        analyzer.roots = [{'Id': 'r-test', 'Name': 'Root'}]
        analyzer.account_ou_assignments = {
            '123456789012': {'ParentId': 'r-test', 'ParentType': 'ROOT', 'AccountName': 'TestAccount'}
        }
        analyzer.ou_policies = {}
        analyzer.organizational_units = {}
        analyzer.ou_hierarchy = {'r-test': []}
        
        # This should not crash now
        analyzer.generate_ou_hierarchy_report()
        
        print("✓ OU hierarchy report fix works correctly")
        return True
        
    except Exception as e:
        print(f"✗ OU hierarchy report fix failed: {e}")
        return False

if __name__ == "__main__":
    success = test_hierarchy_report_fix()
    if success:
        print("Fix validated successfully!")
    else:
        print("Fix validation failed!")
    sys.exit(0 if success else 1)

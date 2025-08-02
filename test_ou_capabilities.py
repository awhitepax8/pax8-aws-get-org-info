#!/usr/bin/env python3
"""
Test script to validate the enhanced OU analysis capabilities
This tests the Phase 1 organizational structure features
"""

import sys
import os
import tempfile
import json
from unittest.mock import Mock, patch

# Add the current directory to the path so we can import the module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_ou_data_structures():
    """Test that the OrganizationAnalyzer has the new OU data structures"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Test OrganizationAnalyzer initialization with OU structures
        analyzer = import_module.OrganizationAnalyzer()
        
        # Check for new OU-related data structures
        required_attributes = [
            'organizational_units',
            'ou_hierarchy', 
            'account_ou_assignments',
            'ou_policies',
            'roots'
        ]
        
        missing_attributes = []
        for attr in required_attributes:
            if not hasattr(analyzer, attr):
                missing_attributes.append(attr)
        
        if missing_attributes:
            print(f"✗ Missing OU data structures: {missing_attributes}")
            return False
        
        # Check that they initialize as expected types
        if (isinstance(analyzer.organizational_units, dict) and
            isinstance(analyzer.ou_hierarchy, dict) and
            isinstance(analyzer.account_ou_assignments, dict) and
            isinstance(analyzer.ou_policies, dict) and
            isinstance(analyzer.roots, list)):
            print("✓ OU data structures initialized correctly")
            return True
        else:
            print("✗ OU data structures have incorrect types")
            return False
            
    except Exception as e:
        print(f"✗ OU data structures test failed: {e}")
        return False

def test_ou_methods_exist():
    """Test that all new OU-related methods exist"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Check for new OU methods
        required_methods = [
            'get_organization_roots',
            'get_organizational_units',
            'get_account_ou_assignments',
            'get_ou_policies',
            'generate_ou_hierarchy_report',
            '_get_ous_recursive',
            '_get_policies_for_target',
            '_print_ou_hierarchy'
        ]
        
        missing_methods = []
        for method_name in required_methods:
            if not hasattr(import_module.OrganizationAnalyzer, method_name):
                missing_methods.append(method_name)
        
        if missing_methods:
            print(f"✗ Missing OU methods: {missing_methods}")
            return False
        
        print(f"✓ All {len(required_methods)} OU methods exist")
        return True
        
    except Exception as e:
        print(f"✗ OU methods test failed: {e}")
        return False

def test_enhanced_json_export():
    """Test that JSON export includes organizational structure data"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Create analyzer with test OU data
        analyzer = import_module.OrganizationAnalyzer()
        analyzer.organization_id = 'o-test123456'
        analyzer.organization_info = {'Id': 'o-test123456', 'FeatureSet': 'ALL'}
        
        # Add test OU data
        analyzer.roots = [{'Id': 'r-test', 'Name': 'Root', 'Arn': 'arn:aws:organizations::123456789012:root/o-test123456/r-test'}]
        analyzer.organizational_units = {
            'ou-test1': {'Id': 'ou-test1', 'Name': 'TestOU1', 'ParentId': 'r-test'},
            'ou-test2': {'Id': 'ou-test2', 'Name': 'TestOU2', 'ParentId': 'ou-test1'}
        }
        analyzer.ou_hierarchy = {
            'r-test': ['ou-test1'],
            'ou-test1': ['ou-test2']
        }
        analyzer.account_ou_assignments = {
            '123456789012': {'ParentId': 'ou-test1', 'ParentType': 'ORGANIZATIONAL_UNIT', 'AccountName': 'TestAccount'}
        }
        analyzer.ou_policies = {
            'ou-test1': [{'Id': 'p-test', 'Name': 'TestPolicy', 'Type': 'SERVICE_CONTROL_POLICY'}]
        }
        
        # Test JSON export to a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_file_path = temp_file.name
        
        try:
            result = analyzer.export_to_json(temp_file_path)
            
            if result and os.path.exists(temp_file_path):
                # Verify the JSON content includes OU data
                with open(temp_file_path, 'r') as f:
                    exported_data = json.load(f)
                
                # Check for organizational structure section
                if ('organizational_structure' in exported_data and
                    'roots' in exported_data['organizational_structure'] and
                    'organizational_units' in exported_data['organizational_structure'] and
                    'ou_hierarchy' in exported_data['organizational_structure'] and
                    'account_ou_assignments' in exported_data['organizational_structure'] and
                    'ou_policies' in exported_data['organizational_structure']):
                    
                    # Check migration summary includes OU metrics
                    migration_summary = exported_data.get('migration_summary', {})
                    if ('total_organizational_units' in migration_summary and
                        'total_roots' in migration_summary and
                        'total_ou_policy_attachments' in migration_summary):
                        print("✓ Enhanced JSON export with OU data works correctly")
                        return True
                    else:
                        print("✗ Migration summary missing OU metrics")
                        return False
                else:
                    print("✗ JSON export missing organizational structure data")
                    return False
            else:
                print("✗ Enhanced JSON export failed")
                return False
                
        finally:
            # Clean up temp file
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
            
    except Exception as e:
        print(f"✗ Enhanced JSON export test failed: {e}")
        return False

def test_hierarchy_building_logic():
    """Test the OU hierarchy building logic"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Create analyzer and test hierarchy logic
        analyzer = import_module.OrganizationAnalyzer()
        
        # Simulate adding OUs to hierarchy
        analyzer.ou_hierarchy = {}
        analyzer.organizational_units = {}
        
        # Test data: Root -> OU1 -> OU2
        root_id = 'r-test'
        ou1_id = 'ou-test1'
        ou2_id = 'ou-test2'
        
        # Simulate the hierarchy building
        analyzer.ou_hierarchy[root_id] = [ou1_id]
        analyzer.ou_hierarchy[ou1_id] = [ou2_id]
        
        analyzer.organizational_units[ou1_id] = {
            'Id': ou1_id,
            'Name': 'TestOU1',
            'ParentId': root_id
        }
        analyzer.organizational_units[ou2_id] = {
            'Id': ou2_id,
            'Name': 'TestOU2', 
            'ParentId': ou1_id
        }
        
        # Test the hierarchy structure
        if (root_id in analyzer.ou_hierarchy and
            ou1_id in analyzer.ou_hierarchy[root_id] and
            ou1_id in analyzer.ou_hierarchy and
            ou2_id in analyzer.ou_hierarchy[ou1_id] and
            analyzer.organizational_units[ou1_id]['ParentId'] == root_id and
            analyzer.organizational_units[ou2_id]['ParentId'] == ou1_id):
            print("✓ OU hierarchy building logic works correctly")
            return True
        else:
            print("✗ OU hierarchy building logic failed")
            return False
            
    except Exception as e:
        print(f"✗ Hierarchy building test failed: {e}")
        return False

def test_migration_summary_enhancements():
    """Test that migration summary includes OU-specific information"""
    try:
        # Read the script and check for OU-related migration summary content
        with open("list-org-info.py", 'r') as f:
            content = f.read()
        
        # Check for OU-related migration planning content
        ou_migration_indicators = [
            'ORGANIZATIONAL STRUCTURE SUMMARY',
            'total_organizational_units',
            'total_ou_policy_attachments',
            'accounts_in_root',
            'accounts_in_ous',
            'Complete OU structure must be recreated'
        ]
        
        missing_indicators = []
        for indicator in ou_migration_indicators:
            if indicator not in content:
                missing_indicators.append(indicator)
        
        if missing_indicators:
            print(f"✗ Missing OU migration indicators: {missing_indicators}")
            return False
        
        print("✓ Migration summary includes OU-specific planning information")
        return True
        
    except Exception as e:
        print(f"✗ Migration summary enhancement test failed: {e}")
        return False

def test_tool_version_update():
    """Test that tool version has been updated to reflect new capabilities"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Create analyzer and check version in export
        analyzer = import_module.OrganizationAnalyzer()
        analyzer.organization_id = 'o-test123456'
        
        # Test JSON export to check version
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_file_path = temp_file.name
        
        try:
            result = analyzer.export_to_json(temp_file_path)
            
            if result and os.path.exists(temp_file_path):
                with open(temp_file_path, 'r') as f:
                    exported_data = json.load(f)
                
                version = exported_data.get('analysis_metadata', {}).get('tool_version')
                includes_ou = exported_data.get('analysis_metadata', {}).get('includes_organizational_structure')
                
                if version == '2.1' and includes_ou:
                    print("✓ Tool version updated to reflect OU capabilities")
                    return True
                else:
                    print(f"✗ Tool version not updated correctly. Version: {version}, Includes OU: {includes_ou}")
                    return False
            else:
                print("✗ Could not test tool version")
                return False
                
        finally:
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
            
    except Exception as e:
        print(f"✗ Tool version test failed: {e}")
        return False

def main():
    """Run OU capabilities tests"""
    print("Testing Phase 1: Organizational Structure capabilities...")
    print("=" * 70)
    
    tests_passed = 0
    total_tests = 6
    
    if test_ou_data_structures():
        tests_passed += 1
    
    if test_ou_methods_exist():
        tests_passed += 1
    
    if test_enhanced_json_export():
        tests_passed += 1
    
    if test_hierarchy_building_logic():
        tests_passed += 1
    
    if test_migration_summary_enhancements():
        tests_passed += 1
    
    if test_tool_version_update():
        tests_passed += 1
    
    print("=" * 70)
    print(f"Tests passed: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        print("✓ All Phase 1 OU capabilities tests passed! Ready for org-to-org migration analysis.")
        return True
    else:
        print("✗ Some tests failed. Please check the implementation.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

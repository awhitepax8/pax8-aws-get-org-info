#!/usr/bin/env python3
"""
Test script to validate the Phase 2 SCP analysis capabilities
This tests the Service Control Policies analysis features
"""

import sys
import os
import tempfile
import json
from unittest.mock import Mock, patch

# Add the current directory to the path so we can import the module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_scp_data_structures():
    """Test that the OrganizationAnalyzer has the new SCP data structures"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Test OrganizationAnalyzer initialization with SCP structures
        analyzer = import_module.OrganizationAnalyzer()
        
        # Check for new SCP-related data structures
        required_attributes = [
            'service_control_policies',
            'scp_attachments', 
            'scp_inheritance_map',
            'custom_policies'
        ]
        
        missing_attributes = []
        for attr in required_attributes:
            if not hasattr(analyzer, attr):
                missing_attributes.append(attr)
        
        if missing_attributes:
            print(f"✗ Missing SCP data structures: {missing_attributes}")
            return False
        
        # Check that they initialize as expected types
        if (isinstance(analyzer.service_control_policies, dict) and
            isinstance(analyzer.scp_attachments, dict) and
            isinstance(analyzer.scp_inheritance_map, dict) and
            isinstance(analyzer.custom_policies, dict)):
            print("✓ SCP data structures initialized correctly")
            return True
        else:
            print("✗ SCP data structures have incorrect types")
            return False
            
    except Exception as e:
        print(f"✗ SCP data structures test failed: {e}")
        return False

def test_scp_methods_exist():
    """Test that all new SCP-related methods exist"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Check for new SCP methods
        required_methods = [
            'get_service_control_policies',
            'get_scp_attachments',
            'analyze_scp_inheritance',
            'generate_scp_analysis_report',
            '_get_target_type',
            '_get_target_name',
            '_get_parent_id'
        ]
        
        missing_methods = []
        for method_name in required_methods:
            if not hasattr(import_module.OrganizationAnalyzer, method_name):
                missing_methods.append(method_name)
        
        if missing_methods:
            print(f"✗ Missing SCP methods: {missing_methods}")
            return False
        
        print(f"✓ All {len(required_methods)} SCP methods exist")
        return True
        
    except Exception as e:
        print(f"✗ SCP methods test failed: {e}")
        return False

def test_enhanced_json_export_with_scp():
    """Test that JSON export includes SCP analysis data"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Create analyzer with test SCP data
        analyzer = import_module.OrganizationAnalyzer()
        analyzer.organization_id = 'o-test123456'
        analyzer.organization_info = {'Id': 'o-test123456', 'FeatureSet': 'ALL'}
        
        # Add test SCP data
        analyzer.service_control_policies = {
            'p-test1': {
                'Id': 'p-test1',
                'Name': 'TestSCP1',
                'Type': 'SERVICE_CONTROL_POLICY',
                'AwsManaged': False,
                'Content': '{"Version": "2012-10-17", "Statement": []}'
            },
            'p-test2': {
                'Id': 'p-test2',
                'Name': 'FullAWSAccess',
                'Type': 'SERVICE_CONTROL_POLICY',
                'AwsManaged': True,
                'Content': '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
            }
        }
        analyzer.scp_attachments = {
            'ou-test1': [{'PolicyId': 'p-test1', 'PolicyName': 'TestSCP1'}]
        }
        analyzer.scp_inheritance_map = {
            '123456789012': {
                'AccountName': 'TestAccount',
                'InheritedSCPs': [{'PolicyId': 'p-test1', 'PolicyName': 'TestSCP1'}],
                'TotalInheritedSCPs': 1
            }
        }
        analyzer.custom_policies = {
            'p-test1': '{"Version": "2012-10-17", "Statement": []}'
        }
        
        # Test JSON export to a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_file_path = temp_file.name
        
        try:
            result = analyzer.export_to_json(temp_file_path)
            
            if result and os.path.exists(temp_file_path):
                # Verify the JSON content includes SCP data
                with open(temp_file_path, 'r') as f:
                    exported_data = json.load(f)
                
                # Check for SCP section
                if ('service_control_policies' in exported_data and
                    'policies' in exported_data['service_control_policies'] and
                    'attachments' in exported_data['service_control_policies'] and
                    'inheritance_map' in exported_data['service_control_policies'] and
                    'custom_policies' in exported_data['service_control_policies']):
                    
                    # Check migration summary includes SCP metrics
                    migration_summary = exported_data.get('migration_summary', {})
                    if ('total_service_control_policies' in migration_summary and
                        'total_custom_scps' in migration_summary and
                        'total_aws_managed_scps' in migration_summary and
                        'total_scp_attachments' in migration_summary and
                        'accounts_with_inherited_scps' in migration_summary):
                        
                        # Check metadata indicates SCP analysis
                        metadata = exported_data.get('analysis_metadata', {})
                        if metadata.get('includes_scp_analysis') and metadata.get('tool_version') == '2.2':
                            print("✓ Enhanced JSON export with SCP data works correctly")
                            return True
                        else:
                            print("✗ Metadata missing SCP analysis indicators")
                            return False
                    else:
                        print("✗ Migration summary missing SCP metrics")
                        return False
                else:
                    print("✗ JSON export missing SCP analysis data")
                    return False
            else:
                print("✗ Enhanced JSON export with SCP failed")
                return False
                
        finally:
            # Clean up temp file
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
            
    except Exception as e:
        print(f"✗ Enhanced JSON export with SCP test failed: {e}")
        return False

def test_target_type_detection():
    """Test the target type detection logic"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Create analyzer and test target type detection
        analyzer = import_module.OrganizationAnalyzer()
        
        # Test different target ID patterns
        test_cases = [
            ('r-test123', 'ROOT'),
            ('ou-test123', 'ORGANIZATIONAL_UNIT'),
            ('123456789012', 'ACCOUNT'),
            ('unknown-format', 'UNKNOWN')
        ]
        
        all_correct = True
        for target_id, expected_type in test_cases:
            actual_type = analyzer._get_target_type(target_id)
            if actual_type != expected_type:
                print(f"✗ Target type detection failed for {target_id}: expected {expected_type}, got {actual_type}")
                all_correct = False
        
        if all_correct:
            print("✓ Target type detection logic works correctly")
            return True
        else:
            return False
            
    except Exception as e:
        print(f"✗ Target type detection test failed: {e}")
        return False

def test_scp_inheritance_logic():
    """Test the SCP inheritance analysis logic"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Create analyzer with test data for inheritance
        analyzer = import_module.OrganizationAnalyzer()
        
        # Set up test hierarchy: Root -> OU1 -> Account
        analyzer.roots = [{'Id': 'r-test', 'Name': 'Root'}]
        analyzer.organizational_units = {
            'ou-test1': {'Id': 'ou-test1', 'Name': 'TestOU1', 'ParentId': 'r-test'}
        }
        analyzer.accounts = [{'Id': '123456789012', 'Name': 'TestAccount'}]
        analyzer.account_ou_assignments = {
            '123456789012': {'ParentId': 'ou-test1', 'ParentType': 'ORGANIZATIONAL_UNIT', 'AccountName': 'TestAccount'}
        }
        
        # Set up SCP attachments
        analyzer.scp_attachments = {
            'r-test': [{'PolicyId': 'p-root', 'PolicyName': 'RootSCP', 'AwsManaged': False}],
            'ou-test1': [{'PolicyId': 'p-ou', 'PolicyName': 'OUSCP', 'AwsManaged': False}]
        }
        
        # Test inheritance analysis
        result = analyzer.analyze_scp_inheritance()
        
        if result and '123456789012' in analyzer.scp_inheritance_map:
            account_inheritance = analyzer.scp_inheritance_map['123456789012']
            inherited_scps = account_inheritance.get('InheritedSCPs', [])
            
            # Should inherit from both OU and Root
            if len(inherited_scps) == 2:
                policy_names = [scp['PolicyName'] for scp in inherited_scps]
                if 'RootSCP' in policy_names and 'OUSCP' in policy_names:
                    print("✓ SCP inheritance logic works correctly")
                    return True
                else:
                    print(f"✗ SCP inheritance missing expected policies: {policy_names}")
                    return False
            else:
                print(f"✗ SCP inheritance count incorrect: expected 2, got {len(inherited_scps)}")
                return False
        else:
            print("✗ SCP inheritance analysis failed")
            return False
            
    except Exception as e:
        print(f"✗ SCP inheritance logic test failed: {e}")
        return False

def test_migration_critical_warnings():
    """Test that the script identifies critical SCP migration requirements"""
    try:
        # Read the script and check for SCP-related migration warnings
        with open("list-org-info.py", 'r') as f:
            content = f.read()
        
        # Check for SCP-related migration planning content
        scp_migration_indicators = [
            'SERVICE CONTROL POLICIES ANALYSIS',
            'Custom SCPs must be recreated',
            'total_custom_scps',
            'total_service_control_policies',
            'SCP INHERITANCE ANALYSIS',
            'accounts_with_inherited_scps'
        ]
        
        missing_indicators = []
        for indicator in scp_migration_indicators:
            if indicator not in content:
                missing_indicators.append(indicator)
        
        if missing_indicators:
            print(f"✗ Missing SCP migration indicators: {missing_indicators}")
            return False
        
        print("✓ Migration analysis includes critical SCP warnings and planning information")
        return True
        
    except Exception as e:
        print(f"✗ Migration critical warnings test failed: {e}")
        return False

def main():
    """Run Phase 2 SCP capabilities tests"""
    print("Testing Phase 2: Service Control Policies capabilities...")
    print("=" * 70)
    
    tests_passed = 0
    total_tests = 6
    
    if test_scp_data_structures():
        tests_passed += 1
    
    if test_scp_methods_exist():
        tests_passed += 1
    
    if test_enhanced_json_export_with_scp():
        tests_passed += 1
    
    if test_target_type_detection():
        tests_passed += 1
    
    if test_scp_inheritance_logic():
        tests_passed += 1
    
    if test_migration_critical_warnings():
        tests_passed += 1
    
    print("=" * 70)
    print(f"Tests passed: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        print("✓ All Phase 2 SCP capabilities tests passed! Ready for comprehensive SCP migration analysis.")
        return True
    else:
        print("✗ Some tests failed. Please check the implementation.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

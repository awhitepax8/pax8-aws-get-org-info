#!/usr/bin/env python3
"""
Test script to validate the Phase 3 service configuration analysis capabilities
This tests the service configuration analysis features
"""

import sys
import os
import tempfile
import json
from unittest.mock import Mock, patch

# Add the current directory to the path so we can import the module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_service_config_data_structures():
    """Test that the OrganizationAnalyzer has the new service configuration data structures"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Test OrganizationAnalyzer initialization with service config structures
        analyzer = import_module.OrganizationAnalyzer()
        
        # Check for new service configuration data structures
        required_attributes = [
            'service_configurations',
            'trusted_access_settings', 
            'service_linked_roles',
            'cross_service_dependencies',
            'service_integration_details'
        ]
        
        missing_attributes = []
        for attr in required_attributes:
            if not hasattr(analyzer, attr):
                missing_attributes.append(attr)
        
        if missing_attributes:
            print(f"✗ Missing service config data structures: {missing_attributes}")
            return False
        
        # Check that they initialize as expected types
        if (isinstance(analyzer.service_configurations, dict) and
            isinstance(analyzer.trusted_access_settings, dict) and
            isinstance(analyzer.cross_service_dependencies, dict)):
            print("✓ Service configuration data structures initialized correctly")
            return True
        else:
            print("✗ Service configuration data structures have incorrect types")
            return False
            
    except Exception as e:
        print(f"✗ Service config data structures test failed: {e}")
        return False

def test_service_config_methods_exist():
    """Test that all new service configuration methods exist"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Check for new service configuration methods
        required_methods = [
            'analyze_service_configurations',
            '_analyze_trusted_access',
            '_analyze_service_specific_config',
            '_analyze_service_dependencies',
            '_assess_service_complexity',
            'generate_service_configuration_report'
        ]
        
        missing_methods = []
        for method_name in required_methods:
            if not hasattr(import_module.OrganizationAnalyzer, method_name):
                missing_methods.append(method_name)
        
        if missing_methods:
            print(f"✗ Missing service config methods: {missing_methods}")
            return False
        
        print(f"✓ All {len(required_methods)} service configuration methods exist")
        return True
        
    except Exception as e:
        print(f"✗ Service config methods test failed: {e}")
        return False

def test_service_complexity_assessment():
    """Test the service complexity assessment logic"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Create analyzer and test complexity assessment
        analyzer = import_module.OrganizationAnalyzer()
        
        # Test different service complexity levels
        test_cases = [
            ('sso.amazonaws.com', 'High'),
            ('guardduty.amazonaws.com', 'High'),
            ('securityhub.amazonaws.com', 'High'),
            ('config.amazonaws.com', 'High'),
            ('cloudtrail.amazonaws.com', 'Medium'),
            ('ram.amazonaws.com', 'Medium'),
            ('unknown-service.amazonaws.com', 'Low')
        ]
        
        all_correct = True
        for service_principal, expected_complexity in test_cases:
            actual_complexity = analyzer._assess_service_complexity(service_principal)
            if actual_complexity != expected_complexity:
                print(f"✗ Complexity assessment failed for {service_principal}: expected {expected_complexity}, got {actual_complexity}")
                all_correct = False
        
        if all_correct:
            print("✓ Service complexity assessment logic works correctly")
            return True
        else:
            return False
            
    except Exception as e:
        print(f"✗ Service complexity assessment test failed: {e}")
        return False

def test_enhanced_json_export_with_service_config():
    """Test that JSON export includes service configuration analysis data"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Create analyzer with test service config data
        analyzer = import_module.OrganizationAnalyzer()
        analyzer.organization_id = 'o-test123456'
        analyzer.organization_info = {'Id': 'o-test123456', 'FeatureSet': 'ALL'}
        
        # Add test service configuration data
        analyzer.service_configurations = {
            'sso.amazonaws.com': {
                'ServicePrincipal': 'sso.amazonaws.com',
                'MigrationComplexity': 'High',
                'ConfigurationItems': ['Permission sets', 'User assignments']
            }
        }
        analyzer.trusted_access_settings = {
            'sso.amazonaws.com': {
                'ServiceName': 'AWS Single Sign-On',
                'CriticalForMigration': True,
                'RequiresSpecialHandling': True
            }
        }
        analyzer.cross_service_dependencies = {
            'sso.amazonaws.com': ['iam.amazonaws.com']
        }
        
        # Test JSON export to a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_file_path = temp_file.name
        
        try:
            result = analyzer.export_to_json(temp_file_path)
            
            if result and os.path.exists(temp_file_path):
                # Verify the JSON content includes service config data
                with open(temp_file_path, 'r') as f:
                    exported_data = json.load(f)
                
                # Check for service configuration section
                if ('service_configurations' in exported_data and
                    'configurations' in exported_data['service_configurations'] and
                    'trusted_access_settings' in exported_data['service_configurations'] and
                    'service_dependencies' in exported_data['service_configurations']):
                    
                    # Check migration summary includes service config metrics
                    migration_summary = exported_data.get('migration_summary', {})
                    if ('total_service_configurations_analyzed' in migration_summary and
                        'high_complexity_services' in migration_summary and
                        'services_requiring_special_handling' in migration_summary):
                        
                        # Check metadata indicates service config analysis
                        metadata = exported_data.get('analysis_metadata', {})
                        if (metadata.get('includes_service_configuration_analysis') and 
                            metadata.get('tool_version') == '2.3'):
                            print("✓ Enhanced JSON export with service configuration data works correctly")
                            return True
                        else:
                            print("✗ Metadata missing service config analysis indicators")
                            return False
                    else:
                        print("✗ Migration summary missing service config metrics")
                        return False
                else:
                    print("✗ JSON export missing service configuration analysis data")
                    return False
            else:
                print("✗ Enhanced JSON export with service config failed")
                return False
                
        finally:
            # Clean up temp file
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
            
    except Exception as e:
        print(f"✗ Enhanced JSON export with service config test failed: {e}")
        return False

def test_service_dependency_analysis():
    """Test the service dependency analysis logic"""
    try:
        # Import the module
        import importlib.util
        spec = importlib.util.spec_from_file_location("list_org_info", "list-org-info.py")
        import_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(import_module)
        
        # Create analyzer and test dependency analysis
        analyzer = import_module.OrganizationAnalyzer()
        
        # Test known service dependencies
        analyzer._analyze_service_dependencies('sso.amazonaws.com')
        analyzer._analyze_service_dependencies('guardduty.amazonaws.com')
        analyzer._analyze_service_dependencies('unknown-service.amazonaws.com')
        
        # Check that dependencies were recorded correctly
        sso_deps = analyzer.cross_service_dependencies.get('sso.amazonaws.com', [])
        guardduty_deps = analyzer.cross_service_dependencies.get('guardduty.amazonaws.com', [])
        unknown_deps = analyzer.cross_service_dependencies.get('unknown-service.amazonaws.com', [])
        
        if ('iam.amazonaws.com' in sso_deps and
            'iam.amazonaws.com' in guardduty_deps and
            'securityhub.amazonaws.com' in guardduty_deps and
            len(unknown_deps) == 0):
            print("✓ Service dependency analysis logic works correctly")
            return True
        else:
            print(f"✗ Service dependency analysis failed. SSO: {sso_deps}, GuardDuty: {guardduty_deps}, Unknown: {unknown_deps}")
            return False
            
    except Exception as e:
        print(f"✗ Service dependency analysis test failed: {e}")
        return False

def test_migration_service_warnings():
    """Test that the script identifies critical service migration requirements"""
    try:
        # Read the script and check for service-related migration warnings
        with open("list-org-info.py", 'r') as f:
            content = f.read()
        
        # Check for service-related migration planning content
        service_migration_indicators = [
            'SERVICE CONFIGURATION ANALYSIS',
            'HIGH COMPLEXITY SERVICES',
            'MigrationComplexity',
            'RequiresSpecialHandling',
            'SERVICE DEPENDENCIES',
            'total_service_configurations_analyzed',
            'high_complexity_services'
        ]
        
        missing_indicators = []
        for indicator in service_migration_indicators:
            if indicator not in content:
                missing_indicators.append(indicator)
        
        if missing_indicators:
            print(f"✗ Missing service migration indicators: {missing_indicators}")
            return False
        
        print("✓ Migration analysis includes critical service configuration warnings and planning information")
        return True
        
    except Exception as e:
        print(f"✗ Migration service warnings test failed: {e}")
        return False

def main():
    """Run Phase 3 service configuration capabilities tests"""
    print("Testing Phase 3: Service Configuration capabilities...")
    print("=" * 70)
    
    tests_passed = 0
    total_tests = 6
    
    if test_service_config_data_structures():
        tests_passed += 1
    
    if test_service_config_methods_exist():
        tests_passed += 1
    
    if test_service_complexity_assessment():
        tests_passed += 1
    
    if test_enhanced_json_export_with_service_config():
        tests_passed += 1
    
    if test_service_dependency_analysis():
        tests_passed += 1
    
    if test_migration_service_warnings():
        tests_passed += 1
    
    print("=" * 70)
    print(f"Tests passed: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        print("✓ All Phase 3 service configuration capabilities tests passed! Ready for comprehensive service migration analysis.")
        return True
    else:
        print("✗ Some tests failed. Please check the implementation.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

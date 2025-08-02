import boto3
import logging
import sys
import json
import os
from datetime import datetime
from collections import defaultdict
from botocore.exceptions import ClientError, NoCredentialsError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)

logger = logging.getLogger(__name__)

class OrganizationAnalyzer:
    """Class to analyze AWS Organizations for migration planning and auditing"""
    
    def __init__(self):
        self.organization_id = None
        self.organization_info = {}
        self.accounts = []
        self.enabled_services = []
        self.delegated_administrators = []
        self.enabled_policy_types = []
        self.iam_dependencies = {
            'policies': [],
            'roles': []
        }
        self.org_client = None
        self.iam_client = None
    
    def initialize_clients(self):
        """Initialize AWS clients with proper error handling"""
        try:
            logger.info("Initializing AWS clients")
            
            self.org_client = boto3.client('organizations')
            self.iam_client = boto3.client('iam')
            
            logger.info("Successfully initialized AWS clients")
            return True
            
        except NoCredentialsError:
            logger.error("AWS credentials not found. Please configure your credentials.")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
            return False
    
    def get_organization_info(self):
        """Get basic organization information"""
        try:
            logger.info("Retrieving organization information")
            
            response = self.org_client.describe_organization()
            organization = response['Organization']
            
            self.organization_id = organization['Id']
            self.organization_info = {
                'Id': organization['Id'],
                'Arn': organization['Arn'],
                'FeatureSet': organization['FeatureSet'],
                'MasterAccountArn': organization['MasterAccountArn'],
                'MasterAccountId': organization['MasterAccountId'],
                'MasterAccountEmail': organization['MasterAccountEmail']
            }
            
            logger.info(f"Found organization: {self.organization_id}")
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AWSOrganizationsNotInUseException':
                logger.error("This AWS account is not part of an AWS Organization")
                print("This AWS account is not part of an AWS Organization.")
                return False
            elif error_code == 'AccessDenied':
                logger.error("Access denied. Please ensure you have the necessary permissions for AWS Organizations operations.")
                return False
            else:
                logger.error(f"AWS API error: {error_code} - {e.response['Error']['Message']}")
                return False
        except Exception as e:
            logger.error(f"Unexpected error retrieving organization info: {e}")
            return False
    
    def get_organization_accounts(self):
        """Retrieve all accounts in the organization"""
        try:
            logger.info("Retrieving organization accounts")
            
            paginator = self.org_client.get_paginator('list_accounts')
            account_count = 0
            
            for page in paginator.paginate():
                for account in page['Accounts']:
                    account_info = {
                        'Id': account['Id'],
                        'Name': account['Name'],
                        'Email': account['Email'],
                        'Status': account['Status'],
                        'JoinedMethod': account.get('JoinedMethod', 'Unknown'),
                        'JoinedTimestamp': str(account.get('JoinedTimestamp', 'Unknown'))
                    }
                    self.accounts.append(account_info)
                    account_count += 1
            
            logger.info(f"Found {account_count} accounts in the organization")
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                logger.error("Access denied retrieving accounts. Please ensure you have the necessary permissions.")
            else:
                logger.error(f"AWS API error retrieving accounts: {error_code} - {e.response['Error']['Message']}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error retrieving accounts: {e}")
            return False
    
    def get_enabled_services(self):
        """Retrieve enabled AWS services for the organization"""
        try:
            logger.info("Retrieving enabled AWS services")
            
            paginator = self.org_client.get_paginator('list_aws_service_access_for_organization')
            service_count = 0
            
            for page in paginator.paginate():
                for service in page['EnabledServicePrincipals']:
                    service_info = {
                        'ServicePrincipal': service['ServicePrincipal'],
                        'DateEnabled': str(service.get('DateEnabled', 'Unknown'))
                    }
                    self.enabled_services.append(service_info)
                    service_count += 1
            
            logger.info(f"Found {service_count} enabled services")
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                logger.error("Access denied retrieving enabled services. Please ensure you have the necessary permissions.")
            else:
                logger.error(f"AWS API error retrieving enabled services: {error_code} - {e.response['Error']['Message']}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error retrieving enabled services: {e}")
            return False
    
    def get_delegated_administrators(self):
        """Retrieve delegated administrator accounts"""
        try:
            logger.info("Retrieving delegated administrators")
            
            try:
                response = self.org_client.list_delegated_administrators()
                admin_count = 0
                
                for admin in response.get('DelegatedAdministrators', []):
                    admin_info = {
                        'Id': admin['Id'],
                        'Name': admin['Name'],
                        'Email': admin['Email'],
                        'Status': admin.get('Status', 'Unknown'),
                        'JoinedMethod': admin.get('JoinedMethod', 'Unknown'),
                        'JoinedTimestamp': str(admin.get('JoinedTimestamp', 'Unknown')),
                        'DelegatedServices': []
                    }
                    
                    # Get delegated services for this administrator
                    try:
                        paginator = self.org_client.get_paginator('list_delegated_services_for_account')
                        for page in paginator.paginate(AccountId=admin['Id']):
                            for service in page['DelegatedServices']:
                                service_info = {
                                    'ServicePrincipal': service['ServicePrincipal'],
                                    'DelegationEnabledDate': str(service['DelegationEnabledDate'])
                                }
                                admin_info['DelegatedServices'].append(service_info)
                    except ClientError as e:
                        logger.warning(f"Could not retrieve delegated services for account {admin['Id']}: {e.response['Error']['Code']}")
                    
                    self.delegated_administrators.append(admin_info)
                    admin_count += 1
                
                logger.info(f"Found {admin_count} delegated administrators")
                return True
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'UnsupportedAPIEndpointException':
                    logger.info("Delegated administrators not supported in this region")
                    return True
                else:
                    raise
                    
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                logger.error("Access denied retrieving delegated administrators. Please ensure you have the necessary permissions.")
            else:
                logger.error(f"AWS API error retrieving delegated administrators: {error_code} - {e.response['Error']['Message']}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error retrieving delegated administrators: {e}")
            return False
    
    def get_enabled_policy_types(self):
        """Retrieve enabled policy types for the organization"""
        try:
            logger.info("Retrieving enabled policy types")
            
            response = self.org_client.list_roots()
            if response.get('Roots'):
                root = response['Roots'][0]
                policy_types = root.get('PolicyTypes', [])
                
                for policy_type in policy_types:
                    if policy_type.get('Status') == 'ENABLED':
                        policy_info = {
                            'Type': policy_type['Type'],
                            'Status': policy_type['Status']
                        }
                        self.enabled_policy_types.append(policy_info)
                
                logger.info(f"Found {len(self.enabled_policy_types)} enabled policy types")
                return True
            else:
                logger.warning("No organization roots found")
                return True
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                logger.error("Access denied retrieving policy types. Please ensure you have the necessary permissions.")
            else:
                logger.error(f"AWS API error retrieving policy types: {error_code} - {e.response['Error']['Message']}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error retrieving policy types: {e}")
            return False
    
    def analyze_iam_dependencies(self):
        """Analyze IAM policies and roles for organization dependencies"""
        try:
            logger.info("Analyzing IAM dependencies on current organization")
            
            if not self.organization_id:
                logger.error("Organization ID not available for dependency analysis")
                return False
            
            # Analyze IAM policies
            logger.info("Checking IAM policies for organization dependencies")
            policy_count = 0
            dependency_count = 0
            
            paginator = self.iam_client.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local', OnlyAttached=False):
                for policy in page['Policies']:
                    if not policy.get('IsAttachable', True):
                        continue
                    
                    policy_count += 1
                    logger.debug(f"Checking policy: {policy['PolicyName']}")
                    
                    try:
                        policy_version = self.iam_client.get_policy_version(
                            PolicyArn=policy['Arn'], 
                            VersionId=policy['DefaultVersionId']
                        )
                        
                        policy_document = policy_version['PolicyVersion']['Document']
                        
                        # Check for organization ID in policy document
                        if self._check_organization_dependency(policy_document):
                            policy_info = {
                                'Name': policy['PolicyName'],
                                'Arn': policy['Arn'],
                                'Type': 'Policy',
                                'DependencyType': 'Organization ID Reference'
                            }
                            self.iam_dependencies['policies'].append(policy_info)
                            dependency_count += 1
                            logger.debug(f"Found organization dependency in policy: {policy['PolicyName']}")
                            
                    except ClientError as e:
                        logger.warning(f"Could not check policy {policy['PolicyName']}: {e.response['Error']['Code']}")
                        continue
            
            logger.info(f"Checked {policy_count} IAM policies, found {len(self.iam_dependencies['policies'])} with dependencies")
            
            # Analyze IAM roles
            logger.info("Checking IAM roles for organization dependencies")
            role_count = 0
            
            paginator = self.iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    role_count += 1
                    logger.debug(f"Checking role: {role['RoleName']}")
                    
                    try:
                        role_response = self.iam_client.get_role(RoleName=role['RoleName'])
                        trust_policy = role_response['Role']['AssumeRolePolicyDocument']
                        
                        # Check for organization dependency in trust policy
                        if self._check_organization_dependency(trust_policy):
                            role_info = {
                                'Name': role['RoleName'],
                                'Arn': role['Arn'],
                                'Type': 'Role',
                                'DependencyType': 'Trust Policy Organization Reference'
                            }
                            self.iam_dependencies['roles'].append(role_info)
                            dependency_count += 1
                            logger.debug(f"Found organization dependency in role: {role['RoleName']}")
                            
                    except ClientError as e:
                        logger.warning(f"Could not check role {role['RoleName']}: {e.response['Error']['Code']}")
                        continue
            
            logger.info(f"Checked {role_count} IAM roles, found {len(self.iam_dependencies['roles'])} with dependencies")
            logger.info(f"Total IAM dependencies found: {dependency_count}")
            
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                logger.error("Access denied analyzing IAM dependencies. Please ensure you have the necessary permissions.")
            else:
                logger.error(f"AWS API error analyzing IAM dependencies: {error_code} - {e.response['Error']['Message']}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error analyzing IAM dependencies: {e}")
            return False
    
    def _check_organization_dependency(self, policy_document):
        """Check if a policy document contains organization dependencies"""
        try:
            # Convert policy document to string for searching
            if isinstance(policy_document, dict):
                policy_str = json.dumps(policy_document)
            else:
                policy_str = str(policy_document)
            
            # Check for organization ID reference
            if f'"{self.organization_id}"' in policy_str:
                return True
            
            # Check for aws:PrincipalOrgID condition
            if isinstance(policy_document, dict):
                return self._check_principal_org_id(policy_document)
            
            return False
            
        except Exception as e:
            logger.debug(f"Error checking organization dependency: {e}")
            return False
    
    def _check_principal_org_id(self, policy_document):
        """Check for aws:PrincipalOrgID condition in policy document"""
        try:
            if 'Statement' in policy_document:
                statements = policy_document['Statement']
                if not isinstance(statements, list):
                    statements = [statements]
                
                for statement in statements:
                    if 'Condition' in statement:
                        condition = statement['Condition']
                        
                        # Check various condition operators
                        for operator in ['StringEquals', 'StringLike', 'ForAllValues:StringEquals']:
                            if operator in condition:
                                if 'aws:PrincipalOrgID' in condition[operator]:
                                    org_id_value = condition[operator]['aws:PrincipalOrgID']
                                    if org_id_value == self.organization_id:
                                        return True
            
            return False
            
        except Exception as e:
            logger.debug(f"Error checking PrincipalOrgID: {e}")
            return False
    
    def generate_console_report(self):
        """Generate a comprehensive console report"""
        print("=" * 60)
        print("AWS ORGANIZATION ANALYSIS REPORT")
        print("=" * 60)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"Organization ID: {self.organization_id}")
        print("=" * 60)
        
        # Organization Summary
        print("\n=== ORGANIZATION SUMMARY ===")
        print(f"Organization ID: {self.organization_info.get('Id', 'Unknown')}")
        print(f"Feature Set: {self.organization_info.get('FeatureSet', 'Unknown')}")
        print(f"Master Account ID: {self.organization_info.get('MasterAccountId', 'Unknown')}")
        print(f"Master Account Email: {self.organization_info.get('MasterAccountEmail', 'Unknown')}")
        
        # Accounts
        print(f"\n=== ORGANIZATION ACCOUNTS ({len(self.accounts)}) ===")
        if self.accounts:
            for account in self.accounts:
                print(f"Account Name: {account['Name']}")
                print(f"Account ID: {account['Id']}")
                print(f"Email: {account['Email']}")
                print(f"Status: {account['Status']}")
                print(f"Joined Method: {account['JoinedMethod']}")
                print("---")
        else:
            print("No accounts found")
        
        # Enabled Services
        print(f"\n=== ENABLED SERVICES ({len(self.enabled_services)}) ===")
        if self.enabled_services:
            for service in self.enabled_services:
                print(f"Service: {service['ServicePrincipal']}")
                if service['DateEnabled'] != 'Unknown':
                    print(f"Date Enabled: {service['DateEnabled']}")
                print("---")
        else:
            print("No enabled services found")
        
        # Delegated Administrators
        print(f"\n=== DELEGATED ADMINISTRATORS ({len(self.delegated_administrators)}) ===")
        if self.delegated_administrators:
            for admin in self.delegated_administrators:
                print(f"Account Name: {admin['Name']}")
                print(f"Account ID: {admin['Id']}")
                print(f"Email: {admin['Email']}")
                print(f"Delegated Services ({len(admin['DelegatedServices'])}):")
                for service in admin['DelegatedServices']:
                    print(f"  - {service['ServicePrincipal']} (Enabled: {service['DelegationEnabledDate']})")
                print("---")
        else:
            print("No delegated administrators found")
        
        # Policy Types
        print(f"\n=== ENABLED POLICY TYPES ({len(self.enabled_policy_types)}) ===")
        if self.enabled_policy_types:
            for policy_type in self.enabled_policy_types:
                print(f"Policy Type: {policy_type['Type']}")
                print(f"Status: {policy_type['Status']}")
                print("---")
        else:
            print("No enabled policy types found")
        
        # IAM Dependencies
        total_dependencies = len(self.iam_dependencies['policies']) + len(self.iam_dependencies['roles'])
        print(f"\n=== IAM DEPENDENCIES ON CURRENT ORGANIZATION ({total_dependencies}) ===")
        
        if self.iam_dependencies['policies']:
            print(f"\nIAM Policies with Dependencies ({len(self.iam_dependencies['policies'])}):")
            for policy in self.iam_dependencies['policies']:
                print(f"  - {policy['Name']} (ARN: {policy['Arn']})")
                print(f"    Dependency Type: {policy['DependencyType']}")
        
        if self.iam_dependencies['roles']:
            print(f"\nIAM Roles with Dependencies ({len(self.iam_dependencies['roles'])}):")
            for role in self.iam_dependencies['roles']:
                print(f"  - {role['Name']} (ARN: {role['Arn']})")
                print(f"    Dependency Type: {role['DependencyType']}")
        
        if total_dependencies == 0:
            print("No IAM resources with dependencies on the current organization were found")
        
        # Migration Planning Summary
        print(f"\n=== MIGRATION PLANNING SUMMARY ===")
        print(f"Total Accounts to Migrate: {len(self.accounts)}")
        print(f"Services to Re-enable: {len(self.enabled_services)}")
        print(f"Delegated Admin Relationships to Recreate: {len(self.delegated_administrators)}")
        print(f"Policy Types to Re-enable: {len(self.enabled_policy_types)}")
        print(f"IAM Resources Requiring Updates: {total_dependencies}")
        
        if total_dependencies > 0:
            print("\n⚠️  WARNING: IAM dependencies found!")
            print("   These resources will need to be updated with the new organization ID")
            print("   after migration to prevent access issues.")
        
        print("=" * 60)
    
    def export_to_json(self, output_file='org-analysis.json'):
        """Export the analysis data to JSON for automation and further processing"""
        try:
            logger.info(f"Exporting analysis data to: {output_file}")
            
            export_data = {
                'analysis_metadata': {
                    'generated_timestamp': datetime.now().isoformat(),
                    'organization_id': self.organization_id,
                    'tool_version': '2.0'
                },
                'organization_info': self.organization_info,
                'accounts': self.accounts,
                'enabled_services': self.enabled_services,
                'delegated_administrators': self.delegated_administrators,
                'enabled_policy_types': self.enabled_policy_types,
                'iam_dependencies': self.iam_dependencies,
                'migration_summary': {
                    'total_accounts': len(self.accounts),
                    'total_enabled_services': len(self.enabled_services),
                    'total_delegated_administrators': len(self.delegated_administrators),
                    'total_enabled_policy_types': len(self.enabled_policy_types),
                    'total_iam_dependencies': len(self.iam_dependencies['policies']) + len(self.iam_dependencies['roles']),
                    'requires_iam_updates': len(self.iam_dependencies['policies']) + len(self.iam_dependencies['roles']) > 0
                }
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Successfully exported analysis data to {output_file}")
            print(f"\nAnalysis data exported to: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export analysis data: {e}")
            return False
    
    def run_complete_analysis(self):
        """Run the complete organization analysis workflow"""
        try:
            logger.info("Starting complete AWS Organization analysis")
            
            # Initialize clients
            if not self.initialize_clients():
                return False
            
            # Get organization info
            if not self.get_organization_info():
                return False
            
            # Gather all organization data
            success = True
            success &= self.get_organization_accounts()
            success &= self.get_enabled_services()
            success &= self.get_delegated_administrators()
            success &= self.get_enabled_policy_types()
            success &= self.analyze_iam_dependencies()
            
            if not success:
                logger.warning("Some data collection operations failed, but continuing with available data")
            
            # Generate reports
            self.generate_console_report()
            self.export_to_json()
            
            logger.info("Organization analysis completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Unexpected error during analysis: {e}")
            return False

def main():
    """Main function to orchestrate the AWS Organization analysis"""
    try:
        logger.info("Starting AWS Organization analysis for migration planning")
        
        analyzer = OrganizationAnalyzer()
        
        if analyzer.run_complete_analysis():
            logger.info("Analysis completed successfully")
            print("\nDone")
        else:
            logger.error("Analysis completed with errors")
            sys.exit(1)
        
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()
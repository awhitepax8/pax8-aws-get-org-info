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
        # Phase 1: Organizational Structure data
        self.organizational_units = {}  # ou_id -> ou_info
        self.ou_hierarchy = {}  # parent_id -> [child_ou_ids]
        self.account_ou_assignments = {}  # account_id -> ou_id
        self.ou_policies = {}  # ou_id -> [attached_policies]
        self.roots = []  # organization roots
        
        # Phase 2: Service Control Policies data
        self.service_control_policies = {}  # policy_id -> policy_details
        self.scp_attachments = {}  # target_id -> [attached_scp_ids]
        self.scp_inheritance_map = {}  # account_id -> [inherited_scp_ids_with_sources]
        self.custom_policies = {}  # policy_id -> policy_content (non-AWS managed)
        
        # Phase 3: Service Configurations data
        self.service_configurations = {}  # service_principal -> configuration_details
        self.trusted_access_settings = {}  # service_principal -> trusted_access_info
        self.service_linked_roles = {}  # service_principal -> [service_linked_roles]
        self.cross_service_dependencies = {}  # service -> [dependent_services]
        self.service_integration_details = {}  # service -> integration_configuration
        
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
    
    def get_organization_roots(self):
        """Retrieve organization roots - the starting point of the OU hierarchy"""
        try:
            logger.info("Retrieving organization roots")
            
            response = self.org_client.list_roots()
            root_count = 0
            
            for root in response.get('Roots', []):
                root_info = {
                    'Id': root['Id'],
                    'Arn': root['Arn'],
                    'Name': root['Name'],
                    'PolicyTypes': root.get('PolicyTypes', [])
                }
                self.roots.append(root_info)
                root_count += 1
                
                # Initialize hierarchy for this root
                self.ou_hierarchy[root['Id']] = []
            
            logger.info(f"Found {root_count} organization roots")
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                logger.error("Access denied retrieving organization roots. Please ensure you have the necessary permissions.")
            else:
                logger.error(f"AWS API error retrieving roots: {error_code} - {e.response['Error']['Message']}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error retrieving organization roots: {e}")
            return False
    
    def get_organizational_units(self):
        """Retrieve all organizational units and build the hierarchy"""
        try:
            logger.info("Retrieving organizational units and building hierarchy")
            
            if not self.roots:
                logger.error("No roots found. Please call get_organization_roots() first.")
                return False
            
            # Process each root
            for root in self.roots:
                root_id = root['Id']
                logger.debug(f"Processing OUs under root: {root_id}")
                
                # Get OUs directly under this root
                self._get_ous_recursive(root_id)
            
            logger.info(f"Found {len(self.organizational_units)} organizational units")
            return True
            
        except Exception as e:
            logger.error(f"Unexpected error retrieving organizational units: {e}")
            return False
    
    def _get_ous_recursive(self, parent_id):
        """Recursively retrieve OUs under a parent (root or OU)"""
        try:
            paginator = self.org_client.get_paginator('list_organizational_units_for_parent')
            
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page['OrganizationalUnits']:
                    ou_id = ou['Id']
                    
                    # Store OU information
                    ou_info = {
                        'Id': ou_id,
                        'Arn': ou['Arn'],
                        'Name': ou['Name'],
                        'ParentId': parent_id
                    }
                    self.organizational_units[ou_id] = ou_info
                    
                    # Update hierarchy
                    if parent_id not in self.ou_hierarchy:
                        self.ou_hierarchy[parent_id] = []
                    self.ou_hierarchy[parent_id].append(ou_id)
                    
                    logger.debug(f"Found OU: {ou['Name']} ({ou_id}) under parent {parent_id}")
                    
                    # Recursively get child OUs
                    self._get_ous_recursive(ou_id)
                    
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                logger.error(f"Access denied retrieving OUs for parent {parent_id}")
            else:
                logger.error(f"AWS API error retrieving OUs for parent {parent_id}: {error_code} - {e.response['Error']['Message']}")
        except Exception as e:
            logger.error(f"Unexpected error retrieving OUs for parent {parent_id}: {e}")
    
    def get_account_ou_assignments(self):
        """Map each account to its organizational unit"""
        try:
            logger.info("Mapping accounts to organizational units")
            
            if not self.accounts:
                logger.warning("No accounts found. Please call get_organization_accounts() first.")
                return True
            
            # For each account, find which OU it belongs to
            for account in self.accounts:
                account_id = account['Id']
                
                try:
                    # Get the parent (OU or root) for this account
                    response = self.org_client.list_parents(ChildId=account_id)
                    
                    if response.get('Parents'):
                        parent = response['Parents'][0]  # Accounts have only one parent
                        parent_id = parent['Id']
                        parent_type = parent['Type']
                        
                        self.account_ou_assignments[account_id] = {
                            'ParentId': parent_id,
                            'ParentType': parent_type,
                            'AccountName': account['Name']
                        }
                        
                        logger.debug(f"Account {account['Name']} ({account_id}) is in {parent_type}: {parent_id}")
                    
                except ClientError as e:
                    logger.warning(f"Could not get parent for account {account_id}: {e.response['Error']['Code']}")
                    continue
            
            logger.info(f"Mapped {len(self.account_ou_assignments)} accounts to their organizational units")
            return True
            
        except Exception as e:
            logger.error(f"Unexpected error mapping accounts to OUs: {e}")
            return False
    
    def get_ou_policies(self):
        """Retrieve policies attached to each organizational unit"""
        try:
            logger.info("Retrieving policies attached to organizational units")
            
            # Check policies for roots
            for root in self.roots:
                root_id = root['Id']
                self._get_policies_for_target(root_id, 'ROOT')
            
            # Check policies for each OU
            for ou_id in self.organizational_units:
                self._get_policies_for_target(ou_id, 'ORGANIZATIONAL_UNIT')
            
            total_attachments = sum(len(policies) for policies in self.ou_policies.values())
            logger.info(f"Found {total_attachments} policy attachments across all OUs and roots")
            return True
            
        except Exception as e:
            logger.error(f"Unexpected error retrieving OU policies: {e}")
            return False
    
    def _get_policies_for_target(self, target_id, target_type):
        """Get all policies attached to a specific target (root or OU)"""
        try:
            # Get policies for each policy type
            policy_types = ['SERVICE_CONTROL_POLICY', 'TAG_POLICY', 'BACKUP_POLICY', 'AISERVICES_OPT_OUT_POLICY']
            
            target_policies = []
            
            for policy_type in policy_types:
                try:
                    paginator = self.org_client.get_paginator('list_policies_for_target')
                    
                    for page in paginator.paginate(TargetId=target_id, Filter=policy_type):
                        for policy in page['Policies']:
                            policy_info = {
                                'Id': policy['Id'],
                                'Arn': policy['Arn'],
                                'Name': policy['Name'],
                                'Description': policy.get('Description', ''),
                                'Type': policy['Type'],
                                'AwsManaged': policy.get('AwsManaged', False)
                            }
                            target_policies.append(policy_info)
                            
                            logger.debug(f"Found {policy_type} policy '{policy['Name']}' attached to {target_type} {target_id}")
                
                except ClientError as e:
                    # Some policy types might not be enabled
                    if e.response['Error']['Code'] not in ['PolicyTypeNotEnabledException', 'InvalidParameterException']:
                        logger.warning(f"Error getting {policy_type} policies for {target_id}: {e.response['Error']['Code']}")
            
            if target_policies:
                self.ou_policies[target_id] = target_policies
            
        except Exception as e:
            logger.error(f"Unexpected error getting policies for {target_id}: {e}")
    
    def generate_ou_hierarchy_report(self):
        """Generate a visual representation of the OU hierarchy"""
        print(f"\n=== ORGANIZATIONAL UNIT HIERARCHY ===")
        
        if not self.roots:
            print("No organizational structure found")
            return
        
        for root in self.roots:
            root_id = root['Id']
            print(f"\nRoot: {root['Name']} ({root_id})")
            
            # Show accounts directly under root
            root_accounts = [assignment for acc_id, assignment in self.account_ou_assignments.items() 
                           if assignment['ParentId'] == root_id]
            if root_accounts:
                print("  Accounts:")
                for assignment in root_accounts:
                    print(f"    - {assignment['AccountName']}")
            
            # Show policies attached to root
            if root_id in self.ou_policies:
                print("  Attached Policies:")
                for policy in self.ou_policies[root_id]:
                    print(f"    - {policy['Name']} ({policy['Type']})")
            
            # Recursively show OU hierarchy
            self._print_ou_hierarchy(root_id, 1)
    
    def _print_ou_hierarchy(self, parent_id, indent_level):
        """Recursively print OU hierarchy with proper indentation"""
        if parent_id not in self.ou_hierarchy:
            return
        
        indent = "  " * indent_level
        
        for ou_id in self.ou_hierarchy[parent_id]:
            ou_info = self.organizational_units[ou_id]
            print(f"{indent}OU: {ou_info['Name']} ({ou_id})")
            
            # Show accounts in this OU
            ou_accounts = [assignment for acc_id, assignment in self.account_ou_assignments.items() 
                          if assignment['ParentId'] == ou_id]
            if ou_accounts:
                print(f"{indent}  Accounts:")
                for assignment in ou_accounts:
                    print(f"{indent}    - {assignment['AccountName']}")
            
            # Show policies attached to this OU
            if ou_id in self.ou_policies:
                print(f"{indent}  Attached Policies:")
                for policy in self.ou_policies[ou_id]:
                    print(f"{indent}    - {policy['Name']} ({policy['Type']})")
            
            # Recursively show child OUs
            self._print_ou_hierarchy(ou_id, indent_level + 1)
    
    def get_service_control_policies(self):
        """Retrieve all Service Control Policies with their full content"""
        try:
            logger.info("Retrieving Service Control Policies")
            
            # Check if SCP policy type is enabled
            scp_enabled = False
            for root in self.roots:
                for policy_type in root.get('PolicyTypes', []):
                    if policy_type.get('Type') == 'SERVICE_CONTROL_POLICY' and policy_type.get('Status') == 'ENABLED':
                        scp_enabled = True
                        break
            
            if not scp_enabled:
                logger.info("Service Control Policy type is not enabled in this organization")
                return True
            
            # Get all SCPs
            paginator = self.org_client.get_paginator('list_policies')
            policy_count = 0
            
            for page in paginator.paginate(Filter='SERVICE_CONTROL_POLICY'):
                for policy in page['Policies']:
                    policy_id = policy['Id']
                    
                    # Get detailed policy information including content
                    try:
                        policy_details = self.org_client.describe_policy(PolicyId=policy_id)
                        policy_info = policy_details['Policy']
                        
                        scp_data = {
                            'Id': policy_info['Id'],
                            'Arn': policy_info['Arn'],
                            'Name': policy_info['Name'],
                            'Description': policy_info.get('Description', ''),
                            'Type': policy_info['Type'],
                            'AwsManaged': policy_info.get('AwsManaged', False),
                            'Content': policy_info.get('Content', ''),
                            'TargetSummary': policy_info.get('PolicySummary', {}).get('TargetSummary', {}),
                            'CreatedTimestamp': str(policy_info.get('PolicySummary', {}).get('CreatedTimestamp', 'Unknown')),
                            'LastUpdatedTimestamp': str(policy_info.get('PolicySummary', {}).get('LastUpdatedTimestamp', 'Unknown'))
                        }
                        
                        self.service_control_policies[policy_id] = scp_data
                        
                        # If it's a custom policy, store the content separately for easier access
                        if not scp_data['AwsManaged']:
                            self.custom_policies[policy_id] = scp_data['Content']
                        
                        policy_count += 1
                        logger.debug(f"Retrieved SCP: {policy_info['Name']} ({'AWS Managed' if scp_data['AwsManaged'] else 'Custom'})")
                        
                    except ClientError as e:
                        logger.warning(f"Could not retrieve details for policy {policy_id}: {e.response['Error']['Code']}")
                        continue
            
            logger.info(f"Retrieved {policy_count} Service Control Policies")
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                logger.error("Access denied retrieving SCPs. Please ensure you have the necessary permissions.")
            else:
                logger.error(f"AWS API error retrieving SCPs: {error_code} - {e.response['Error']['Message']}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error retrieving SCPs: {e}")
            return False
    
    def get_scp_attachments(self):
        """Map SCP attachments to all targets (roots, OUs, accounts)"""
        try:
            logger.info("Mapping SCP attachments to targets")
            
            if not self.service_control_policies:
                logger.info("No SCPs found to map attachments for")
                return True
            
            # Get attachments for each SCP
            for policy_id, policy_info in self.service_control_policies.items():
                try:
                    paginator = self.org_client.get_paginator('list_targets_for_policy')
                    targets = []
                    
                    for page in paginator.paginate(PolicyId=policy_id):
                        for target in page['Targets']:
                            target_info = {
                                'TargetId': target['TargetId'],
                                'Arn': target['Arn'],
                                'Name': target['Name'],
                                'Type': target['Type']
                            }
                            targets.append(target_info)
                            
                            # Also track from target perspective
                            target_id = target['TargetId']
                            if target_id not in self.scp_attachments:
                                self.scp_attachments[target_id] = []
                            self.scp_attachments[target_id].append({
                                'PolicyId': policy_id,
                                'PolicyName': policy_info['Name'],
                                'PolicyType': 'SERVICE_CONTROL_POLICY',
                                'AwsManaged': policy_info['AwsManaged']
                            })
                    
                    # Update policy info with targets
                    self.service_control_policies[policy_id]['AttachedTargets'] = targets
                    
                    logger.debug(f"SCP '{policy_info['Name']}' attached to {len(targets)} targets")
                    
                except ClientError as e:
                    logger.warning(f"Could not get targets for policy {policy_id}: {e.response['Error']['Code']}")
                    continue
            
            total_attachments = sum(len(attachments) for attachments in self.scp_attachments.values())
            logger.info(f"Mapped {total_attachments} SCP attachments across all targets")
            return True
            
        except Exception as e:
            logger.error(f"Unexpected error mapping SCP attachments: {e}")
            return False
    
    def analyze_scp_inheritance(self):
        """Analyze which SCPs each account inherits through the OU hierarchy"""
        try:
            logger.info("Analyzing SCP inheritance for all accounts")
            
            if not self.accounts or not self.account_ou_assignments:
                logger.warning("Account or OU assignment data not available for inheritance analysis")
                return True
            
            for account in self.accounts:
                account_id = account['Id']
                account_name = account['Name']
                
                inherited_scps = []
                
                # Get the account's current OU assignment
                assignment = self.account_ou_assignments.get(account_id)
                if not assignment:
                    logger.debug(f"No OU assignment found for account {account_name}")
                    continue
                
                # Trace up the hierarchy to collect inherited SCPs
                current_target_id = assignment['ParentId']
                inheritance_path = []
                
                while current_target_id:
                    # Add SCPs attached to current target
                    if current_target_id in self.scp_attachments:
                        for scp_attachment in self.scp_attachments[current_target_id]:
                            inherited_scps.append({
                                'PolicyId': scp_attachment['PolicyId'],
                                'PolicyName': scp_attachment['PolicyName'],
                                'InheritedFrom': current_target_id,
                                'InheritedFromType': self._get_target_type(current_target_id),
                                'InheritedFromName': self._get_target_name(current_target_id),
                                'AwsManaged': scp_attachment['AwsManaged']
                            })
                    
                    inheritance_path.append(current_target_id)
                    
                    # Move up to parent
                    current_target_id = self._get_parent_id(current_target_id)
                    
                    # Prevent infinite loops
                    if current_target_id in inheritance_path:
                        break
                
                self.scp_inheritance_map[account_id] = {
                    'AccountName': account_name,
                    'InheritedSCPs': inherited_scps,
                    'InheritancePath': inheritance_path,
                    'TotalInheritedSCPs': len(inherited_scps)
                }
                
                logger.debug(f"Account {account_name} inherits {len(inherited_scps)} SCPs")
            
            logger.info(f"Analyzed SCP inheritance for {len(self.scp_inheritance_map)} accounts")
            return True
            
        except Exception as e:
            logger.error(f"Unexpected error analyzing SCP inheritance: {e}")
            return False
    
    def _get_target_type(self, target_id):
        """Determine the type of a target (ROOT, ORGANIZATIONAL_UNIT, or ACCOUNT)"""
        if target_id.startswith('r-'):
            return 'ROOT'
        elif target_id.startswith('ou-'):
            return 'ORGANIZATIONAL_UNIT'
        elif target_id.startswith('123456789') or len(target_id) == 12:  # Account ID pattern
            return 'ACCOUNT'
        else:
            return 'UNKNOWN'
    
    def _get_target_name(self, target_id):
        """Get the human-readable name for a target"""
        target_type = self._get_target_type(target_id)
        
        if target_type == 'ROOT':
            for root in self.roots:
                if root['Id'] == target_id:
                    return root['Name']
        elif target_type == 'ORGANIZATIONAL_UNIT':
            if target_id in self.organizational_units:
                return self.organizational_units[target_id]['Name']
        elif target_type == 'ACCOUNT':
            for account in self.accounts:
                if account['Id'] == target_id:
                    return account['Name']
        
        return f"Unknown ({target_id})"
    
    def _get_parent_id(self, target_id):
        """Get the parent ID for a given target"""
        target_type = self._get_target_type(target_id)
        
        if target_type == 'ORGANIZATIONAL_UNIT':
            if target_id in self.organizational_units:
                return self.organizational_units[target_id]['ParentId']
        elif target_type == 'ACCOUNT':
            if target_id in self.account_ou_assignments:
                return self.account_ou_assignments[target_id]['ParentId']
        
        return None
    
    def generate_scp_analysis_report(self):
        """Generate comprehensive SCP analysis report"""
        print(f"\n=== SERVICE CONTROL POLICIES ANALYSIS ===")
        
        if not self.service_control_policies:
            print("No Service Control Policies found or SCP policy type not enabled")
            return
        
        # SCP Summary
        total_scps = len(self.service_control_policies)
        aws_managed_scps = len([p for p in self.service_control_policies.values() if p['AwsManaged']])
        custom_scps = total_scps - aws_managed_scps
        
        print(f"\nSCP Summary:")
        print(f"  Total SCPs: {total_scps}")
        print(f"  AWS Managed: {aws_managed_scps}")
        print(f"  Custom SCPs: {custom_scps}")
        
        # Custom SCPs (most critical for migration)
        if custom_scps > 0:
            print(f"\n⚠️  CRITICAL: {custom_scps} Custom SCPs must be recreated in new organization!")
            print("Custom SCPs:")
            for policy_id, policy_info in self.service_control_policies.items():
                if not policy_info['AwsManaged']:
                    targets = policy_info.get('AttachedTargets', [])
                    print(f"  - {policy_info['Name']} (attached to {len(targets)} targets)")
                    for target in targets:
                        print(f"    └─ {target['Type']}: {target['Name']}")
        
        # AWS Managed SCPs
        if aws_managed_scps > 0:
            print(f"\nAWS Managed SCPs (can be re-attached easily):")
            for policy_id, policy_info in self.service_control_policies.items():
                if policy_info['AwsManaged']:
                    targets = policy_info.get('AttachedTargets', [])
                    print(f"  - {policy_info['Name']} (attached to {len(targets)} targets)")
        
        # SCP Inheritance Analysis
        if self.scp_inheritance_map:
            print(f"\n=== SCP INHERITANCE ANALYSIS ===")
            accounts_with_scps = len([acc for acc in self.scp_inheritance_map.values() if acc['TotalInheritedSCPs'] > 0])
            print(f"Accounts with inherited SCPs: {accounts_with_scps}/{len(self.scp_inheritance_map)}")
            
            # Show accounts with most complex inheritance
            complex_accounts = sorted(
                self.scp_inheritance_map.values(), 
                key=lambda x: x['TotalInheritedSCPs'], 
                reverse=True
            )[:5]  # Top 5 most complex
            
            if complex_accounts and complex_accounts[0]['TotalInheritedSCPs'] > 0:
                print(f"\nAccounts with most SCP inheritance:")
                for account_info in complex_accounts:
                    if account_info['TotalInheritedSCPs'] > 0:
                        print(f"  - {account_info['AccountName']}: {account_info['TotalInheritedSCPs']} inherited SCPs")
        
        print("=" * 60)
    
    def analyze_service_configurations(self):
        """Analyze detailed configurations for enabled services"""
        try:
            logger.info("Analyzing service configurations and integration details")
            
            if not self.enabled_services:
                logger.info("No enabled services found to analyze configurations for")
                return True
            
            # Analyze each enabled service
            for service_info in self.enabled_services:
                service_principal = service_info['ServicePrincipal']
                logger.debug(f"Analyzing configuration for service: {service_principal}")
                
                # Get trusted access details
                self._analyze_trusted_access(service_principal)
                
                # Get service-specific configurations
                self._analyze_service_specific_config(service_principal)
                
                # Analyze service dependencies
                self._analyze_service_dependencies(service_principal)
            
            logger.info(f"Analyzed configurations for {len(self.enabled_services)} enabled services")
            return True
            
        except Exception as e:
            logger.error(f"Unexpected error analyzing service configurations: {e}")
            return False
    
    def _analyze_trusted_access(self, service_principal):
        """Analyze trusted access configuration for a service"""
        try:
            # Get trusted access status and details
            trusted_access_info = {
                'ServicePrincipal': service_principal,
                'TrustedAccessEnabled': True,  # If it's in enabled_services, trusted access is enabled
                'RequiresRecreation': True,    # All trusted access needs to be re-enabled
                'ConfigurationComplexity': self._assess_service_complexity(service_principal)
            }
            
            # Add service-specific trusted access details
            if service_principal == 'sso.amazonaws.com':
                trusted_access_info.update({
                    'ServiceName': 'AWS Single Sign-On',
                    'CriticalForMigration': True,
                    'RequiresSpecialHandling': True,
                    'MigrationNotes': 'SSO service integration requires careful coordination during migration'
                })
            elif service_principal == 'guardduty.amazonaws.com':
                trusted_access_info.update({
                    'ServiceName': 'Amazon GuardDuty',
                    'CriticalForMigration': True,
                    'RequiresSpecialHandling': True,
                    'MigrationNotes': 'GuardDuty delegated admin and detector configurations need preservation'
                })
            elif service_principal == 'securityhub.amazonaws.com':
                trusted_access_info.update({
                    'ServiceName': 'AWS Security Hub',
                    'CriticalForMigration': True,
                    'RequiresSpecialHandling': True,
                    'MigrationNotes': 'Security Hub aggregation and standards subscriptions need recreation'
                })
            elif service_principal == 'config.amazonaws.com':
                trusted_access_info.update({
                    'ServiceName': 'AWS Config',
                    'CriticalForMigration': True,
                    'RequiresSpecialHandling': True,
                    'MigrationNotes': 'Config aggregators and organization rules need recreation'
                })
            elif service_principal == 'cloudtrail.amazonaws.com':
                trusted_access_info.update({
                    'ServiceName': 'AWS CloudTrail',
                    'CriticalForMigration': True,
                    'RequiresSpecialHandling': True,
                    'MigrationNotes': 'Organization trails need to be recreated in new organization'
                })
            elif service_principal == 'ram.amazonaws.com':
                trusted_access_info.update({
                    'ServiceName': 'AWS Resource Access Manager',
                    'CriticalForMigration': True,
                    'RequiresSpecialHandling': True,
                    'MigrationNotes': 'Resource shares need to be recreated with new organization accounts'
                })
            else:
                # Generic service
                service_name = service_principal.split('.')[0].upper()
                trusted_access_info.update({
                    'ServiceName': f'AWS {service_name}',
                    'CriticalForMigration': False,
                    'RequiresSpecialHandling': False,
                    'MigrationNotes': f'{service_name} trusted access needs to be re-enabled in new organization'
                })
            
            self.trusted_access_settings[service_principal] = trusted_access_info
            
        except Exception as e:
            logger.warning(f"Could not analyze trusted access for {service_principal}: {e}")
    
    def _analyze_service_specific_config(self, service_principal):
        """Analyze service-specific configuration details"""
        try:
            config_details = {
                'ServicePrincipal': service_principal,
                'ConfigurationItems': [],
                'MigrationComplexity': 'Medium',
                'RequiresManualRecreation': True
            }
            
            # Service-specific configuration analysis
            if service_principal == 'sso.amazonaws.com':
                config_details.update({
                    'ConfigurationItems': [
                        'Permission sets and their policies',
                        'User and group assignments',
                        'Application assignments',
                        'Identity source configuration',
                        'Attribute mappings'
                    ],
                    'MigrationComplexity': 'High',
                    'SpecialConsiderations': [
                        'Identity Center instance cannot be migrated - must be recreated',
                        'All permission sets must be recreated with exact policies',
                        'User/group assignments must be recreated',
                        'Application integrations need reconfiguration'
                    ]
                })
            
            elif service_principal == 'guardduty.amazonaws.com':
                config_details.update({
                    'ConfigurationItems': [
                        'Delegated administrator account',
                        'Member account invitations',
                        'Detector configurations per region',
                        'Finding publishing settings',
                        'Threat intelligence sets',
                        'IP sets and threat lists'
                    ],
                    'MigrationComplexity': 'High',
                    'SpecialConsiderations': [
                        'Delegated admin must be set up first',
                        'All member accounts need re-invitation',
                        'Detector settings need recreation per region',
                        'Custom threat intelligence needs migration'
                    ]
                })
            
            elif service_principal == 'securityhub.amazonaws.com':
                config_details.update({
                    'ConfigurationItems': [
                        'Delegated administrator account',
                        'Security standards subscriptions',
                        'Custom insights and findings',
                        'Finding aggregation settings',
                        'Integration configurations'
                    ],
                    'MigrationComplexity': 'High',
                    'SpecialConsiderations': [
                        'Delegated admin setup required first',
                        'Security standards need re-subscription',
                        'Custom insights and findings will be lost',
                        'Third-party integrations need reconfiguration'
                    ]
                })
            
            elif service_principal == 'config.amazonaws.com':
                config_details.update({
                    'ConfigurationItems': [
                        'Configuration aggregators',
                        'Organization config rules',
                        'Conformance packs',
                        'Remediation configurations',
                        'Delivery channels'
                    ],
                    'MigrationComplexity': 'High',
                    'SpecialConsiderations': [
                        'Organization aggregators need recreation',
                        'Config rules need redeployment',
                        'Conformance packs need reassignment',
                        'Historical data will be lost'
                    ]
                })
            
            elif service_principal == 'cloudtrail.amazonaws.com':
                config_details.update({
                    'ConfigurationItems': [
                        'Organization trails',
                        'Event data stores',
                        'Insights selectors',
                        'S3 bucket policies',
                        'CloudWatch Logs integration'
                    ],
                    'MigrationComplexity': 'Medium',
                    'SpecialConsiderations': [
                        'Organization trails need recreation',
                        'S3 bucket permissions need updating',
                        'Event history will be preserved in original buckets',
                        'Insights configurations need recreation'
                    ]
                })
            
            elif service_principal == 'ram.amazonaws.com':
                config_details.update({
                    'ConfigurationItems': [
                        'Resource shares',
                        'Resource associations',
                        'Principal associations',
                        'Sharing policies'
                    ],
                    'MigrationComplexity': 'Medium',
                    'SpecialConsiderations': [
                        'All resource shares need recreation',
                        'Principal associations need updating with new account IDs',
                        'Resource permissions need validation',
                        'Cross-account access may be temporarily disrupted'
                    ]
                })
            
            else:
                # Generic service configuration
                service_name = service_principal.split('.')[0]
                config_details.update({
                    'ConfigurationItems': [
                        f'{service_name.title()} organization-level settings',
                        'Delegated administrator configurations',
                        'Service-specific policies and rules'
                    ],
                    'MigrationComplexity': 'Medium',
                    'SpecialConsiderations': [
                        f'{service_name.title()} trusted access needs re-enabling',
                        'Service configurations may need manual recreation',
                        'Check service documentation for migration specifics'
                    ]
                })
            
            self.service_configurations[service_principal] = config_details
            
        except Exception as e:
            logger.warning(f"Could not analyze service configuration for {service_principal}: {e}")
    
    def _analyze_service_dependencies(self, service_principal):
        """Analyze dependencies between services"""
        try:
            dependencies = []
            
            # Define known service dependencies
            service_dependencies = {
                'sso.amazonaws.com': ['iam.amazonaws.com'],
                'guardduty.amazonaws.com': ['iam.amazonaws.com', 'securityhub.amazonaws.com'],
                'securityhub.amazonaws.com': ['iam.amazonaws.com', 'config.amazonaws.com'],
                'config.amazonaws.com': ['iam.amazonaws.com', 'cloudtrail.amazonaws.com'],
                'cloudtrail.amazonaws.com': ['iam.amazonaws.com', 's3.amazonaws.com'],
                'ram.amazonaws.com': ['iam.amazonaws.com'],
                'access-analyzer.amazonaws.com': ['iam.amazonaws.com'],
                'compute-optimizer.amazonaws.com': ['iam.amazonaws.com'],
                'cost-optimization-hub.amazonaws.com': ['iam.amazonaws.com']
            }
            
            if service_principal in service_dependencies:
                dependencies = service_dependencies[service_principal]
            
            self.cross_service_dependencies[service_principal] = dependencies
            
        except Exception as e:
            logger.warning(f"Could not analyze dependencies for {service_principal}: {e}")
    
    def _assess_service_complexity(self, service_principal):
        """Assess the migration complexity for a service"""
        high_complexity_services = [
            'sso.amazonaws.com',
            'guardduty.amazonaws.com', 
            'securityhub.amazonaws.com',
            'config.amazonaws.com'
        ]
        
        medium_complexity_services = [
            'cloudtrail.amazonaws.com',
            'ram.amazonaws.com',
            'access-analyzer.amazonaws.com'
        ]
        
        if service_principal in high_complexity_services:
            return 'High'
        elif service_principal in medium_complexity_services:
            return 'Medium'
        else:
            return 'Low'
    
    def generate_service_configuration_report(self):
        """Generate comprehensive service configuration analysis report"""
        print(f"\n=== SERVICE CONFIGURATION ANALYSIS ===")
        
        if not self.service_configurations:
            print("No service configurations analyzed")
            return
        
        # Service complexity summary
        high_complexity = [s for s, config in self.service_configurations.items() 
                          if config.get('MigrationComplexity') == 'High']
        medium_complexity = [s for s, config in self.service_configurations.items() 
                            if config.get('MigrationComplexity') == 'Medium']
        low_complexity = [s for s, config in self.service_configurations.items() 
                         if config.get('MigrationComplexity') == 'Low']
        
        print(f"\nMigration Complexity Summary:")
        print(f"  High Complexity Services: {len(high_complexity)}")
        print(f"  Medium Complexity Services: {len(medium_complexity)}")
        print(f"  Low Complexity Services: {len(low_complexity)}")
        
        # High complexity services (most critical)
        if high_complexity:
            print(f"\n⚠️  HIGH COMPLEXITY SERVICES (Require Special Attention):")
            for service_principal in high_complexity:
                config = self.service_configurations[service_principal]
                trusted_access = self.trusted_access_settings.get(service_principal, {})
                
                print(f"\n  🔴 {trusted_access.get('ServiceName', service_principal)}")
                print(f"     Service Principal: {service_principal}")
                print(f"     Configuration Items:")
                for item in config.get('ConfigurationItems', []):
                    print(f"       - {item}")
                
                print(f"     Special Considerations:")
                for consideration in config.get('SpecialConsiderations', []):
                    print(f"       ⚠️  {consideration}")
        
        # Medium complexity services
        if medium_complexity:
            print(f"\n🟡 MEDIUM COMPLEXITY SERVICES:")
            for service_principal in medium_complexity:
                config = self.service_configurations[service_principal]
                trusted_access = self.trusted_access_settings.get(service_principal, {})
                print(f"  - {trusted_access.get('ServiceName', service_principal)}")
                print(f"    Items to recreate: {len(config.get('ConfigurationItems', []))}")
        
        # Service dependencies
        if self.cross_service_dependencies:
            print(f"\n=== SERVICE DEPENDENCIES ===")
            print("Services with dependencies (must be enabled in order):")
            for service, deps in self.cross_service_dependencies.items():
                if deps:
                    service_name = self.trusted_access_settings.get(service, {}).get('ServiceName', service)
                    print(f"  {service_name} depends on:")
                    for dep in deps:
                        dep_name = dep.split('.')[0].upper()
                        print(f"    - {dep_name}")
        
        print("=" * 60)
    
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
        
        # Organizational Structure Summary
        print(f"\n=== ORGANIZATIONAL STRUCTURE SUMMARY ===")
        print(f"Organization Roots: {len(self.roots)}")
        print(f"Organizational Units: {len(self.organizational_units)}")
        print(f"OU Policy Attachments: {sum(len(policies) for policies in self.ou_policies.values())}")
        accounts_in_root = len([a for a in self.account_ou_assignments.values() if a.get('ParentType') == 'ROOT'])
        accounts_in_ous = len([a for a in self.account_ou_assignments.values() if a.get('ParentType') == 'ORGANIZATIONAL_UNIT'])
        print(f"Accounts in Root: {accounts_in_root}")
        print(f"Accounts in OUs: {accounts_in_ous}")
        
        if self.organizational_units:
            print(f"\n⚠️  CRITICAL: Complete OU structure must be recreated in new organization!")
            print("   - Create all OUs with exact same names and hierarchy")
            print("   - Attach all policies to corresponding OUs")
            print("   - Move accounts to correct OUs after migration")
        
        if total_dependencies > 0:
            print(f"\n⚠️  WARNING: IAM dependencies found!")
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
                    'tool_version': '2.3',
                    'includes_organizational_structure': True,
                    'includes_scp_analysis': True,
                    'includes_service_configuration_analysis': True
                },
                'organization_info': self.organization_info,
                'accounts': self.accounts,
                'enabled_services': self.enabled_services,
                'delegated_administrators': self.delegated_administrators,
                'enabled_policy_types': self.enabled_policy_types,
                'iam_dependencies': self.iam_dependencies,
                # Phase 1: Organizational Structure
                'organizational_structure': {
                    'roots': self.roots,
                    'organizational_units': self.organizational_units,
                    'ou_hierarchy': self.ou_hierarchy,
                    'account_ou_assignments': self.account_ou_assignments,
                    'ou_policies': self.ou_policies
                },
                # Phase 2: Service Control Policies
                'service_control_policies': {
                    'policies': self.service_control_policies,
                    'attachments': self.scp_attachments,
                    'inheritance_map': self.scp_inheritance_map,
                    'custom_policies': self.custom_policies
                },
                # Phase 3: Service Configurations
                'service_configurations': {
                    'configurations': self.service_configurations,
                    'trusted_access_settings': self.trusted_access_settings,
                    'service_dependencies': self.cross_service_dependencies
                },
                'migration_summary': {
                    'total_accounts': len(self.accounts),
                    'total_enabled_services': len(self.enabled_services),
                    'total_delegated_administrators': len(self.delegated_administrators),
                    'total_enabled_policy_types': len(self.enabled_policy_types),
                    'total_iam_dependencies': len(self.iam_dependencies['policies']) + len(self.iam_dependencies['roles']),
                    'requires_iam_updates': len(self.iam_dependencies['policies']) + len(self.iam_dependencies['roles']) > 0,
                    # Organizational structure summary
                    'total_organizational_units': len(self.organizational_units),
                    'total_roots': len(self.roots),
                    'total_ou_policy_attachments': sum(len(policies) for policies in self.ou_policies.values()),
                    'accounts_in_root': len([a for a in self.account_ou_assignments.values() if a.get('ParentType') == 'ROOT']),
                    'accounts_in_ous': len([a for a in self.account_ou_assignments.values() if a.get('ParentType') == 'ORGANIZATIONAL_UNIT']),
                    # SCP analysis summary
                    'total_service_control_policies': len(self.service_control_policies),
                    'total_custom_scps': len([p for p in self.service_control_policies.values() if not p.get('AwsManaged', True)]),
                    'total_aws_managed_scps': len([p for p in self.service_control_policies.values() if p.get('AwsManaged', False)]),
                    'total_scp_attachments': sum(len(attachments) for attachments in self.scp_attachments.values()),
                    'accounts_with_inherited_scps': len([acc for acc in self.scp_inheritance_map.values() if acc.get('TotalInheritedSCPs', 0) > 0]),
                    # Service configuration summary
                    'total_service_configurations_analyzed': len(self.service_configurations),
                    'high_complexity_services': len([s for s, config in self.service_configurations.items() if config.get('MigrationComplexity') == 'High']),
                    'medium_complexity_services': len([s for s, config in self.service_configurations.items() if config.get('MigrationComplexity') == 'Medium']),
                    'low_complexity_services': len([s for s, config in self.service_configurations.items() if config.get('MigrationComplexity') == 'Low']),
                    'services_requiring_special_handling': len([s for s, settings in self.trusted_access_settings.items() if settings.get('RequiresSpecialHandling', False)])
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
            
            # Phase 1: Organizational Structure Analysis
            logger.info("Starting organizational structure analysis")
            success &= self.get_organization_roots()
            success &= self.get_organizational_units()
            success &= self.get_account_ou_assignments()
            success &= self.get_ou_policies()
            
            # Phase 2: Service Control Policies Analysis
            logger.info("Starting Service Control Policies analysis")
            success &= self.get_service_control_policies()
            success &= self.get_scp_attachments()
            success &= self.analyze_scp_inheritance()
            
            # Phase 3: Service Configuration Analysis
            logger.info("Starting service configuration analysis")
            success &= self.analyze_service_configurations()
            
            # IAM dependency analysis
            success &= self.analyze_iam_dependencies()
            
            if not success:
                logger.warning("Some data collection operations failed, but continuing with available data")
            
            # Generate reports
            self.generate_console_report()
            self.generate_ou_hierarchy_report()
            self.generate_scp_analysis_report()
            self.generate_service_configuration_report()
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
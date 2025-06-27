import boto3
from botocore.exceptions import ClientError

def get_organization_iam_dependencies(org_client, iam_client, organization_id):
    """
    Check for any IAM policies and roles that have a dependency on the current AWS Organization
    """
    try:
        found_dependencies = False
        
        # Check IAM policies
        print("Checking IAM Policies:")
        paginator = iam_client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local', OnlyAttached=False):
            for policy in page['Policies']:
                if not policy['IsAttachable']:
                    continue
                print(f"- Checking policy: {policy['PolicyName']}")

                # Check if the policy has a dependency on the current organization
                try:
                    policy_version = iam_client.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])
                    if f'"{organization_id}"' in policy_version['PolicyVersion']['Document']:
                        print(f"  IAM Policy: {policy['PolicyName']} (ARN: {policy['Arn']}) has a dependency on the current organization")
                        found_dependencies = True
                except ClientError as e:
                    print(f"  Error checking policy {policy['PolicyName']}: {e}")
        
        # Check IAM roles
        print("\nChecking IAM Roles:")
        paginator = iam_client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                print(f"- Checking role: {role['RoleName']}")
                
                # Check if the role's trust policy has a dependency on the current organization
                try:
                    role_response = iam_client.get_role(RoleName=role['RoleName'])
                    trust_policy = role_response['Role']['AssumeRolePolicyDocument']
                    if isinstance(trust_policy, str):
                        if f'"{organization_id}"' in trust_policy:
                            print(f"  IAM Role: {role['RoleName']} (ARN: {role['Arn']}) has a dependency on the current organization")
                            found_dependencies = True
                    elif isinstance(trust_policy, dict):
                        if 'Statement' in trust_policy and 'Condition' in trust_policy['Statement'][0]:
                            if 'aws:PrincipalOrgID' in trust_policy['Statement'][0]['Condition']['StringEquals']:
                                if trust_policy['Statement'][0]['Condition']['StringEquals']['aws:PrincipalOrgID'] == organization_id:
                                    print(f"  IAM Role: {role['RoleName']} (ARN: {role['Arn']}) has a dependency on the current organization")
                                    found_dependencies = True
                except ClientError as e:
                    print(f"  Error checking role {role['RoleName']}: {e}")
        
        if not found_dependencies:
            print("No IAM policies or roles found with a dependency on the current organization")
        return found_dependencies
    except ClientError as e:
        print(f"Error getting IAM policies and roles: {e}")
        raise

def get_organization_info():
    """
    Retrieve information about AWS Organization services, accounts, delegated administrators, and enabled policy types
    """
    try:
        # Create AWS Organizations client
        org_client = boto3.client('organizations')
        
        # Create IAM client
        iam_client = boto3.client('iam')

        # Get the current organization ID
        try:
            response = org_client.describe_organization()
            organization_id = response['Organization']['Id']
        except ClientError as e:
            if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
                print("This AWS account is not part of an AWS Organization.")
                return
            else:
                print(f"Error: {e}")
                raise

        print("=== Organization Accounts ===")
        print()
        # List accounts
        paginator = org_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            for account in page['Accounts']:
                print(f"Account Name: {account['Name']}")
                print(f"Account ID: {account['Id']}")
                print(f"Email: {account['Email']}")
                print(f"Status: {account['Status']}")
                print("---")
        print()
        print()
        
        print("=== Enabled Services ===")
        print()
        # List enabled services
        enabled_services = []
        paginator = org_client.get_paginator('list_aws_service_access_for_organization')
        for page in paginator.paginate():
            for service in page['EnabledServicePrincipals']:
                enabled_services.append(service['ServicePrincipal'])
        if enabled_services:
            for service in enabled_services:
                print(f"Service Name: {service}")
        else:
            print("None")
        print()
        print()
        
        print("=== Delegated Administrators ===")
        print()
        # List delegated administrator accounts
        delegated_admins = []
        try:
            paginator = org_client.get_paginator('list_delegated_services_for_account')
            delegated_admins = org_client.list_delegated_administrators()
            
            for admin in delegated_admins['DelegatedAdministrators']:
                print(f"Delegated Admin Account ID: {admin['Id']}")
                print(f"Account Name: {admin['Name']}")
                print(f"Email: {admin['Email']}")
                print("Delegated Services:")
                
                try:
                    for page in paginator.paginate(AccountId=admin['Id']):
                        for service in page['DelegatedServices']:
                            print(f"- Service Principal: {service['ServicePrincipal']}")
                            print(f"  Delegation Enabled Date: {service['DelegationEnabledDate']}")
                except ClientError as e:
                    print(f"Error listing delegated services for account {admin['Id']}: {e}")
                print("---")
        except ClientError as e:
            print(f"Error listing delegated administrators: {e}")
        if not delegated_admins:
            print("None")
        print()
        print()
        
        print("=== Enabled Policy Types ===")
        print()
        # Get enabled policy types
        enabled_policy_types = []
        response = org_client.list_roots()
        enabled_policy_types = response['Roots'][0]['PolicyTypes']
        
        for policy_type in enabled_policy_types:
            if policy_type['Status'] == 'ENABLED':
                print(f"Policy Type: {policy_type['Type']}")
        if not enabled_policy_types:
            print("None")
        print()
        print()
        
        print("=== IAM Dependencies on Current Organization ===")
        print()
        if get_organization_iam_dependencies(org_client, iam_client, organization_id):
            print(" IAM resources with a dependency on the current organization were found.")
        else:
            print(" No IAM resources with a dependency on the current organization were found.")

    except ClientError as e:
        if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
            print("This AWS account is not part of an AWS Organization.")
        else:
            print(f"Error: {e}")
        raise

if __name__ == "__main__":
    get_organization_info()
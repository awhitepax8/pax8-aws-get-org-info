import boto3
from botocore.exceptions import ClientError

def get_organization_info():
    """
    Retrieve information about AWS Organization services, accounts, delegated administrators, and enabled policy types
    """
    try:
        # Create AWS Organizations client
        org_client = boto3.client('organizations')
        
        print()
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

    except ClientError as e:
        print(f"Error: {e}")
        raise

if __name__ == "__main__":
    get_organization_info()
# pax8-aws-get-org-info
python script to gather aws organization info to prepare for migration to pax8 org

# AWS Organization Information Retriever

This Python script retrieves information about an AWS Organization, including:

- Enabled services
- Accounts
- Delegated administrators
- Enabled policy types
- IAM policies and roles with organization dependency

## Usage

1. Open the AWS Management Console and navigate to the CloudShell.
2. Upload the Python script named list-org-info.py to the CloudShell.
3. Run the script and redirect the output to a file named org-info.txt: python list-org-info.py > org-info.txt
4. Download the "org-info.txt" file from the CloudShell.

## Prerequisites

- You must have the necessary permissions to access the AWS Organizations service and list the organization's information.

## Output

The script will generate a file named "org-info.txt" that contains the following information:

1. Organization Accounts
2. Enabled Services
3. Delegated Administrators
4. Enabled Policy Types
5. IAM policies and roles with organization dependency

If there are no enabled services, delegated administrators, or enabled policy types, the script will print "None" for the corresponding section.

## Troubleshooting

If you encounter any issues while running the script, please check the following:

- Ensure that you have the necessary permissions to access the AWS Organizations service.
- Check the CloudShell logs for any error messages or additional information that may help you troubleshoot the issue.

If you continue to experience problems, please reach out to the appropriate support channels for assistance.




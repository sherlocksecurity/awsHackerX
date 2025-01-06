import boto3
import random
import string
import json
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
import markdown2
import pdfkit

def generate_random_ami_id():
    return 'ami-' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

def get_region_from_access_key(access_key, secret_key):
    regions = boto3.session.Session().get_available_regions('sts')
    
    for region in regions:
        try:
            client = boto3.client('sts', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
            # Make a simple STS API call to verify the credentials
            client.get_caller_identity()
            return region  # Return the valid region if the credentials work
        except Exception:
            continue
    
    return None 

def list_services(region, access_key, secret_key):
    session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    available_services = session.get_available_services()
    accessible_services = []
    for service in available_services:
        try:
            client = session.client(service)
            client.meta.service_model.operation_names
            accessible_services.append(service)
        except Exception:
            continue
    return accessible_services

def perform_operation(client, operation_name):
    try:
        operation = client.meta.service_model.operation_model(operation_name)
        print(f"Executing operation: {operation_name}")

        params = {}
        for param_name, param in operation.input_shape.members.items():
            if param.required:
                value = input(f"Enter value for {param_name} ({param.documentation}): ")
                params[param_name] = value
        response = client.meta.client._make_api_call(operation_name, params)
        print(json.dumps(response, indent=2))
    except ClientError as e:
        print(f"Error executing operation: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def explore_s3(client):
    try:
        while True:
            print("\nExploring S3:")
            print("1: List buckets")
            print("2: Download a file from a bucket")
            print("0: Go back to service list")
            action_choice = int(input("Enter the number of the action you want to perform: "))
            if action_choice == 0:
                break
            elif action_choice == 1:
                buckets = client.list_buckets()
                if 'Buckets' in buckets and buckets['Buckets']:
                    for i, bucket in enumerate(buckets['Buckets']):
                        print(f"{i + 1}: {bucket['Name']}")
                else:
                    print("No S3 buckets found.")
            elif action_choice == 2:
                bucket_name = input("Enter the bucket name: ")
                objects = client.list_objects_v2(Bucket=bucket_name)
                if 'Contents' in objects:
                    for i, obj in enumerate(objects['Contents']):
                        print(f"{i + 1}: {obj['Key']} (Size: {obj['Size']} bytes)")
                    file_choice = int(input("Enter the number of the file to download: "))
                    file_key = objects['Contents'][file_choice - 1]['Key']
                    download_path = input("Enter the download path (with filename): ")
                    client.download_file(bucket_name, file_key, download_path)
                    print(f"Downloaded {file_key} to {download_path}")
                else:
                    print(f"No files found in bucket {bucket_name}.")
    except ClientError as e:
        print(f"Error with S3 service: {e}")
    except Exception as e:
        print(f"Unexpected error while exploring S3: {e}")

def explore_ec2(client):
    try:
        while True:
            print("\nExploring EC2:")
            print("1: List instances")
            print("2: Create a new EC2 instance")
            print("3: Terminate an EC2 instance")
            print("0: Go back to service list")
            action_choice = int(input("Enter the number of the action you want to perform: "))
            if action_choice == 0:
                break
            elif action_choice == 1:
                instances = client.describe_instances()
                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:
                        print(f"Instance ID: {instance['InstanceId']}, State: {instance['State']['Name']}")
            elif action_choice == 2:
                ami_id = generate_random_ami_id()  # Replace with a valid AMI ID for actual usage
                instance_type = input("Enter the instance type (e.g., t2.micro): ")
                try:
                    client.run_instances(ImageId=ami_id, InstanceType=instance_type, MinCount=1, MaxCount=1)
                    print("Instance launched successfully.")
                except client.exceptions.ClientError as e:
                    print(f"Error launching instance: {e}")
            elif action_choice == 3:
                instance_id = input("Enter the Instance ID to terminate: ")
                try:
                    client.terminate_instances(InstanceIds=[instance_id])
                    print(f"Instance {instance_id} terminated.")
                except client.exceptions.ClientError as e:
                    print(f"Error terminating instance: {e}")
    except ClientError as e:
        print(f"Error with EC2 service: {e}")
    except Exception as e:
        print(f"Unexpected error while exploring EC2: {e}")

def explore_route53(client):
    try:
        while True:
            print("\nExploring Route 53:")
            print("1: List hosted zones")
            print("2: List records in a hosted zone")
            print("0: Go back to service list")
            action_choice = int(input("Enter the number of the action you want to perform: "))
            if action_choice == 0:
                break
            elif action_choice == 1:
                zones = client.list_hosted_zones()
                for zone in zones['HostedZones']:
                    print(f"Zone ID: {zone['Id']}, Name: {zone['Name']}")
            elif action_choice == 2:
                zone_id = input("Enter the Hosted Zone ID to list records for: ")
                records = client.list_resource_record_sets(HostedZoneId=zone_id)
                for record in records['ResourceRecordSets']:
                    print(f"Name: {record['Name']}, Type: {record['Type']}, TTL: {record.get('TTL', 'N/A')}")
            else:
                print("Invalid option.")
    except ClientError as e:
        print(f"Error with Route 53 service: {e}")
    except Exception as e:
        print(f"Unexpected error while exploring Route 53: {e}")

def explore_other_services(service_name, client):
    try:
        while True:
            print(f"\nExploring {service_name}:")
            try:
                operations = client.meta.service_model.operation_names
                print(f"Available operations for {service_name}:")
                for i, op in enumerate(operations):
                    print(f"{i + 1}: {op}")
                op_choice = int(input("Enter the number of the operation to execute (0 to go back): "))
                if op_choice == 0:
                    break
                operation_name = operations[op_choice - 1]
                perform_operation(client, operation_name)
            except Exception as e:
                print(f"Could not list operations for {service_name}: {str(e)}")
    except ClientError as e:
        print(f"Error with {service_name} service: {e}")
    except Exception as e:
        print(f"Unexpected error while exploring {service_name}: {e}")

def explore_services(services, region, access_key, secret_key):
    session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    while True:
        print("\nAccessible AWS Services:")
        for i, service in enumerate(services):
            print(f"{i + 1}: {service}")
        service_choice = int(input("\nEnter the number of the service you want to explore (0 to exit): "))
        if service_choice == 0:
            break
        service_name = services[service_choice - 1]
        client = session.client(service_name)
        if service_name == 's3':
            explore_s3(client)
        elif service_name == 'ec2':
            explore_ec2(client)
        elif service_name == 'route53':
            explore_route53(client)
        else:
            explore_other_services(service_name, client)

def generate_markdown_report(credentials):
    report = []

    # AWS Account Info
    report.append("# AWS Comprehensive Report\n")
    report.append("# Scanned by @SherlockSecure\n")
    report.append(f"**Access Key: REDACTED-This is a POC** \n")
    
    # Account Information
    try:
        sts_client = boto3.client('sts', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'])
        account_id = sts_client.get_caller_identity().get('Account')
        report.append(f"**Account ID:** {account_id}\n")
    except ClientError as e:
        report.append(f"Error retrieving account information: {e}\n")


    # IAM Roles
    try:
        iam_client = boto3.client('iam', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'])
        roles = iam_client.list_roles()
        report.append("## IAM Roles\n")
        for role in roles['Roles']:
            report.append(f"- **Role Name:** {role['RoleName']}\n")
            report.append(f"  **Role ARN:** {role['Arn']}\n")
            report.append(f"  **Creation Date:** {role['CreateDate']}\n")
    except ClientError as e:
        report.append(f"Error retrieving IAM roles: {e}\n")


    # Secret Store
    try:
        secretsmanager_client = boto3.client('secretsmanager', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'], region_name=credentials['region'])
        secrets = secretsmanager_client.list_secrets()
        report.append("## Secret Store\n")
        for secret in secrets['SecretList']:
            report.append(f"- **Secret Name:** {secret['Name']}\n")
            report.append(f"  **Secret ARN:** {secret['ARN']}\n")
    except ClientError as e:
        report.append(f"Error retrieving Secret Store information: {e}\n")




    # Parameter Store
    try:
        ssm_client = boto3.client('ssm', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'], region_name=credentials['region'])
        parameters = ssm_client.describe_parameters()
        report.append("## Parameter Store\n")
        for param in parameters['Parameters']:
            report.append(f"- **Parameter Name:** {param['Name']}\n")
            report.append(f"  **Parameter Type:** {param['Type']}\n")
            report.append(f"  **Last Modified Date:** {param['LastModifiedDate']}\n")
    except ClientError as e:
        report.append(f"Error retrieving Parameter Store information: {e}\n")


    # Security Groups
    try:
        ec2_client = boto3.client('ec2', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'], region_name=credentials['region'])
        security_groups = ec2_client.describe_security_groups()
        report.append("## Security Groups\n")
        for sg in security_groups['SecurityGroups']:
            report.append(f"- **Group Name:** {sg['GroupName']}\n")
            report.append(f"  **Group ID:** {sg['GroupId']}\n")
            report.append(f"  **Description:** {sg['Description']}\n")
            report.append(f"  **VPC ID:** {sg.get('VpcId', 'N/A')}\n")
            report.append(f"  **Inbound Rules:**\n")
            for rule in sg['IpPermissions']:
                report.append(f"    - **Protocol:** {rule['IpProtocol']}\n")
                report.append(f"      **Ports:** {rule.get('FromPort', 'All')} - {rule.get('ToPort', 'All')}\n")
                report.append(f"      **IP Ranges:** {[ip['CidrIp'] for ip in rule['IpRanges']]}\n")
            report.append(f"  **Outbound Rules:**\n")
            for rule in sg['IpPermissionsEgress']:
                report.append(f"    - **Protocol:** {rule['IpProtocol']}\n")
                report.append(f"      **Ports:** {rule.get('FromPort', 'All')} - {rule.get('ToPort', 'All')}\n")
                report.append(f"      **IP Ranges:** {[ip['CidrIp'] for ip in rule['IpRanges']]}\n")
    except ClientError as e:
        report.append(f"Error retrieving Security Groups: {e}\n")



    # Billing Info
    try:
        ce_client = boto3.client('ce', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'])
        billing = ce_client.get_cost_and_usage(TimePeriod={'Start': '2024-07-01', 'End': '2024-07-31'}, Granularity='MONTHLY', Metrics=['BlendedCost'])
        report.append("## Billing Information\n")
        for result in billing['ResultsByTime']:
            report.append(f"- **Time Period:** {result['TimePeriod']['Start']} to {result['TimePeriod']['End']}\n")
            report.append(f"  **Blended Cost:** {result['Total']['BlendedCost']['Amount']} {result['Total']['BlendedCost']['Unit']}\n")
    except ClientError as e:
        report.append(f"Error retrieving billing information: {e}\n")



    markdown_content = '\n'.join(report)
    return markdown_content

def save_report_as_pdf(markdown_content, output_file):
    try:
        html_content = markdown2.markdown(markdown_content)
        pdfkit.from_string(html_content, output_file)
        print(f"PDF report saved as: {output_file}")
    except Exception as e:
        print(f"Error saving PDF report: {e}")

def main():
    print("Welcome to the AWS service explorer")

    access_key = input("Enter your AWS Access Key: ")
    secret_key = input("Enter your AWS Secret Key: ")

    try:
        region = get_region_from_access_key(access_key, secret_key)
        if not region:
            print("Unable to determine region. Please check your credentials.")
            return
        print(f"Region determined: {region}")

        while True:
            print("\nMain Menu:")
            print("1: Generate a comprehensive report")
            print("2: Explore AWS services")
            print("0: Exit")
            choice = int(input("Enter the number of your choice: "))
            
            if choice == 0:
                break
            elif choice == 1:
                # Generating the report
                credentials = {'access_key': access_key, 'secret_key': secret_key, 'region': region}
                markdown_content = generate_markdown_report(credentials)
                report_file = "aws_report.md"
                with open(report_file, 'w') as f:
                    f.write(markdown_content)
                print(f"Markdown report saved as: {report_file}")

                # Optionally convert to PDF
                save_report_as_pdf(markdown_content, "aws_report.pdf")
            elif choice == 2:
                accessible_services = list_services(region, access_key, secret_key)
                print(f"Accessible Services: {accessible_services}")
                explore_services(accessible_services, region, access_key, secret_key)
            else:
                print("Invalid choice. Please select a valid option.")
    except NoCredentialsError:
        print("No credentials provided. Please enter valid AWS credentials.")
    except PartialCredentialsError:
        print("Partial credentials provided. Please ensure both Access Key and Secret Key are entered.")
    except ClientError as e:
        print(f"Client error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()

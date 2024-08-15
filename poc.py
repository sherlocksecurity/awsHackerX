import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

def get_region_from_access_key(access_key, secret_key):
    """Determine the region where the keys have access."""
    regions = boto3.session.Session().get_available_regions('ec2')
    for region in regions:
        try:
            client = boto3.client('ec2', aws_access_key_id=access_key,
                                  aws_secret_access_key=secret_key, region_name=region)
            client.describe_regions()
            print(f"Region {region} is accessible.")
            return region
        except Exception:
            continue
    print("No regions are accessible with these credentials.")
    return None

def list_services(region, access_key, secret_key):
    """List all services the credentials can access."""
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

def explore_s3(client, access_key, secret_key):
    """Explore the S3 service."""
    buckets = client.list_buckets()
    if len(buckets['Buckets']) == 0:
        print("No S3 buckets found.")
        return

    print("\nS3 Buckets:")
    for i, bucket in enumerate(buckets['Buckets']):
        print(f"{i + 1}: {bucket['Name']}")

    while True:
        bucket_choice = int(input("\nEnter the number of the bucket to explore (0 to go back): "))
        if bucket_choice == 0:
            break

        bucket_name = buckets['Buckets'][bucket_choice - 1]['Name']
        region = client.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
        if region is None:
            region = 'us-east-1'  # Default region

        s3_client = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
        
        while True:
            print(f"\nExploring bucket: {bucket_name}")
            print("1: List files in the bucket")
            print("2: Download a file")
            print("0: Go back to bucket list")
            
            action_choice = int(input("Enter the number of the action you want to perform: "))
            if action_choice == 0:
                break
            elif action_choice == 1:
                objects = s3_client.list_objects_v2(Bucket=bucket_name)
                if 'Contents' in objects:
                    for i, obj in enumerate(objects['Contents']):
                        print(f"{i + 1}: File: {obj['Key']} (Size: {obj['Size']} bytes)")
                else:
                    print(f"No files found in bucket {bucket_name}.")
            elif action_choice == 2:
                objects = s3_client.list_objects_v2(Bucket=bucket_name)
                if 'Contents' in objects:
                    for i, obj in enumerate(objects['Contents']):
                        print(f"{i + 1}: File: {obj['Key']} (Size: {obj['Size']} bytes)")
                    file_choice = int(input("Enter the number of the file to download: "))
                    file_key = objects['Contents'][file_choice - 1]['Key']
                    download_path = input("Enter the download path (with filename): ")
                    s3_client.download_file(bucket_name, file_key, download_path)
                    print(f"Downloaded {file_key} to {download_path}")
                else:
                    print(f"No files found in bucket {bucket_name}.")

def explore_ec2(client):
    """Explore the EC2 service."""
    while True:
        print("\nExploring EC2 Instances:")
        print("1: List EC2 instances")
        print("0: Go back to service list")

        action_choice = int(input("Enter the number of the action you want to perform: "))
        if action_choice == 0:
            break
        elif action_choice == 1:
            instances = client.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    print(f"Instance ID: {instance['InstanceId']}, State: {instance['State']['Name']}")
            if len(instances['Reservations']) == 0:
                print("No EC2 instances found.")

def explore_other_services(service_name, client):
    """Explore other AWS services in a generic manner."""
    while True:
        print(f"\nExploring {service_name}")
        print("1: List available operations")
        print("0: Go back to service list")

        action_choice = int(input("Enter the number of the action you want to perform: "))
        if action_choice == 0:
            break
        elif action_choice == 1:
            try:
                operations = client.meta.service_model.operation_names
                print(f"Available operations for {service_name}:")
                for i, op in enumerate(operations):
                    print(f"{i + 1}: {op}")
            except Exception as e:
                print(f"Could not list operations for {service_name}: {str(e)}")

def explore_services(services, region, access_key, secret_key):
    """Prompt user to select services and explore them."""
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
            explore_s3(client, access_key, secret_key)
        elif service_name == 'ec2':
            explore_ec2(client)
        else:
            explore_other_services(service_name, client)

if __name__ == "__main__":
    access_key = input("Enter your AWS Access Key: ")
    secret_key = input("Enter your AWS Secret Key: ")

    try:
        region = get_region_from_access_key(access_key, secret_key)
        if region:
            services = list_services(region, access_key, secret_key)
            if services:
                explore_services(services, region, access_key, secret_key)
            else:
                print("No services accessible with these credentials.")
    except (NoCredentialsError, PartialCredentialsError):
        print("Invalid credentials. Please check your access and secret keys.")

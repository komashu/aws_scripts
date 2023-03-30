import boto3
#from botocore.exceptions import ClientError
import socket
from requests import get


# TODO make this command line argument
# fill this out
security_group = ""
port = ""
proto = ""

ec2client = boto3.client('ec2')



def get_IPs_in_sg(security_group: str, port: int): -> list
    """
    Makes a list of ingress IPs in cidr notation to pre-check if the IP has already been added.
    :param security_group: (str) security group ID
    :param port: (int) the port number for the rule
    :return: (list) a list of (str)IPs in cidr notation eg. '205.251.233.178/32'
    """
    desc = ec2client.describe_security_groups(GroupIds=[security_group])
    ingress_ips = []
    for rule in desc['SecurityGroups'][0]['IpPermissions']:
        if rule['FromPort'] == port:
            for ips in rule['IpRanges']:
                ingress_ips.append(ips['CidrIp'])
    return ingress_ips



def update_sec_grp(sec_grp_id: str, ec2client: obj, ip: str, port: int, proto: str):
    """
    Adds rules/IPs to a security group
    :param sec_grp_id: (str) security group ID
    :param ec2client: (obj) the ec2 client made earlier, eg. ec2client = boto3.client('ec2')
    :param ip: (str) IP of the client
    :param port: (int) port number of the rule
    :param proto: (str) protocol type. eg. tcp, udp, icmp
    :return: nothing, it just updates the security group. it might return a json of the return request
    """
    # TODO see what it returns and update this
    data = ec2client.authorize_security_group_ingress(
        GroupId=sec_grp_id,
        IpPermissions=[
            {
                'IpProtocol': proto,
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [{'CidrIp': f'{ip}/32'}]
            },
        ]
    )
    return data


def get_public_ip():
	ip = get('https://api.ipify.org').text
	return ip


def main():
	pub_ip = get_public_ip()
	ingress_ips = get_IPs_in_sg(security_group, port)
    if not f'{pub}/32' in ingress_ips:
        try:
        	update_sec_grp(security_group, ec2client, pub_ip, port, proto)
        	print(f'Success! {pub_ip} was added to {security_group}')
        except Exception as e:
        	print(f'Could not add {pub_ip} to {security_group}')
            	print(f'Error: {e}')



if __name__ == '__main__':
	main()


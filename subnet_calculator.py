import re
import ipaddress
cd

def is_valid_ip(ip):
    pattern = r'^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(' \
              r'25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(' \
              r'25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(' \
              r'25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
    return re.match(pattern, ip) is not None


def check_ip(ip):
    return is_valid_ip(ip)


def calculate_subnet_mask(ip):
    ip_obj = ipaddress.IPv4Address(ip)
    first_octet = int(str(ip_obj).split('.')[0])
    if 0 <= first_octet <= 127:
        return 8
    elif 128 <= first_octet <= 191:
        return 16
    elif 192 <= first_octet <= 223:
        return 24
    else:
        raise ValueError("Invalid IP")


def choose_type():
    while True:
        choice = input("Do you want to partition by subnet or by host? (subnet/host): ").strip().lower()
        if choice in ['host', 'subnet']:
            return choice
        else:
            print("Please choose only subnet or host.")


def get_valid_number(prompt):
    while True:
        try:
            number = int(input(prompt))
            if number > 0:
                return number
            else:
                print('Invalid number.')
        except ValueError:
            print("Please choose a valid number.")


def calculate_hosts_and_subnets(cidr_prefix):
    host_bits = 32 - cidr_prefix
    num_hosts = 2 ** host_bits - 2
    num_subnets = 2 ** (cidr_prefix - 24) if cidr_prefix > 24 else 1
    return num_hosts, num_subnets


def calculate_network_and_broadcast(ip, cidr_prefix):
    network = ipaddress.IPv4Network(f"{ip}/{cidr_prefix}", strict=False)
    network_address = network.network_address
    broadcast_address = network.broadcast_address
    return network_address, broadcast_address


def calculate_first_and_last_subnets(ip, cidr_prefix):
    network = ipaddress.IPv4Network(f"{ip}/{cidr_prefix}", strict=False)
    subnets = list(network.subnets(new_prefix=cidr_prefix + 1))

    
    return subnets[:1] + subnets[-1:]


def main():
    ip = input("Please enter IP number: ")
    if not check_ip(ip):
        print("Invalid IP address.")
        return

    cidr_input = input("Please enter CIDR (or press Enter to calculate it): ")
    if cidr_input:
        cidr_prefix = int(cidr_input)
    else:
        cidr_prefix = calculate_subnet_mask(ip)

    partition_type = choose_type()

    if partition_type == 'host':
        num_hosts = get_valid_number("Enter number of hosts: ")
        cidr_prefix = 32 - (num_hosts + 2).bit_length()  # Calculate new CIDR prefix
    else:
        num_subnets = get_valid_number("Enter number of subnets: ")
        cidr_prefix = 24 + num_subnets.bit_length()  # Calculate new CIDR prefix

    num_hosts, num_subnets = calculate_hosts_and_subnets(cidr_prefix)
    network_address, broadcast_address = calculate_network_and_broadcast(ip, cidr_prefix)

    print(f"Number of hosts: {num_hosts}")
    print(f"Number of subnets: {num_subnets}")
    print(f"Network address: {network_address}")
    print(f"Broadcast address: {broadcast_address}")

    subnets_info = calculate_first_and_last_subnets(ip, cidr_prefix)
    for i, subnet in enumerate(subnets_info):
        print(f"Subnet {i + 1}:")
        print(f"  Network address: {subnet.network_address}")
        print(f"  Broadcast address: {subnet.broadcast_address}")


if __name__ == "__main__":
    main()

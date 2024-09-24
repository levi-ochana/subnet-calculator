import tkinter as tk
from tkinter import messagebox
import re
import ipaddress


# Function to validate if the entered IP address is valid
def is_valid_ip(ip):
    # Regular expression pattern to match valid IPv4 addresses
    pattern = r'^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(' \
              r'25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(' \
              r'25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(' \
              r'25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
    return re.match(pattern, ip) is not None  # Return True if the IP matches the pattern


# Function to calculate the default subnet mask based on the IP address class
def calculate_subnet_mask(ip):
    ip_obj = ipaddress.IPv4Address(ip)  # Convert the IP string to an IPv4Address object
    first_octet = int(str(ip_obj).split('.')[0])  # Get the first octet of the IP address
    # Determine the class of the IP address and return the corresponding subnet mask
    if 0 <= first_octet <= 127:
        return 8  # Class A
    elif 128 <= first_octet <= 191:
        return 16  # Class B
    elif 192 <= first_octet <= 223:
        return 24  # Class C
    else:
        raise ValueError("Invalid IP")  # Raise an error for invalid IPs


# Function to calculate the number of hosts and subnets based on the CIDR prefix
def calculate_hosts_and_subnets(cidr_prefix):
    host_bits = 32 - cidr_prefix  # Calculate the number of bits available for hosts
    num_hosts = 2 ** host_bits - 2  # Calculate the number of usable hosts (subtracting network and broadcast)
    num_subnets = 2 ** (cidr_prefix - 24) if cidr_prefix > 24 else 1  # Calculate subnets if CIDR > /24
    return num_hosts, num_subnets  # Return the number of hosts and subnets


# Function to calculate the network and broadcast addresses based on IP and CIDR prefix
def calculate_network_and_broadcast(ip, cidr_prefix):
    network = ipaddress.IPv4Network(f"{ip}/{cidr_prefix}", strict=False)  # Create a network object
    network_address = network.network_address  # Get the network address
    broadcast_address = network.broadcast_address  # Get the broadcast address
    return network_address, broadcast_address  # Return the network and broadcast addresses


# Function to calculate the first and last subnets based on the CIDR
def calculate_first_and_last_subnets(ip, cidr_prefix):
    network = ipaddress.IPv4Network(f"{ip}/{cidr_prefix}", strict=False)  # Create a network object
    subnets = list(network.subnets(new_prefix=cidr_prefix + 1))  # Generate a list of subnets
    return subnets[:1] + subnets[-1:]  # Return only the first and last subnets


# Function triggered when the "Calculate" button is clicked
def start_calculations():
    ip = ip_entry.get().strip()  # Get the user input for IP address
    if not is_valid_ip(ip):  # Validate the IP address
        messagebox.showerror("Error", "Invalid IP address.")  # Show error if invalid
        return

    cidr_input = cidr_entry.get().strip()  # Get user input for CIDR
    if cidr_input:  # If CIDR is provided
        try:
            cidr_prefix = int(cidr_input)  # Convert to integer
            if cidr_prefix < 0 or cidr_prefix > 32:
                raise ValueError("CIDR must be between 0 and 32.")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid CIDR value (0-32).")  # Show error for invalid input
            return
    else:  # If CIDR is not provided
        cidr_prefix = calculate_subnet_mask(ip)  # Calculate default CIDR based on the IP

    partition_type = partition_var.get()  # Get the partition type selected by the user

    # Handle partitioning by number of hosts
    if partition_type == 'host':
        try:
            num_hosts = int(input_entry.get().strip())  # Get number of hosts from user
            if num_hosts <= 0:
                raise ValueError("Number of hosts must be greater than 0.")
            cidr_prefix = 32 - (num_hosts + 2).bit_length()  # Calculate the CIDR for the specified number of hosts
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number of hosts.")  # Show error for invalid input
            return

    # Handle partitioning by number of subnets
    elif partition_type == 'subnet':
        try:
            num_subnets = int(input_entry.get().strip())  # Get number of subnets from user
            if num_subnets <= 0:
                raise ValueError("Number of subnets must be greater than 0.")
            cidr_prefix = 24 + num_subnets.bit_length()  # Calculate CIDR based on number of subnets
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number of subnets.")  # Show error for invalid input
            return
    else:
        messagebox.showerror("Error", "Please select partition type.")  # Show error if no partition type selected
        return

    # Perform calculations for hosts and subnets
    num_hosts, num_subnets = calculate_hosts_and_subnets(cidr_prefix)  # Calculate hosts and subnets
    network_address, broadcast_address = calculate_network_and_broadcast(ip, cidr_prefix)  # Calculate network and broadcast addresses

    # Display results in the result label
    result_text.set(f"Number of hosts: {num_hosts}\n"
                    f"Number of subnets: {num_subnets}\n"
                    f"Network address: {network_address}\n"
                    f"Broadcast address: {broadcast_address}")

    # Calculate and display the first and last subnets
    subnets_info = calculate_first_and_last_subnets(ip, cidr_prefix)  # Get first and last subnets
    for i, subnet in enumerate(subnets_info):
        result_text.set(result_text.get() + f"\n\nSubnet {i + 1}:\n"
                                            f"  Network address: {subnet.network_address}\n"
                                            f"  Broadcast address: {subnet.broadcast_address}")


# Function to show an explanation of the program in a message box
def show_explanation():
    explanation = ("This program is a Subnet Calculator.\n"
                   "It allows you to enter an IP address and a CIDR value "
                   "(or calculate one based on the IP).\n"
                   "You can specify the number of hosts or subnets you want, "
                   "and it will calculate the corresponding subnet information.")
    messagebox.showinfo("Program Explanation", explanation)  # Show the explanation in a message box


# Create the main window for the application
root = tk.Tk()
root.title("Subnet Calculator")  # Set the title of the window

# Add a welcome message at the top
welcome_label = tk.Label(root, text="Welcome to the Subnetting Calculator!", font=("Helvetica", 14))
welcome_label.grid(row=0, columnspan=2, padx=10, pady=10)  # Position the welcome label

# Label and entry for IP address input
tk.Label(root, text="Enter IP:").grid(row=1, column=0, padx=10, pady=5)
ip_entry = tk.Entry(root)  # Create an entry field for IP input
ip_entry.grid(row=1, column=1, padx=10, pady=5)

# Label and entry for CIDR input
tk.Label(root, text="Enter CIDR (optional):").grid(row=2, column=0, padx=10, pady=5)
cidr_entry = tk.Entry(root)  # Create an entry field for CIDR input
cidr_entry.grid(row=2, column=1, padx=10, pady=5)

# Radio buttons for partitioning by hosts or subnets
partition_var = tk.StringVar(value="host")  # Default to 'host' option
tk.Radiobutton(root, text="Host", variable=partition_var, value="host").grid(row=3, column=0, padx=10, pady=5)
tk.Radiobutton(root, text="Subnet", variable=partition_var, value="subnet").grid(row=3, column=1, padx=10, pady=5)

# Label and entry for number of hosts or subnets input
tk.Label(root, text="Enter number of hosts/subnets:").grid(row=4, column=0, padx=10, pady=5)
input_entry = tk.Entry(root)  # Create an entry field for hosts/subnets input
input_entry.grid(row=4, column=1, padx=10, pady=5)

# Button to start calculations
calculate_button = tk.Button(root, text="Calculate", command=start_calculations)
calculate_button.grid(row=5, columnspan=2, padx=10, pady=10)  # Position the calculate button

# Label to display results
result_text = tk.StringVar()  # Create a StringVar to hold the result text
result_label = tk.Label(root, textvariable=result_text, justify=tk.LEFT)
result_label.grid(row=6, columnspan=2, padx=10, pady=10)  # Position the result label

# Button to show explanation of the program
explanation_button = tk.Button(root, text="Program Explanation", command=show_explanation)
explanation_button.grid(row=7, columnspan=2, padx=10, pady=10)  # Position the explanation button

# Run the application
root.mainloop()

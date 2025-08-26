import subprocess


class FireWallAuto:

    def open_port(self,port_number: int):
        """Open a port in the firewall - Linux version"""
        print(f"Opening port {port_number}...")

        command = ["sudo", "ufw", "allow", f"{port_number}/tcp"]
        print(f"Running: {' '.join(command)}")
        return self._run_command(command)

    def close_port(self,port_number: int):
        """Close a port in the firewall - Linux version"""
        print(f"Closing port {port_number}...")

        command = ["sudo", "ufw", "deny", f"{port_number}/tcp"]
        print(f"Running: {' '.join(command)}")
        return self._run_command(command)

    def _run_command(self,command: list):
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ sucsess")
                return True
            else:
                print(f"❌ command did not run{result.stderr}")
                return False
        except Exception as e:
            return e
        
        
    def block_suspicious_ips(self,ips_list: list):
        """Block multiple suspicious IP addresses"""

        success_counts = 0

        for ip in ips_list:
            command = ["sudo", "ufw", "deny", "from", ip]
            print(f"\nBlocking {ip}...")
            print(f"Command: {' '.join(command)}")

            result = self._run_command(command)
            if result:
                success_counts += 1

        print(f"\n📊 Summary: {success_counts}/{len(ips_list)} IPs processed")

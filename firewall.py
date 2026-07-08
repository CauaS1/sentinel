import subprocess

def firewallFunc(ip, action, direction="in"):
    output = subprocess.run(
        ['sudo', 'ufw', action, direction, 'from', ip],
        capture_output=True,
        text=True
    )

    print(output.stdout)



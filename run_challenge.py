import sys
import yaml
import subprocess

# Modular Functions for Building, Running and Testing Containers
def run_challenge(challenge, category, challenge_no=1, port_base=3000):
    mode = challenge.get("mode", "remote")
    if mode == "static":    # Static challenges require *no* remote connection to find the flag
        return

    image_name = challenge.get("image_name", f"fyp_default_{challenge_no+1}")
    folder = challenge.get("folder", image_name)    # folder relative from /challenges
    port = challenge.get("port", port_base+challenge_no)
    domain = challenge.get("domain", overall_domain)
    test = challenge.get("test", overall_test)
    exploit_need_manual = challenge.get("exploit_need_manual", 0)

    # Build command line
    cmd = [f"./build_docker.sh", "-i", image_name, "-p", str(port), "-d", domain, "-t", test, "-f", folder]
    if exploit_need_manual:
        cmd.append("-m")

    # Get command-line arguments specific to category
    if category == 'pwn':
        get_pwn_options(challenge, cmd, image_name)
    elif category == 'web':
        get_web_options(challenge, cmd, image_name)
    elif category == 'python_script':
        get_py_options(challenge, cmd, image_name)
    # Run command
    try:
        output = subprocess.run(cmd, check=True, cwd=f".")
        return True
    except subprocess.CalledProcessError as e:
        print("Error: shell script failed. Output below")
        print(e)
        return False

def get_pwn_options(challenge, cmd, image_name):
    run_with_privilege = challenge.get("run_with_privilege", 0)
    binary_name = challenge.get("binary_name", image_name)
    if run_with_privilege:
        cmd.append("-P")
    cmd.append("-b"); cmd.append(binary_name)

def get_web_options(challenge, cmd, image_name):
    return
def get_py_options(challenge, cmd, image_name):
    run_with_privilege = challenge.get("run_with_privilege", 0)
    script_name = challenge.get("script_name", f"{image_name}.py")
    if run_with_privilege:
        cmd.append("-P")
    cmd.append("-s"); cmd.append(script_name) 


# Read YAML file
with open("challenges.yml", "r") as f:
    config = yaml.safe_load(f)

# Extract values
overall_test = config.get("overall").get("test", "ci")
overall_domain = config.get("overall").get("domain", "http://localhost")
overall_quick_fail = config.get("overall").get("quick_fail", 0)

built_challenge_count = 0
success_challenge_count = 0
try:
    categories = config.get("challenges")
    for category, challenges in categories.items():
        if category == 'web':
            for challenge in challenges:
                success = run_challenge(challenge, category='web', challenge_no=built_challenge_count, port_base=3000)
                built_challenge_count+=1
                if success:
                    success_challenge_count+=1
                elif overall_quick_fail:
                    print("[INFO] Quick fail is set. Abort build")
                    exit(1)
        elif category == 'pwn':
            for challenge in challenges:
                success = run_challenge(challenge, category='pwn', challenge_no=built_challenge_count, port_base=4000)
                built_challenge_count+=1
                if success:
                    success_challenge_count+=1
                elif overall_quick_fail:
                    print("[INFO] Quick fail is set. Abort build")
                    exit(1)
        elif category == 'python_script':
            for challenge in challenges:
                success = run_challenge(challenge, category='python_script', challenge_no=built_challenge_count, port_base=5000)
                built_challenge_count+=1
                if success:
                    success_challenge_count+=1
                elif overall_quick_fail:
                    print("[INFO] Quick fail is set. Abort build")
                    exit(1)
              
              
        
            
    print(f"{success_challenge_count}/{built_challenge_count} challenges built")
    if success_challenge_count < built_challenge_count:
        print("Not all challenges built")
        exit(1)
    else:
        print("All challenges passed test")

except KeyError:
    print("Error: Must specify `challenges` at the same level as `overall`")
    exit(1)



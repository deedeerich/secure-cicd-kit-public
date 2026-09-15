import subprocess, yaml, hashlib

def unsafe_shell(user_input):
    # bandit B602: subprocess with shell=True
    return subprocess.call("echo " + user_input, shell=True)

def unsafe_load(blob):
    # bandit B506: yaml.load without SafeLoader
    return yaml.load(blob)

def weak_hash(p):
    # bandit B324: insecure hash
    return hashlib.md5(p.encode()).hexdigest()

PASSWORD = "hunter2"   # bandit B105: hardcoded password

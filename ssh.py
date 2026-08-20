"""
ssh.py — SSH connection and command execution helpers for wp_audit.
"""

from typing import Optional

import paramiko

from config import CONNECTION_RETRIES, SSH_PORT, log


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

def client_connect(
    host: str,
    user: str,
    password: str | None,
    port: int = SSH_PORT,
    key_filename: str | None = None,
    known_hosts_file: str | None = None,
) -> paramiko.SSHClient:
    """
    Open an authenticated SSH connection to *host*.

    Host-key verification always uses RejectPolicy (hard deny).  Pass
    *known_hosts_file* to load an additional known_hosts file on top of the
    system one — this is how CI supplies the ephemeral container's key without
    disabling verification for every other host in the run.
    """
    client = paramiko.SSHClient()
    client.load_system_host_keys()          # ~/.ssh/known_hosts (and /etc/ssh/…)
    if known_hosts_file:
        client.load_host_keys(known_hosts_file)  # extra file, e.g. ci/run/known_hosts
    client.set_missing_host_key_policy(paramiko.RejectPolicy())  # deny unknown hosts
    client.connect(
        hostname=host,
        username=user,
        password=password,
        timeout=10,
        port=port,
        key_filename=key_filename,
    )
    return client


def establish_connection(
    host: str,
    user: str,
    password: str | None,
    port: int = SSH_PORT,
    key_filename: str | None = None,
    known_hosts_file: str | None = None,
) -> bool:
    """
    Attempt to establish an SSH connection to the host using provided credentials.
    Password or private key authentication can be used.
    When both are provided, password is interpreted as the passphrase for the private key.
    Returns True if successful, False otherwise.
    """
    success = False
    retries = 0
    while not success and retries < CONNECTION_RETRIES:
        try:
            client = client_connect(host, user, password, port, key_filename, known_hosts_file)
            client.close()
            success = True
            break
        except paramiko.AuthenticationException:
            log.warning("Authentication failed for %s@%s", user, host)
        except paramiko.SSHException as e:
            log.warning("SSH error for %s@%s: %s", user, host, e)
        except Exception as e:
            log.warning("Connection error for %s@%s: %s", user, host, e)
        retries += 1
    return success


def run_ssh_command(client: paramiko.SSHClient, command: str) -> Optional[str]:
    """
    Execute a command on the SSH client and return its output as a string.
    Returns None if the command fails or produces no output.
    """
    try:
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode("utf-8").strip()
        error = stderr.read().decode("utf-8").strip()
        if error:
            log.warning("SSH command error: %s", error)
        return output if output else None
    except Exception as e:
        log.warning("Failed to execute SSH command '%s': %s", command, e)
        return None

def has_wp_cli(client: paramiko.SSHClient) -> bool:
    """
    Check if WP-CLI is available on the remote server.
    Returns True if wp command is found, False otherwise.
    """
    output = run_ssh_command(client, "which wp")
    return bool(output)
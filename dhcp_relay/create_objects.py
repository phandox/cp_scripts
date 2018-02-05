import requests
import click
import json
import warnings
import logging


# Copied from example of Check Point R80.10 Management API:
# https://sc1.checkpoint.com/documents/latest/APIs/index.html#ws~v1.1%20
def api_call(ip_addr: str, port: int, command: str, json_payload: dict, sid=None):
    """
    Calls and API command to management server. If SID is not provided, login command is assumend and headers will omit SID
    :param ip_addr: IP address of management server
    :param port: Port where API listens
    :param command: API command to call on management server
    :param json_payload: Payload as dictionary used to feed the API command
    :param sid: Session identification - required for API commands expect the `login`.
    :return: Response of management server in JSON format
    """
    url = 'https://' + ip_addr + ':' + str(port) + '/web_api/' + command
    if sid is None:
        request_headers = {'Content-Type': 'application/json'}
    else:
        request_headers = {'Content-Type': 'application/json', 'X-chkp-sid': sid}
    with warnings.catch_warnings():  # Disable warnings about unverified HTTPS request
        warnings.simplefilter("ignore")
        r = requests.post(url, data=json.dumps(json_payload), headers=request_headers, verify=False)
    r.raise_for_status()
    return r.json()


def get_sessions(connection_info: dict, sid: str):
    # TODO make sure you can get more than 500 session ( use generator? )
    if sid is None or sid == "":
        raise TypeError("Sid not provided")
    response = api_call(connection_info["ip"], connection_info["port"], 'show-sessions', {}, sid)
    return [s["uid"] for s in response["objects"]]  # get sessions uids from top hierarchy


def clean_empty_disconnected_sessions(connection_info: dict, sid: str):
    if sid is None or sid == "":
        raise TypeError("Sid not provided")
    uids = get_sessions(connection_info, sid)
    counter = 0
    for u in uids:
        r = api_call(connection_info["ip"], connection_info["port"], 'show-session', {"uid": u}, sid)
        if r["in-work"] is False and r["locks"] == 0 and r["changes"] == 0:
            api_call(connection_info["ip"], connection_info["port"], 'discard', {"uid": u}, sid)
            counter += 1
    logging.info(f"Cleaned {counter} sessions")


def session_mgmt(connection_info: dict, action: str, sid=None):
    if action == "login":
        payload = {
            'user': connection_info["username"], 
            'password': connection_info["password"], 
            "session-name": connection_info["session-name"], 
            "session-description": connection_info["session-description"]
        }
        response = api_call(connection_info["ip"], connection_info["port"], 'login', payload)
        logging.info(f"Logged in as user {connection_info['username']}")
        return response["sid"]
    elif action == "publish":
        if sid is None or sid == "":
            raise TypeError("Sid not provided")
        response = api_call(connection_info["ip"], connection_info["port"], 'publish', {}, sid)
        logging.info("Publishing changes.")
    elif action == "discard":
        if sid is None or sid == "":
            raise TypeError("Sid not provided")
        response = api_call(connection_info["ip"], connection_info["port"], 'discard', {}, sid)
        logging.info("Discarding changes.")
    elif action == "logout":
        if sid is None or sid == "":
            raise TypeError("Sid not provided")
        response = api_call(connection_info["ip"], connection_info["port"], 'logout', {}, sid)
        logging.info(f"Logging out user {connection_info['username']}")
    else:
        raise TypeError("Action is not defined")


def add_dhcp_relay_interface_objects(connection_info: dict, sid: str, host_file: str, group_file: str, vlan: str):
    with open(host_file, mode='r', encoding='utf-8') as hf:
        hosts = json.load(hf)
    logging.info("Adding interfaces as host objects for DHCP Relay.")
    for h in hosts[vlan].values():
        response = api_call(connection_info["ip"], connection_info["port"], 'add-host', h, sid)
    with open(group_file, mode='r', encoding='utf-8') as gf:
        groups = json.load(gf)
    logging.info("Creating groups with interfaces for DHCP Relay.")
    response = api_call(connection_info["ip"], connection_info["port"], 'add-group', groups[vlan], sid)


@click.command()
@click.option("--user", required=True, help="Username on management server")
@click.option("--log", default="warning", help="Sets the log level")
@click.option("--session-name", default="", help="Names the API session")
@click.option("--session-description", default="", help="Description of API session")
@click.password_option()
@click.argument("ip_address")
@click.argument("port", default=443, required=False)
def main(user, log, session_name, session_description, password, ip_address, port):
    # Sets up logging level
    numeric_level = getattr(logging, log.upper())
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log}")
    logging.basicConfig(level=numeric_level)

    # Saves information for login into management server
    # TODO password should be stored in hash
    management_info = {
        "username": user, 
        "password": password, 
        "ip": ip_address, 
        "port": port,
        "session-name": session_name,
        "session-description": session_description
    }
    sid = session_mgmt(management_info, "login")
    vlans_to_add = ["vlan80", "vlan90", "vlan100"]

    try:
        for vlan in vlans_to_add:
            add_dhcp_relay_interface_objects(management_info, sid, "data/hosts.json", "data/groups.json", vlan)
        session_mgmt(management_info, "publish", sid)
    except Exception as e:
        # TODO React on duplicate objects as skipping them
        logging.critical(e)
        logging.critical("Exception detected. Discarding all changes.")
        session_mgmt(management_info, "discard", sid)
        clean_empty_disconnected_sessions(management_info, sid)
    finally:
        # Log out after finishing work
        clean_empty_disconnected_sessions(management_info, sid)
        session_mgmt(management_info, "logout", sid)


if __name__ == '__main__':
    main()

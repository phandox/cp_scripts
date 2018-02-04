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
    with warnings.catch_warnings(): # Disable warnings about unverified HTTPS request
        warnings.simplefilter("ignore")
        r = requests.post(url, data=json.dumps(json_payload), headers=request_headers, verify=False)
    r.raise_for_status()
    return r.json()



def session_mgmt(connection_info: dict, action: str, sid=None):
    if action == "login":
        payload = {'user': connection_info["username"], 'password': connection_info["password"]}
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
@click.password_option()
@click.argument("ip_address")
@click.argument("port", default=443, required=False)
def main(user, log, password, ip_address, port):
    numeric_level = getattr(logging, log.upper())
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log}")
    logging.basicConfig(level=numeric_level)

    management_info = {"username": user, "password": password, "ip": ip_address, "port": port}
    sid = session_mgmt(management_info, "login")

    try:
        add_dhcp_relay_interface_objects(management_info, sid, "data/hosts.json", "data/groups.json", "vlan70")
        session_mgmt(management_info, "publish", sid)
    except Exception as e:
        logging.critical(e)
        logging.critical("Exception detected. Discarding all changes.")
        session_mgmt(management_info, "discard", sid)
    finally:
        session_mgmt(management_info, "logout", sid)


if __name__ == '__main__':
    main()

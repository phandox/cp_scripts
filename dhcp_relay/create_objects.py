import requests
import click
import json


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
    r = requests.post(url, data=json.dumps(json_payload), headers=request_headers, verify=False)
    r.raise_for_status()
    return r.json()


def login(connection_info: dict):
    """
    Creates a new session on management server. Every work on management server must begin with login command.
    :param connection_info: Contains username, password, ip and port for connection
    """
    payload = {'user': connection_info["username"], 'password': connection_info["password"]}
    response = api_call(connection_info["ip"], connection_info["port"], 'login', payload)
    return response["sid"]


def logout(connection_info: dict, sid: str):
    """
    Logs out of session, defined by SID. Does not check if changes were published, saves the changes
    :param connection_info: Contains username, password, ip and port for connection
    :param sid: Session ID
    :return: Response of API command
    """
    if sid is None or sid == "":
        raise TypeError("Sid not provided")
    response = api_call(connection_info["ip"], connection_info["port"], 'logout', {}, sid)
    return response


@click.command()
@click.option("--user", required=True, help="Username on management server")
@click.password_option()
@click.argument("ip_address")
@click.argument("port", default=443, required=False)
def main(user, password, ip_address, port):
    management_info = {"username": user, "password": password, "ip": ip_address, "port": port}
    sid = login(management_info)
    click.echo(f"Session is {sid}")
    click.echo("Logging out")
    click.echo(logout(management_info, sid))


if __name__ == '__main__':
    main()

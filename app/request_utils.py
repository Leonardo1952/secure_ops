from flask import request


def get_client_ip():
    return request.remote_addr

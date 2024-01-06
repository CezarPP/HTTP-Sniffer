def is_http_data(data):
    try:
        text = data.decode('ascii')
        methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'CONNECT ']
        if any(text.startswith(method) for method in methods) or text.startswith('HTTP/'):
            return True
    except UnicodeDecodeError:
        # If data can't be decoded to ASCII, it's not HTTP
        pass
    return False


def parse_http_data(data):
    try:
        text = data.decode('ascii')
        print("HTTP Data:")
        print(text)
    except UnicodeDecodeError:
        print("HTTP Data could not be decoded")

from flask import Flask

def trace(current_app: Flask, in_function: str, variables: dict = {}):
    if current_app.config.get('TRACE'):
        if variables != {}:
            current_app.logger.debug(f'{in_function}({variables})')
        else:
            current_app.logger.debug(f'{in_function}()')
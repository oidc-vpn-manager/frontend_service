import os
import logging

logger = logging.getLogger('utils/environment')
logger.setLevel(logging.DEBUG)

def loadConfigValueFromFileOrEnvironment(key: str, default_value: str = '', default_path: str = '') -> str:
    """
    Load configuration values, by preference from a variable file (e.g. SECRET_FILE).
    This function reads the entire file content and strips leading/trailing whitespace.
    """
    VALUE_FILE = os.environ.get(f'{key}_FILE', None)
    if VALUE_FILE is None:
        logger.debug(f'{key}_FILE is not set. Using {default_path}.')
        VALUE_FILE = default_path

    if VALUE_FILE != '':
        if not os.path.exists(VALUE_FILE):
            raise FileNotFoundError(f'{key}_FILE is set to {VALUE_FILE} but the path does not exist.')
        if not os.path.isfile(VALUE_FILE):
            raise FileNotFoundError(f'{key}_FILE is set to {VALUE_FILE} but the path is not a file.')
        
        logger.debug(f'Reading {VALUE_FILE}')
        with open(VALUE_FILE, 'r') as file:
            # Read the entire content of the file and strip whitespace
            file_content = file.read().strip()
    
        logger.debug(f'{VALUE_FILE} contains: [REDACTED FOR SECURITY]')

        if file_content: # Use content if the file is not empty
            # Do not log file content as it may contain secrets
            logger.debug(f'File content loaded, length: {len(file_content)} characters')
            return file_content
        
        logger.debug('---No Content---')
    
    VALUE = os.environ.get(key, None)
    if VALUE is None:
        logger.debug(f'{key} is not set. Using {default_value or "None-as-defined"}')
        VALUE = default_value

    return VALUE

def loadBoolConfigValue(key: str, default: str, prefer: bool = False):
    false_strings = ['false', 'no', 'off', '0']
    true_strings = ['true', 'yes', 'on', '1']
    if prefer:
        return False if not str(os.environ.get(key, default)).lower() in true_strings else True
    else:
        return True if not str(os.environ.get(key, default)).lower() in false_strings else False


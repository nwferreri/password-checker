# Uses pwnedpasswords API to securely check if
# passwords input by user have been involved in data breaches

# Import libraries
import requests
import hashlib
import sys


def request_api_data(query_char):
    '''
    Requests API data from pwnedpasswords using the query characters.
    '''
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    result = requests.get(url)
    if result.status_code != 200:
        raise RuntimeError(f'Error fetching: {result.status_code}, check the API and try again.')
    return result


def get_password_leaks_count(hashes, hash_to_check):
    '''
    Checks for a specific hashed password in a list of hashed passwords
    and returns the count associated with that password. 
    '''
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    '''
    Hashes the password input by the user,
    sends the first 5 characters to the API,
    then returns the number of leaks associated with the password.
    '''
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    '''
    Loops through arguments (passwords) input by the user
    and evaluates safety of the password.
    '''
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times. Consider changing your password!')
        else:
            print(f'{password} was NOT found.  You should be safe!')
    return 'Done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

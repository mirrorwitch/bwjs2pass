bwjs2pass
=========

Unrefined importer of Bitwarden JSON exports into pass(1), the standard unix
password manager.  I did this in one day because 'pass-import bitwarden" wasn't
working for my JSON exports, and the CSV exports don't have custom
fields/notes/etc., and I was impatient.  It should be basically functional, but
it's untested and hacky.

## Features
 - Works with non-English password content even though passpy doesn't
 - Handles all 5 bitwarden item types (login, secure note, card, identity, and
   ssh key).
 - Preserves notes, custom fields, and uris.
 - Indents multi-lines notes.
 - Optionally preserves Bitwarden timestamps (`--timestamps`) or IDs (`--id`).
 - Optionally make entry names a bit more unixy for the LCI (`--detox`).  For
   example, ` Capitalised Entry  / my test  ` will become
   `capitalised-entry/my-test`.
   - This detox feature pointedly will *not* reduce Unicode to ASCII or erase
     non-English characters, deliberately.  (It will normalise Unicode to NFKD.)
     It also doesn't do much for punctuation, you can fix that later with sed.

## Missing features

 - Bitwarden OTP import *should* be compatible with pass-otp but I haven't
   tested it.
 - No FIDO2 credentials yet (wanted).
 - No handling of encrypted JSON exports yet (wanted).
 - No handling of ZIP exports / file attachments (probably not going to do
   this).
 - Not a round-trip conversion.  Many Bitwarden fields are ignored, including
   the "favourite" flag, "reprompt", or the distiction between "hidden" and
   "public" custom fields. (Not planned either.)

## Setup

pip install passpy
apt install python3-gnupg python3-colorlog python3-rich-argparse

have a pass(1) store set up and gpg key, etc. working.

## Usage

Options are documented on `python3 bwjs2pass.py -h`.

    python3 bwjs2pass.py --path bw-imported --detox --dry-run bitwarden | less
    # examine your password entries, make sure it looks ok

    python3 bwjs2pass.py --path bw-imported --detox --dry-run bitwarden > /dev/null
    # examine logs, make sure the warnings don't bother you

    python3 bwjs2pass.py --path bw-imported --detox bitwarden > /dev/null
    # highly recommended to use a --path separated from the rest of your store


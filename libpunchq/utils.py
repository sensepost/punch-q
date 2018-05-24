import socket
import string

from beautifultable import BeautifulTable as btable

from libpunchq.mqstate import mqstate


# Small helper to get a table handle
def get_table_handle(headers, markdown=True):
    """
        Gets a table handle.

        :param headers: list
        :param markdown:

        :return:
    """

    t = btable(max_width=mqstate.table_width, default_alignment=btable.ALIGN_LEFT)
    t.column_headers = headers

    if markdown:
        t.set_style(t.STYLE_MARKDOWN)

    return t


def is_ip_address(address):
    """
        Check if a string is an IP address.

        :param address:
        :return:
    """

    try:
        socket.inet_aton(address)

        return True
    except socket.error:

        return False


def filename_from_attributes(*args):
    """
        Generate a filename from arbitrary attributes.

        :param args:
        :return:
    """

    return safe_filename(''.join([str(a) for a in args]))


def safe_filename(filename):
    """
        Returns a 'safe' filename.

        :param filename:
        :return:
    """

    return ''.join(c for c in filename if c in string.printable).replace(' ', '')

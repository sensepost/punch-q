import click
import pymqi


def channel_type_to_name(channel_type):
    """
        Returns a string name for a LONG channel type.

        :param channel_type:
        :return:
    """

    channel_types = {
        pymqi.CMQC.MQCHT_SENDER: 'Sender',
        pymqi.CMQC.MQCHT_SERVER: 'Server',
        pymqi.CMQC.MQCHT_RECEIVER: 'Receiver',
        pymqi.CMQC.MQCHT_REQUESTER: 'Requester',
        pymqi.CMQC.MQCHT_ALL: 'All',
        pymqi.CMQC.MQCHT_CLNTCONN: 'Client-connection',
        pymqi.CMQC.MQCHT_SVRCONN: 'Server-connection',
        pymqi.CMQC.MQCHT_CLUSRCVR: 'Cluster-receiver',
        pymqi.CMQC.MQCHT_CLUSSDR: 'Cluster-sender',

        # 10L & 11L Don't have documented constants in CMQC it seems
        10: 'MQTT',
        11: 'AMQP',
    }

    if channel_type not in channel_types.keys():
        raise Exception('Unknown channel type \'{0}\' detected'.format(channel_type))

    return channel_types[channel_type]


def queue_type_to_name(queue_type):
    """
        Returns a string name for a LONG queue type.

        :param queue_type:
        :return:
    """

    queue_types = {
        pymqi.CMQC.MQQT_LOCAL: 'Local',
        pymqi.CMQC.MQQT_MODEL: 'Model',
        pymqi.CMQC.MQQT_ALIAS: 'Alias',
        pymqi.CMQC.MQQT_REMOTE: 'Remote',
        pymqi.CMQC.MQQT_CLUSTER: 'Cluster',
        pymqi.CMQC.MQQT_ALL: 'All',
    }

    if queue_type not in queue_types.keys():
        raise Exception('Unknown queue type \'{0}\' detected'.format(queue_type))

    return queue_types[queue_type]


def queue_usage_to_name(queue_usage):
    """
        Returns a string name for a LONG queue usage type.

        :param queue_usage:
        :return:
    """

    queue_usages = {
        None: '',  # :|
        pymqi.CMQC.MQUS_NORMAL: 'Normal',
        pymqi.CMQC.MQUS_TRANSMISSION: 'Transmission',
    }

    if queue_usage not in queue_usages.keys():
        raise Exception(f'Unknown usage type "{queue_usage}" detected')

    return queue_usages[queue_usage]


def mq_string(s, strip: bool = True) -> str:
    """
        Try and handle strings returned from MQ.

        If s is bytes, try and decode() them.
    """

    if isinstance(s, str):
        return s

    if isinstance(s, bytes):
        s = s.decode()
        return s.strip() if strip else s

    click.secho(f'Unsure what to do with: {s}. Returning unchanged', fg='yellow')
    return s

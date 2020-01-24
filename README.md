<h1 align="center">
  <br>
    👊 punch-q
  <br>
  <br>
</h1>

<h4 align="center">A small utility to play with IBM MQ</h4>
<p align="center">
  <a href="https://twitter.com/leonjza"><img src="https://img.shields.io/badge/twitter-%40leonjza-blue.svg" alt="@leonjza" height="18"></a>
  <a href="https://pypi.python.org/pypi/punch-q"><img src="https://badge.fury.io/py/punch-q.svg" alt="PyPI version" height="18"></a>
</p>
<br>

## introduction

`punch-q` is a small Python utility used to play with IBM MQ instances. Using `punch-q`, it is possible to perform  security related tasks such as manipulating messages on an IBM MQ queue granting one the ability to tamper with business processes at an integration layer.

## features

With `punch-q`, you can:

- GET / PUT / SNIFF messages on message queues.
- Execute commands using MQ services.
- Perform various brute force attacks.

### examples

Sniffing messages from a message queue:

![message sniff](https://i.imgur.com/sAt2v1U.png)

Executing commands via MQ services:

![command execution](https://i.imgur.com/vEvRem0.png)

## installation - docker

A docker container for `punch-q` can be built with:

```text
git clone https://github.com/sensepost/punch-q.git
cd punch-q
docker build -t punch-q:local .
```

Once done, you can run `punch-q` with:

```text
docker run --rm -ti punch-q:local --help
```

## installation

This utility relies on [pymqi](https://github.com/dsuch/pymqi) and needs to be successfully installed for `punch-q` to work. The installation of `pymqi` relies on the IBM MQ client utilities to be available which you would need to download from IBM's website first. [This](https://github.com/dsuch/pymqi/issues/15#issuecomment-124772995) Github issue can be used as a reference to install the correct MQ Client libraries.

Alternatively, a hint from [this](https://github.com/ibm-messaging/mq-golang/blob/master/Dockerfile#L53-L62) repository means one could just download and extract the archive in the correct location to compile `pymqi`. This is how the docker container does it.

To get the IBM MQ client for `pymqi` and `punch-q` working, you need to:

- Download the IBM MQ Client libraries for Linux from IBM's website [here](https://public.dhe.ibm.com/ibmdl/export/pub/software/websphere/messaging/mqdev/redist/9.1.4.0-IBM-MQC-Redist-LinuxX64.tar.gz). Older versions and ibraries for other operating systems is also available [here](https://public.dhe.ibm.com/ibmdl/export/pub/software/websphere/messaging/mqdev/redist/).
- Extract the downloaded archive to `/opt/mqm`.

Finally, `punch-q` itself can be installed with:

```bash
pip install punch-q
```

*Note:* When running `punch-q`, and you get an error similar to `Importing pymqi failed with: libmqic_r.so: cannot open shared object file: No such file or directory!`, simply set the `LB_LIBRARY_PATH` to /opt/mqm/lib64 library with:

```bash
export LD_LIBRARY_PATH=/opt/mqm/lib64
```

## osquery table plugin

An osquery table plugin PoC can also be found in this repository [here](https://github.com/sensepost/punch-q/tree/master/osquery-mqtable).

## license

`punch-q` is licensed under a [GNU General Public v3 License](https://www.gnu.org/licenses/gpl-3.0.en.html). Permissions beyond the scope of this license may be available at [http://sensepost.com/contact/](http://sensepost.com/contact/).

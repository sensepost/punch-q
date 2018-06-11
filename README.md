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

`punch-q` is a small Python 2 utility used to play with IBM MQ instances. Using `punch-q`, it is possible to perform  security related tasks such as manipulating messages on an IBM MQ queue granting one the ability to tamper with business processes at an integration layer.

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

## installation

This utility relies on [pymqi](https://github.com/dsuch/pymqi) and needs to be successfully installed for `punch-q` to work. The installation of `pymqi` relies on the IBM MQ client utilities to be installed which you would need to download from IBM's website first. [This](https://github.com/dsuch/pymqi/issues/15#issuecomment-124772995) Github issue can be used as a reference to install the correct MQ Client libraries.

In summary, to get the IBM MQ client for `pymqi` and `punch-q` working, you need to:

- Download the IBM MQ Client libraries from IBM's [website](http://www-01.ibm.com/software/integration/wmq/clients/). The version 7.5 x64 Linux client library was used while testing `punch-q` and can be found [here](https://www-945.ibm.com/support/fixcentral/swg/downloadFixes?parent=ibm~WebSphere&product=ibm/WebSphere/WebSphere+MQ&release=7.5.0.8&platform=All&function=fixId&fixids=7.5.0.8-WS-MQC-LinuxX64&useReleaseAsTarget=true&includeRequisites=0&includeSupersedes=0&downloadMethod=http) (You may need to login with an IBM ID first).
- After the download is complete, extract the archives contents and accept the IBM license agreement with `/mqlicense.sh -accept`.
- Install the `MQSeriesRuntime`, `MQSeriesClient` and `MQSeriesSDK` RPM's. These can be installed on Kali Linux after installing `rpm` with `rpm -ivh <PackageName>.rpm`.

Finally, with the MQ series client installed, `punch-q` itself can be installed with:

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

`punch-q` is licensed under a [GNU General Public v3 License](https://www.gnu.org/licenses/gpl-3.0.en.html). Permissions beyond the scope of this license may be available at http://sensepost.com/contact/.

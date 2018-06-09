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

- GET / PUT messages on message queues.
- Execute commands using MQ service.
- Perform various brute force attacks.

### examples

Sniffing messages from a message queue:

![message sniff](https://i.imgur.com/sAt2v1U.png)

Executing commands via MQ services:

![command execution](https://i.imgur.com/vEvRem0.png)

## installation

`punch-q` can be installed via `pip` with `pip install punch-q`.

## license

`punch-q` is licensed under a [GNU General Public v3 License](https://www.gnu.org/licenses/gpl-3.0.en.html). Permissions beyond the scope of this license may be available at http://sensepost.com/contact/.

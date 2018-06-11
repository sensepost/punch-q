# osquery-mqtable

A simple PoC for a custom osquery table plugin that returns information about IBM MQ.

## building

Clone this reposistory and ensure that your `$GOPATH` is set. Resolve dependencies with `dep ensure` and finally build the extention with `make`. If you want to build for other architectures, refer to the `Makefile` for an easy reference.

## running

To load the extention using the interactive osquery shell, run:

```bash
osqueryi --extension /path/to/plugin/linux-amd64-mqtable.ext
```

For more information on loading custom extentions with the osquery daemon, please refer to the osquery [documentation](https://osquery.readthedocs.io/en/stable/deployment/extensions/).

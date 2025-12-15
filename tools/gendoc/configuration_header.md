# Configuration

![LockBox Node Configuration](/img/banner_lockbox_configuration.png)

LockBox uses a JSON standard format as a config file. If you are unsure about JSON syntax, you can find more information in the [official JSON specs](https://www.json.org).

You can change the path of the config file by using the `-c` or `--config` argument while executing `lockbox-node` executable.

For example:
```bash
lockbox-node -c config_example.json
```

You can always get the most up-to-date description of the config parameters by running:

```bash
lockbox-node -h --full
```


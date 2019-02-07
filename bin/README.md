# secrets

Encrypt small packets of data into websafe text.

## How to Use It

Your encryption key is read from Keychain or from an environment variable. You should not type your key into the terminal where it will likely be saved by your shell history.

*Retrieve the key from the OS Keychain*

```sh
$ secrets -s myapp -a session-key encrypt ./path/to/file.json
```

*Retrieve the key from the default environment variable*

It will look for a key in the `SECRET_KEY` environment variable.

```sh
$ source ./export_key.sh
$ secrets encrypt ./path/to/file.json
# Equivalent to this:
$ secrets -e SECRET_KEY encrypt ./path/to/file.json
```

```sh
# In ./export_key.sh
export SECRET_KEY="some-64-character-hex-value"
```


```
Encrypt small packets of data into websafe text.

USAGE:
    secrets [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -e, --env <env_name>           Environment variable name containing the 256-bit key value in hex [default:
                                   SECRET_KEY]
    -a, --account <key_account>    Keychain account name containing the 256-bit key value in hex
    -s, --service <key_service>    Keychain service name containing the 256-bit key value in hex

SUBCOMMANDS:
    decrypt    Decrypt a websafe string into a JSON object
    encrypt    Encrypt a JSON file to a websafe string
    help       Prints this message or the help of the given subcommand(s)
```

### Encrypt JSON files

*Encrypt a JSON file*

```sh
$ secrets encrypt ./path/to/file.json
```

*Encrypt non-JSON file*

```sh
$ secrets encrypt --raw ./path/to/file.xls
```

```
Encrypt a JSON file to a websafe string

USAGE:
    secrets encrypt [FLAGS] <json_file>

FLAGS:
    -h, --help       Prints help information
    -r, --raw        Encrypt input bytes directly, without expecting JSON
    -V, --version    Prints version information

ARGS:
    <json_file>    JSON input file to encrypt, "-" to read from STDIN
```

## Decrypt websafe text

*Decrypt a JSON file*

```sh
$ secrets decrypt ./path/to/file.txt
{
    "hello": "world"
}
```

*Decrypt non-JSON file*

```sh
$ secrets decrypt --raw ./path/to/file.txt > ./my.xls
```

```
Decrypt a websafe string into a JSON object

USAGE:
    secrets decrypt [FLAGS] <websafe_text_file>

FLAGS:
    -h, --help       Prints help information
    -r, --raw        Decrypt directly to raw bytes, without interpreting as JSON
    -V, --version    Prints version information

ARGS:
    <websafe_text_file>    Text file to decrypt, "-" to read from STDIN
```

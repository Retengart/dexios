## Encrypt a File

```bash
dexios encrypt secret.txt secret.enc
```

## Decrypt a File

```bash
dexios decrypt secret.enc secret.txt
```

## Use AES-256-GCM Instead of the Default

```bash
dexios encrypt --aes secret.txt secret.enc
```

You do not need to repeat `--aes` during decryption; the algorithm is stored in the header.

## Use a Keyfile

```bash
dexios encrypt --keyfile keyfile secret.txt secret.enc
```

## Generate a Passphrase Automatically

```bash
dexios encrypt --auto secret.txt secret.enc
```

Or with an explicit number of words:

```bash
dexios encrypt --auto=5 secret.txt secret.enc
```

## Use `DEXIOS_KEY`

```bash
DEXIOS_KEY='correct horse battery staple' dexios encrypt secret.txt secret.enc
```

## Write the Header Separately

```bash
dexios encrypt --header secret.header secret.txt secret.enc
```

And later decrypt with it:

```bash
dexios decrypt --header secret.header secret.enc secret.txt
```

## Print a Checksum for the Encrypted Input

```bash
dexios encrypt --hash secret.txt secret.enc
```

```bash
dexios decrypt --hash secret.enc secret.txt
```

## Securely Erase the Input After Encrypting

```bash
dexios encrypt --erase secret.txt secret.enc
```

To request more overwrite passes:

```bash
dexios encrypt --erase=3 secret.txt secret.enc
```

## Hash Files Directly

```bash
dexios hash secret.enc
```

## Pack and Encrypt Directories

```bash
dexios pack photos/ archive.enc
```

With compression:

```bash
dexios pack --zstd photos/ archive.enc
```

## Unpack a Previously Packed Archive

```bash
dexios unpack archive.enc output-dir
```

## Encrypt a File

```bash
dexios encrypt secret.txt secret.enc
```

## Decrypt a File

```bash
dexios decrypt secret.enc secret.txt
```

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

## Delete the Input After Encrypting

```bash
dexios encrypt --delete-input secret.txt secret.enc
```

## Delete the Encrypted Input After Decrypting

```bash
dexios decrypt --delete-input secret.enc secret.txt
```

## Hash Files Directly

```bash
dexios hash secret.enc
```

## Pack and Encrypt Directories

```bash
dexios pack photos/ archive.enc
```

Pack uses Dexios-owned manifest-first archive framing with a fixed archive
policy.

## Unpack a Previously Packed Archive

```bash
dexios unpack archive.enc output-dir
```

Delete the encrypted archive after a successful unpack:

```bash
dexios unpack --delete-input archive.enc output-dir
```

Delete source directories after a successful pack:

```bash
dexios pack --delete-source photos/ archive.enc
```

The delete flags run only after the workflow commits its outputs and any requested hash succeeds.

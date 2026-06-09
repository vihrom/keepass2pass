# keepass2pass

A Python script to import KeePass2 XML databases into the `pass` password store.

## Requirements

* Python 3.x
* pass (password-store)

## Usage

Make the script executable:

```BASH
chmod +x keepass2pass
```

1. Default import (uses default XML root group name):

```BASH
./keepass2pass -f export.xml
```

1. Custom root folder (places everything inside a specific folder):

```BASH
./keepass2pass -f export.xml -r "foo"
```

1. Flat structure (skips root folder completely):

```BASH
./keepass2pass -f export.xml -r ""
```

## Duplicate Handling

When a duplicate path is found, the script prompts you interactively:

* m  -> Merge this specific duplicate into one file
* s  -> Split this specific duplicate (adds _2,_3, etc.)
* ma -> Merge ALL remaining duplicates automatically
* sa -> Split ALL remaining duplicates automatically

## License

Based on the original script by Stefan Simroth.

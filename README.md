# SPU Cell Architecture Plugin (v0.0.1)
Author: **Bambu**

_A disassembler for the SPU Cell architecture._

## Description:
This plugin disassembles SPU assembly code. This plugin is based off of the SPU IDA plugin by Felix Domke.

To install this plugin, navigate to your Binary Ninja plugins directory, and run

```git clone https://github.com/bambu/binaryninja-spu.git spu```

Then create a python file called `spu.py` with the contents

```import spu```

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * dev (Personal) - 1.0.dev-614
 * dev (Commercial) - 1.0.dev-614
 * release (Commercial) - 1.0.317
 * release (Personal) - 1.0.317
 
## TODO
 * LLIL generation 
 * `__noreturn` function types
 * Calling Convention

## License

This plugin is released under a [MIT](LICENSE) license.



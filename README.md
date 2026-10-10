# another-backporter

Experimental automatic PS5 backport creator. Rather than applying a static set of fakelibs to every title, this project attempts to dynamically resolve which exports are missing on a target firmware for a given title, and satisfy those imports by building fresh fakelibs from a clean firmware dump. Where an import cannot be reasonably satisfied, stubs are are handled per export and tracked on a manually reviewed database.

Expects a 13.60 firmware dump available under data/PS5_Libs/13.60.

Very much a work in progress. Only built to handle 7.XX backports for now.

Usage

```bash
backport-ps5.py run SRC OUT
```
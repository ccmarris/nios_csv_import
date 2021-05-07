Control CSV import to NIOS via API
==================================


nios_csv_import.py --help
usage: nios_csv_import.py [-h] [-c CONFIG] [-f FILE] [-m] [-s STATUS] [-a ACTION] [-d]

Create EA in NIOS

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Override ini file
  -f FILE, --file FILE  Override csv import file
  -m, --monitor         Monitor Status of Import
  -s STATUS, --status STATUS
                        Get Status of CSV Import Job Specified
  -a ACTION, --action ACTION
                        Change default action of INSERT (e.g. DELETE) for CSV Import
  -d, --debug           Enable debug messages


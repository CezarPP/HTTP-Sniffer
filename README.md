# HTTP Sniffer

## Task

Implement an application that functions as an HTTP packet sniffer.

The application should allow real-time viewing of requests, and apply filters to packet traffic (e.g., requests coming
from a certain address, requests of specific types: GET/POST/DELETE, etc.).

Additionally, for a given request, the user should be able to find details about that request: headers, request mode,
payload, etc.

A GUI is not necessary (data can also be displayed in the console).
However, there should be a clear representation of this data (it should be understandable what each piece of data
represents).
Traffic is captured using the *socket* library, and packet decoding is done with *struct/ctypes*.
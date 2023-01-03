### 

* passing all autobahn tests
* handles per message deflate, including sliding window bits size negotiation
* uses zlib for message compression/decompression

### References


[The WebSocket Protocol RFC](https://www.rfc-editor.org/rfc/rfc6455)  
[compression extension RFC](https://www.rfc-editor.org/rfc/rfc7692)   
[autobahn testsuite](https://github.com/crossbario/autobahn-testsuite)

[mattnite/zig-zlib](https://github.com/mattnite/zig-zlib)  
[zlib](https://www.zlib.net/manual.html#Advanced)

<!--
https://bugs.chromium.org/p/chromium/issues/detail?id=691074
https://www.igvita.com/2013/11/27/configuring-and-optimizing-websocket-compression/#parameters
-->

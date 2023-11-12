###

* passing all autobahn tests
* handles per message deflate, including sliding window bits size negotiation
* uses zlib for message compression/decompression


### Include library in you project

There is a minimal project in [examples/exe](examples/exe/) which demonstrates
how to use websocket client. 

* add dependency to ws lib in your [build.zig.zon](examples/exe/build.zig.zon#L5:L8)
* link library in your [build.zig](examples/exe/build.zig#L27:L29)

Then you can `@import("ws")` in [src/main.zig](examples/exe/src/main.zig#L2).
This example uses public echo ws server at ws://ws.vi-server.org/mirror/.
Connects to websocket server, sends hello message and prints echoed reply.

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

### run file tests
```
zig test src/main.zig --deps zlib=zlib --mod zlib::../zig-zlib/src/main.zig -l z 2>&1 | cat
```

# Native Windows RDP credential handoff

The Windows mstscax adapter receives public display, target, user and gateway
metadata only. Its managed profile has no primary or gateway password property.
Go removes both password fields from every adapter command before JSON encoding.
This replaces the former plaintext password delivery to the C# adapter. Existing
FreeRDP stdin authentication and external mstsc credential prompts are unchanged.

For a connection that supplies credentials, the adapter configures its native
ActiveX control and exports an IDispatch reference, without starting the network
connection. The Go parent accepts only a bounded standard OBJREF for IDispatch.
It rejects custom, handler and extended marshaling and removes all non-ncalrpc
transport bindings. Windows compact same-machine references are also supported.
The reference stays inside the native parent/child boundary and is removed from
all events sent to Electron.

Go unmarshals the reference on a dedicated STA thread and requires authenticated
RPC packet privacy on the control and returned settings proxies. It sets the
native write-only ClearTextPassword and GatewayPassword properties directly.
UTF-8 credentials are converted into mutable UTF-16 and BSTR buffers; both are
cleared after the setter returns. Authentication state retained internally by
mstscax belongs to that native control and dies with its process. No password is
placed in the adapter JSON model, managed strings, command arguments or files.

The supervisor owns a one-use handoff with a 15-second deadline. It binds the
reference to the exact start request, rejects replay and early initialization,
and sends a metadata-only connect acknowledgement after the setters succeed.
Cancellation atomically prevents completion. A timeout kills the adapter to
interrupt an in-flight COM call; completion, error, panic and teardown clear the
owned Go buffers. A failed or unowned connect command closes the adapter.

Verification includes a real Windows mstscax export and cross-process setter,
primary and independent gateway credentials, explicit empty/Unicode BSTR values,
and RDP negotiation against a loopback listener. The supervisor integration also
checks that setters precede connection and teardown clears its buffers. Negative
cases cover malformed/remote references, property errors, replay, premature
responses, timeout and concurrent cancellation. These are synthetic local tests;
they do not establish real server login or RD Gateway interoperability. Windows
arm64 is cross-built; the runtime probe executes on Windows x64.

This handoff is a prerequisite for protected local/shared RDP sessions. It does
not itself enable those vault session APIs or their renderer integration.

References: [COM marshaling](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-comarshalinterface),
[primary password](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpclientadvancedsettings-cleartextpassword),
[gateway password](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpclienttransportsettings2-gatewaypassword).

## Running the native regression

Build the helper with `scripts/Build-RdpHost.ps1 -Arch x64`. Set
`WORMHOLE_TEST_RDP_HOST` to the absolute packaged
`dist-electron/wormhole-rdp-host-x64.exe` path. From `tools/wormhole-backend`, run
`go test . -run '^Test(Rdp|NativeRdpCOM)' -count=1 -race`.

For cross-process C# coverage, compile the Go test binary with `go test -c`, set
`WORMHOLE_TEST_RDP_GO_PROBE` to that binary's absolute path, and run the adapter
xUnit project with the built-in Code Coverage collector. The native test requires
both Go PASS markers and rejects skipped probe cases. Without the probe, it is
explicitly skipped during discovery; the managed unit tests remain available.

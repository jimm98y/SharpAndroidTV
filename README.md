# AndroidTVAPI
Client to control Android TV.

## AndroidTVPairingClient
Create the client:
```cs
AndroidTVPairingClient tvPairingClient = new AndroidTVPairingClient("192.168.1.90");
```

Initiate the pairing process:
```cs
await tvPairingClient.InitiatePairingAsync();
```

TV should display a 6 letter pairing code on the screen. Pass it to the pairing client and the pairing client will return a certificate that you should store somewhere safe:
```cs
string certificate = await tvPairingClient.CompletePairingAsync("1234AB");
```

## AndroidTVClient

### Turn on the TV
To turn on the TV if you know the MAC address:
```cs
await AndroidTVClient.TurnOnAsync("192.168.1.90", "FF:FF:FF:FF:FF:FF");
```
If you don't know the MAC address, but you are running on Windows/MacOS/Linux where your process can access the terminal, run:
```cs
await AndroidTVClient.TurnOnAsync("192.168.1.90");
```
This will attempt to use ARP to resolve the MAC address from the IP address.

### Control the TV
To control the TV, create the client and pass the certificate from the `AndroidTVPairingClient`:
```cs
AndroidTVClient tvClient = new AndroidTVClient("192.168.1.90", certificate);
```
Send a volume up key:
```cs
await tvClient.PressKeyAsync(KeyCodes.KEYCODE_VOLUME_UP, KeyAction.Down);
await tvClient.PressKeyAsync(KeyCodes.KEYCODE_VOLUME_UP, KeyAction.Up);
```
Open Netflix:
```cs
tvClient.StartApplication("https://www.netflix.com/title.*");
```
Get current TV configuration:
```cs
var configuration = tvClient.GetConfiguration();
```

## Credits
This project is based upon the research from here: https://github.com/Aymkdn/assistant-freebox-cloud/wiki/Google-TV-(aka-Android-TV)-Remote-Control-(v2)
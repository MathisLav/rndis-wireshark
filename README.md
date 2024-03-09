## Protocol dissector for Remote NDIS protocol

### Building:
- Clone the Wireshark repository.
- Clone this repository into plugins/epan/rndis
- Move CMakeListsCustom.txt.example to CMakeListsCustom.txt
- Add plugins/epan/rndis to CUSTOM_PLUGIN_SRC_DIR
- Build Wireshark as usual

You can then either run wireshark and enjoy the built-in RNDIS dissector.
Or copy the output file `run/plugins/4.0/epan/rndis.so` to `~/.local/lib/wireshark/plugins/4.0/epan/`.

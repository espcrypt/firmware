# ESP Crypt firmware

The firmware that runs on your ESP Crypt board. You do not need to download
anything from here: the [ESP Crypt app](https://github.com/espcrypt/manager)
installs and updates it for you.

## Supported boards

| Board | Vault | Passkey |
| --- | --- | --- |
| Waveshare ESP32-S3-Zero | ✓ | ✓ |
| Seeed XIAO ESP32-S3 | ✓ | ✓ |
| ESP32-C3 SuperMini | ✓ | – |
| ESP32-C6 SuperMini | ✓ | – |

## LED

| LED | Meaning |
| --- | --- |
| Red, slow blink | Locked |
| Green, slow blink | Unlocked |
| Purple, slow blink | No passphrase set yet |
| Orange, fast blink | Unlocking |
| Green, fast blink | Syncing with the backup board |
| Yellow, fast blink | Updating |
| White blinking | Press BOOT to confirm |
| Red, three times | Wrong passphrase |

## License

GNU Lesser General Public License v3.0 or later. See [LICENSE](LICENSE).

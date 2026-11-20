# Third-party software

PhoneSentry's own code is licensed under the GNU GPL v3 (see `LICENSE`). The Windows executable bundles the components below, each under its own licence.

| Component | Use | Licence | Source |
|---|---|---|---|
| Mobile Verification Toolkit (MVT) | Spyware forensics, indicator matching | MVT License 1.1 | https://github.com/mvt-project/mvt |
| MVT indicator feeds | Pegasus, Predator, stalkerware... indicators (STIX2) | Licence of each feed (Amnesty International, Citizen Lab, Echap, ...) | https://github.com/mvt-project/mvt-indicators |
| pymobiledevice3 | iPhone communication | GPL-3.0 | https://github.com/doronz88/pymobiledevice3 |
| Android SDK Platform-Tools (adb) | Android communication | Android Software Development Kit License | https://developer.android.com/tools/releases/platform-tools |
| CustomTkinter | User interface | MIT | https://github.com/TomSchimansky/CustomTkinter |
| Pillow | Images | MIT-CMU | https://github.com/python-pillow/Pillow |
| Requests | HTTP | Apache-2.0 | https://github.com/psf/requests |
| PyInstaller | Packaging | GPL-2.0 with bootloader exception | https://github.com/pyinstaller/pyinstaller |

## MVT License 1.1: consensual use

MVT's licence adds a *Consensual Use Restriction* (section 3.0): the owner of the data must explicitly consent to the procedure, free from coercion, and be fully informed about its nature, privacy implications and data retention. PhoneSentry asks for this confirmation before every scan. Do not remove that step, and do not use PhoneSentry on a phone without its owner's informed consent.

The full MVT source code, including its licence text, is available at the link above.

# pam_parallel

Runs PAM authentication modules in parallel. The first module to succeed logs you in. Splits modules into a foreground (`fg=`, allows I/O like passwords) and background (`bg=`, async, no I/O, like fingerprint or USB).

## Install

Dependencies: You need a C compiler (e.g., gcc) and your distribution's PAM development headers (often named libpam0g-dev, pam-devel, or libpam-dev). Then run

```bash
make
sudo make install
```

## Setup & Example

Instead of placing modules directly in your main PAM file, create separate sub-configs for each method, then map them using `pam_parallel.so`.

**Step A: Create method sub-configs**

1. Create `/etc/pam.d/sub-pwd` (for your password):
```text
auth sufficient pam_unix.so try_first_pass
```

2. Create `/etc/pam.d/sub-fp` (for your fingerprint):
```text
auth sufficient pam_fprintd.so
```

3. Create `/etc/pam.d/sub-usb` (for your usb device):
```text
auth sufficient pam_usb.so
```

**Step B: Update your target application**

Edit the PAM file for the app you want to configure (e.g., `/etc/pam.d/sudo` or `/etc/pam.d/swaylock`) and replace/append the existing `auth` rules with:

```text
auth sufficient pam_parallel.so fg=sub-pwd bg=sub-fp,sub-usb
```

*Note: You can specify multiple background modules separated by commas (no spaces): `bg=sub-fp,sub-usb`*

## Uninstall

Revert the `pam.d` files appropriately, then run:

```bash
sudo make uninstall
```

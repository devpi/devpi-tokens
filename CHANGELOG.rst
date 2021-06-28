0.5.0 (Unreleased)
==================

- ask for confirmation when using unknown permissions

- add option to write generated token to a file

- show list of known devpi-server permissions in help

- show helpful error when ``delta`` dependency is missing

- fix timezone issue in expiration calculation

- show human readable expiration if possible


0.4.0 (Unreleased)
==================

- unify command naming by using prefix

- add ``token-delete`` command

- add ``token-derive`` command

- add ``token-list`` command

- allow ``root`` or users from ``--restrict-modify`` to create tokens for
  other users, and with no expiration

- add allowed restriction to tokens

- add expiration to tokens

- add indexes restriction to tokens

- add projects restriction to tokens


0.3.0 (Unreleased)
==================

- add ``inspect-token`` command

- verify login status when using ``token-login``


0.2.0 (Unreleased)
==================

- use new hook and derived keys


0.1.0 (Unreleased)
==================

- initial proof of concept

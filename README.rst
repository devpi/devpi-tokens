====================================================
devpi-tokens: authentication tokens plugin for devpi
====================================================

This plugin adds a authentication tokens to `devpi-server`_ and supporting commands to `devpi-client`_.

.. _devpi-server: http://pypi.python.org/pypi/devpi-server
.. _devpi-client: http://pypi.python.org/pypi/devpi-client


Installation
============

``devpi-tokens`` needs to be installed alongside ``devpi-server`` to enable authentication tokens.

On client machines the usage of tokens works without the plugin.
The creation of tokens requires the ``devpi-tokens`` plugin to be installed alongside ``devpi-client``.
The plugin also adds several commands to inspect and derive tokens with restricted permissions.

You can install it with::

    pip install devpi-tokens

There is no configuration needed as ``devpi-server`` and ``devpi-client`` will automatically discover the plugin through calling hooks using the setuptools entry points mechanism.


Motivation
==========

The default authentication mechanism of devpi requires a username and password.
With that the authenticated user has a fixed set of permissions.
Especially for CI systems this is too inflexible.
There is also the risk of leaking the password in log output and other sources.

With ``devpi-tokens`` it is possible to create additional authentication tokens per user.
These tokens can have a limited set of permissions.
It is impossible to modify any user data with a token.

It is possible to derive tokens from existing ones and limit the permission set even further without requiring contact with the server.

The plugin builds on `macaroons`_.

.. _macaroons: https://pypi.org/project/pymacaroons/


Usage
=====

The ``devpi-tokens`` plugin adds new commands when installed alongside ``devpi-client``.

.. warning::

    Be aware that tokens need to be handled like passwords.
    They should always be hidden.
    The best way is to store them on the file system with proper permissions and pass them with the ``-f`` option to commands like ``token-login``.
    It is also best practice to limit their usage time with ``-e/--expires``,
    so any leaked token can only be used until that time.
    Used tokens should also be as limited in scope as possible.

``token-create``
    Create a new token for a user.
    By default the token is created in the scope of the current user.
    Administration users like ``root`` can create tokens for other users with the ``-u/--user`` option.
    The token has a default expiration date of one year,
    but that can be changed with the ``-e/--expires`` option.
    With the ``-a/--allowed``, ``-i/--indexes`` and ``-p/--projects`` options the scope of the token can be further limited.

``token-delete``
    Delete an existing token.
    Any derived tokens will be invalidated as well.

``token-derive``
    Takes an existing token and derives a new one from it.
    This allows to limit the scope of the token further than the original one.

``token-inspect``
    Show information about the given token.
    This includes any expiration times and permission limitations etc.

``token-list``
    Show a list of tokens for a user from the server.
    This only shows initial tokens created with ``token-create``.
    Derived tokens by definition can not be listed,
    as they do not require contact to the server.

``token-login``
    Use a token for login with ``devpi-client``.
    This is also useful to login longer than the default 10 hours by creating a token with a longer expiration time and no further restrictions.
    It is impossible to modify any user data when logged in like this, as tokens never have user manipulation permissions.

Copy as Jsoup plugin for Burp Suite
======================================

This extension was heavily based on [Copy as Requests][1] - including this ripped off readme.

Copies selected request(s) as Java Jsoup requests.

Building
--------

- Download the [Burp Extender API][2] and unpack it into `src`
- Execute `ant`, and you'll have the plugin ready in `burp-requests.jar`

Dependencies
------------

- JDK 1.7+ (tested on AdoptJDK `14.0.2`, MacOS)
- Apache ANT (Debian/Ubuntu package: `ant`)

License
-------

The whole project is available under MIT license, see `LICENSE.txt`,
except for the [Mjson library][3], where

> The source code is a single Java file. [...] Some of it was ripped
> off from other projects and credit and licensing notices are included
> in the appropriate places. The license is Apache 2.0.

[1]: https://github.com/silentsignal/burp-requests/blob/master/README.md
[2]: https://portswigger.net/burp/extender/api/burp_extender_api.zip
[3]: https://bolerio.github.io/mjson/
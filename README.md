# Neve Pro Addon: Content Protection Password Bypass

A security issue in the **Elementor Booster → Content Protection**
extension of Neve Pro Addon allowed unauthenticated visitors to bypass
password protection on Elementor widgets by supplying an arbitrary
client-controlled cookie.

> **Status:** Fixed\
> **Fixed version reported by Themeisle:** Neve 3.2.15\
> **Affected version reproduced:** Neve Pro Addon 3.2.14\
> **CVE:** Not assigned

## Overview

The Content Protection extension allows a site owner to require a
password before displaying an Elementor widget's content.

In the tested version, the server-side rendering logic checked whether
the `neb_content_protection_password` cookie existed, rather than
validating the cookie's value. Because visitors control the cookies sent
with their requests, an unauthenticated visitor could set an arbitrary
value for this cookie and cause the protected widget content to be
returned.

The same cookie could unlock multiple password-protected widgets,
including widgets configured with different passwords.

## Vulnerability details

  ---------------------------------------------------------------------------
  Field                               Details
  ----------------------------------- ---------------------------------------
  Product                             Neve Pro Addon (`neve-pro-addon`)

  Vendor                              Themeisle

  Affected component                  Elementor Booster → Content Protection

  Affected version tested             3.2.14

  Fixed version                       Neve 3.2.15, as confirmed by Themeisle

  Vulnerability                       Password-protection bypass /
                                      unauthorized content disclosure

  Authentication required             None

  CWE                                 CWE-287: Improper Authentication;
                                      CWE-807: Reliance on Untrusted Inputs
                                      in a Security Decision

  Reporter-assessed severity          CVSS 3.1: 7.5 (High)

  CVSS vector                         `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

  CVE                                 Not assigned
  ---------------------------------------------------------------------------

## Technical description

The vulnerable code was in:

``` text
neve-pro-addon/includes/modules/elementor_booster/extensions/content_protection.php
```

The relevant condition was:

``` php
if ( isset( $_COOKIE['neb_content_protection_password'] ) || $unlocked ) {
    $html .= $content;
}
```

This condition treats the presence of the cookie as proof that the
visitor has passed password verification. It does not validate the
cookie value or bind the unlock state to a particular widget.

A visitor could therefore send a request containing:

``` http
Cookie: neb_content_protection_password=1
```

and bypass the password gate in the tested configuration.

## Proof of concept

The repository's `poc.py` demonstrates the behavior against a test
installation. Run it only against systems you own or are explicitly
authorized to test.

Example:

``` bash
python3 poc.py http://127.0.0.1:8080/page-with-protected-widget/
```

The PoC is intended for verification of the specific behavior described
in this report. Do not use it to access content on systems without
authorization.

## Video demonstration

The following video demonstrates the proof of concept:

[![Watch the PoC
demonstration](https://img.youtube.com/vi/0fD6tedcdyE/0.jpg)](https://youtu.be/0fD6tedcdyE)

[Watch on YouTube](https://youtu.be/0fD6tedcdyE)

## Impact

An unauthenticated visitor could retrieve content that a site owner
intended to protect with the Elementor widget password feature. Since
the cookie was not scoped to an individual widget, one forged cookie
could unlock multiple protected widgets.

The demonstrated impact is unauthorized **read access to password-gated
widget content**. This report does not claim WordPress account
compromise, privilege escalation, or write access.

The issue was reproduced with Elementor 3.21.4. The behavior was not
reproduced in a separate test configuration using Elementor 4.3.5, where
the relevant frontend widget-rendering filter did not execute. The
complete range of affected Neve Pro Addon and Elementor versions has not
been established.

## Remediation

Themeisle confirmed that a fix was released in **Neve 3.2.15**.

Site owners should update to the fixed release and verify that their
installed Neve/Neve Pro Addon package is current. Until updated, do not
rely on the password mode of the affected Content Protection feature as
a security boundary for sensitive information.

The underlying security requirement is that an unlock decision must be
based on server-verifiable proof of successful password validation, not
merely the presence of a client-controlled cookie. Unlock tokens should
also be scoped to the relevant protected resource.

## Disclosure timeline

  -----------------------------------------------------------------------
  Date                                Event
  ----------------------------------- -----------------------------------
  2026-10-24                          Vulnerability identified and
                                      reproduced in a private local
                                      Docker test environment.

  2026-10-25                          Report and supporting PoC/video
                                      submitted to Themeisle.

  2026-10-27                          Themeisle acknowledged the report
                                      and said it had been forwarded
                                      internally for investigation.

  2026-11-06                          Themeisle support confirmed that
                                      the fix had been released in Neve
                                      3.2.15.

  2026-11-07                          Public write-up prepared after the
                                      vendor's fix confirmation.
  -----------------------------------------------------------------------

## Credits

Discovered and reported by **4m3rr0r**.

-   GitHub: https://github.com/4m3rr0r
  
All testing was performed in a private, reporter-controlled environment
using test content.

## Disclaimer

This information is published for educational and defensive security
purposes. The proof of concept should only be used on systems for which
you have explicit authorization.

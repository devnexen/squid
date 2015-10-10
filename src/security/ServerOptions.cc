/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Packable.h"
#include "globals.h"
#include "security/ServerOptions.h"

#if HAVE_OPENSSL_ERR_H
#include <openssl/err.h>
#endif
#if HAVE_OPENSSL_X509_H
#include <openssl/x509.h>
#endif

Security::ServerOptions::ServerOptions(const Security::ServerOptions &s) :
    dh(s.dh),
    dhParamsFile(s.dhParamsFile),
    eecdhCurve(s.eecdhCurve)
{
}

void
Security::ServerOptions::parse(const char *token)
{
    if (!*token) {
        // config says just "ssl" or "tls" (or "tls-")
        encryptTransport = true;
        return;
    }

    // parse the server-only options
    if (strncmp(token, "dh=", 3) == 0) {
        // clear any previous Diffi-Helman configuration
        dh.clear();
        dhParamsFile.clear();
        eecdhCurve.clear();

        dh.append(token + 3);

        if (!dh.isEmpty()) {
            auto pos = dh.find(':');
            if (pos != SBuf::npos) {  // tls-dh=eecdhCurve:dhParamsFile
                eecdhCurve = dh.substr(0,pos);
                dhParamsFile = dh.substr(pos+1);
            } else {  // tls-dh=dhParamsFile
                dhParamsFile = dh;
                // empty eecdhCurve means "do not use EECDH"
            }
        }

    } else if (strncmp(token, "dhparams=", 9) == 0) {
        if (!eecdhCurve.isEmpty()) {
            debugs(83, DBG_PARSE_NOTE(1), "UPGRADE WARNING: EECDH settings in tls-dh= override dhparams=");
            return;
        }

        // backward compatibility for dhparams= configuration
        dh.clear();
        dh.append(token + 9);
        dhParamsFile = dh;

    } else {
        // parse generic TLS options
        Security::PeerOptions::parse(token);
    }
}

void
Security::ServerOptions::dumpCfg(Packable *p, const char *pfx) const
{
    // dump out the generic TLS options
    Security::PeerOptions::dumpCfg(p, pfx);

    if (!encryptTransport)
        return; // no other settings are relevant

    // dump the server-only options
    if (!dh.isEmpty())
        p->appendf(" %sdh=" SQUIDSBUFPH, pfx, SQUIDSBUFPRINT(dh));
}

void
Security::ServerOptions::updateContextEecdh(Security::ContextPointer &ctx)
{
    if (eecdhCurve.isEmpty())
        return;

    debugs(83, 9, "Setting Ephemeral ECDH curve to " << eecdhCurve << ".");

#if USE_OPENSSL && OPENSSL_VERSION_NUMBER >= 0x0090800fL && !defined(OPENSSL_NO_ECDH)
    int nid = OBJ_sn2nid(eecdhCurve.c_str());
    if (!nid) {
        debugs(83, DBG_CRITICAL, "ERROR: Unknown EECDH curve '" << eecdhCurve << "'");
        return;
    }

    auto ecdh = EC_KEY_new_by_curve_name(nid);
    if (!ecdh) {
        auto ssl_error = ERR_get_error();
        debugs(83, DBG_CRITICAL, "ERROR: Unable to configure Ephemeral ECDH: " << ERR_error_string(ssl_error, NULL));
        return;
    }

    if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 0) {
        auto ssl_error = ERR_get_error();
        debugs(83, DBG_CRITICAL, "ERROR: Unable to set Ephemeral ECDH: " << ERR_error_string(ssl_error, NULL));
    }
    EC_KEY_free(ecdh);
#else
    debugs(83, DBG_CRITICAL, "ERROR: EECDH is not available in this build." <<
           " Please link against OpenSSL>=0.9.8 and ensure OPENSSL_NO_ECDH is not set.");
#endif
}


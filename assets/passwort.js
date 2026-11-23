/*
 * Rezeptly – Seite „Neues Passwort“ (passwort.html, E-150). Von Hand gepflegt.
 * Reine Logik ohne Seitenzugriff, getestet in src/domain/auth/__tests__/passwortSeite.test.ts.
 * web/rezeptbuch/assets/passwort.js muss gleich sein (prüft derselbe Test).
 *
 * Der Link in der Mail lautet https://rezeptly.app/passwort#<Bestätigungslink von Supabase>.
 * Das Fragment (#…) schickt der Browser nie an den Server; ein Mail-Scanner, der den Link
 * vorab aufruft, verbraucht also nichts. Die Seite tauscht den Code erst, wenn man auf
 * „Passwort speichern“ tippt (verifyOtp mit token_hash, geräteunabhängig), oder reicht
 * den unveränderten Bestätigungslink an die App weiter (Weg wie bisher, PKCE, E-069).
 * Nur öffentliche Schlüssel (publishable), nie der geheime Schlüssel.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.RezeptlyPasswort = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /** Erlaubte Supabase-Projekte; dev nur, wenn die Seite lokal läuft (Test am PC) */
  var PROJECTS = {
    'mslrprrhllzillwejkbo.supabase.co': { key: 'sb_publishable_42492Bk9AxldvvXHCmLIPw_ywYxUtEh', localOnly: false },
    'afrmtrtwesgghsvozzgv.supabase.co': { key: 'sb_publishable_1hk9u5P_n25E3hbcy5Pqvw_0R7GLs5S', localOnly: true },
  };
  /** App-Schemata aus app.config.ts */
  var APP_SCHEMES = ['rezeptbuch', 'rezeptbuch-preview', 'rezeptbuch-development'];
  var LOCAL_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

  /** Längen in Zeichen (Codepunkten) wie zod in der App; gleich wie MIN_PASSWORD_LENGTH / password_requirements in der App (src/domain/auth/validation.ts) */
  var MIN_LENGTH = 8;
  var MAX_BYTES = 72;

  var TEXTS = {
    passwordTooShort: 'Das Passwort braucht mindestens 8 Zeichen.',
    passwordNeedsLetterAndDigit: 'Das Passwort braucht mindestens einen Buchstaben (a–z) und eine Ziffer.',
    passwordTooLong: 'Das Passwort ist zu lang: höchstens 72 Zeichen, Umlaute und Sonderzeichen zählen doppelt.',
    passwordsDiffer: 'Die beiden Passwörter stimmen nicht überein.',
    samePassword: 'Das neue Passwort muss sich vom alten unterscheiden.',
    weakPassword: 'Dieses Passwort ist zu leicht zu erraten. Bitte wähle ein anderes.',
    network: 'Keine Internetverbindung. Bitte prüfe dein Internet und versuche es noch einmal.',
    rateLimited: 'Zu viele Versuche in kurzer Zeit. Bitte warte ein paar Minuten.',
    unknown: 'Etwas ist schiefgelaufen. Bitte versuche es noch einmal.',
  };

  function utf8Length(text) {
    var bytes = 0;
    for (var i = 0; i < text.length; i++) {
      var c = text.codePointAt(i);
      if (c > 0xffff) i++; // Ersatzpaar: zweites Zeichen überspringen
      bytes += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
    }
    return bytes;
  }

  /**
   * Prüft die Eingaben wie die App. Liefert null oder { field: 'password'|'passwordRepeat', message }.
   */
  function validatePasswords(password, repeat) {
    var error = null;
    var chars = Array.from(password).length;
    if (chars < MIN_LENGTH) error = TEXTS.passwordTooShort;
    else if (chars > MAX_BYTES || utf8Length(password) > MAX_BYTES) error = TEXTS.passwordTooLong;
    else if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) error = TEXTS.passwordNeedsLetterAndDigit;
    if (error) return { field: 'password', message: error };
    if (password !== repeat) return { field: 'passwordRepeat', message: TEXTS.passwordsDiffer };
    return null;
  }

  /**
   * Liest den Bestätigungslink aus dem Fragment der Seite.
   * Ergebnis: { ok: true, apiOrigin, key, tokenHash, appLink } oder { ok: false }.
   * appLink ist der unveränderte Bestätigungslink, wenn er zurück in eine der Apps führt, sonst null.
   */
  function readRecoveryLink(hash, pageHostname) {
    var raw = String(hash || '').replace(/^#/, '');
    if (!/^https:/i.test(raw)) {
      try {
        raw = decodeURIComponent(raw);
      } catch (e) {
        return { ok: false };
      }
    }
    var url;
    try {
      url = new URL(raw);
    } catch (e) {
      return { ok: false };
    }
    var project = Object.prototype.hasOwnProperty.call(PROJECTS, url.hostname) ? PROJECTS[url.hostname] : null;
    if (url.protocol !== 'https:' || !project || url.port !== '' || url.username || url.password) return { ok: false };
    if (project.localOnly && LOCAL_HOSTS.indexOf(String(pageHostname)) === -1) return { ok: false };
    if (url.pathname !== '/auth/v1/verify' || url.searchParams.get('type') !== 'recovery') return { ok: false };
    var token = url.searchParams.get('token') || '';
    // Bei PKCE stellt Supabase dem Wert „pkce_“ voran. Der Server sucht genau diesen Wert
    // (verifyTokenHash, exakter Vergleich) – also unverändert weitergeben (Fehler vom 23.11.:
    // ohne Vorsilbe kam „Link nicht mehr gültig“).
    var tokenHash = token;
    if (!/^[A-Za-z0-9_-]{16,200}$/.test(tokenHash)) return { ok: false };

    var appLink = null;
    var redirect = url.searchParams.get('redirect_to') || '';
    var scheme = /^([a-z][a-z0-9+.-]*):\/\/auth\/callback(?:[/?#]|$)/i.exec(redirect);
    if (scheme && APP_SCHEMES.indexOf(scheme[1]) !== -1) appLink = url.toString();

    return { ok: true, apiOrigin: url.origin, key: project.key, tokenHash: tokenHash, appLink: appLink };
  }

  /** App-Schema aus dem Bestätigungslink, für „Rezeptly öffnen“ nach dem Speichern */
  function appSchemeOf(appLink) {
    if (!appLink) return 'rezeptbuch';
    var redirect = new URL(appLink).searchParams.get('redirect_to') || '';
    var scheme = /^([a-z][a-z0-9+.-]*):/i.exec(redirect);
    return scheme && APP_SCHEMES.indexOf(scheme[1]) !== -1 ? scheme[1] : 'rezeptbuch';
  }

  /** Handy oder Tablet (nur dort kann die App installiert sein) */
  function isMobile(userAgent, maxTouchPoints) {
    var ua = String(userAgent || '');
    // iPad meldet sich seit iPadOS 13 als Mac, hat aber Touch
    return /iPhone|iPad|iPod|Android/i.test(ua) || (/Macintosh/.test(ua) && Number(maxTouchPoints) > 1);
  }

  /** Fehlerantwort von Supabase Auth in verständlichen Text (wie src/domain/auth/errors.ts) */
  function errorKind(status, body) {
    var code = body && (body.error_code || body.code);
    if (code === 'otp_expired' || code === 'flow_state_expired' || code === 'flow_state_not_found') return { kind: 'expired' };
    if (code === 'same_password') return { kind: 'field', message: TEXTS.samePassword };
    if (code === 'weak_password') return { kind: 'field', message: TEXTS.weakPassword };
    if (code === 'validation_failed') return { kind: 'field', message: TEXTS.passwordTooLong };
    if (code === 'session_not_found' || code === 'session_expired' || code === 'bad_jwt') return { kind: 'expired' };
    if (status === 429 || code === 'over_request_rate_limit' || code === 'too_many_requests') {
      return { kind: 'message', message: TEXTS.rateLimited };
    }
    // verify antwortet bei unbekanntem oder verbrauchtem Code mit 403 bzw. 401
    if (status === 401 || status === 403) return { kind: 'expired' };
    return { kind: 'message', message: TEXTS.unknown };
  }

  function call(fetchImpl, link, method, path, accessToken, body) {
    var headers = { apikey: link.key, 'Content-Type': 'application/json' };
    if (accessToken) headers.Authorization = 'Bearer ' + accessToken;
    return fetchImpl(link.apiOrigin + '/auth/v1' + path, {
      method: method,
      headers: headers,
      body: body ? JSON.stringify(body) : undefined,
      credentials: 'omit',
      cache: 'no-store',
    }).then(
      function (response) {
        return response
          .json()
          .catch(function () {
            return null;
          })
          .then(function (json) {
            return response.ok ? { ok: true, data: json } : { ok: false, error: errorKind(response.status, json) };
          });
      },
      function () {
        return { ok: false, error: { kind: 'message', message: TEXTS.network } };
      },
    );
  }

  /** Tauscht den Code gegen eine kurze Sitzung (verifyOtp, type recovery). */
  function verifyRecovery(fetchImpl, link) {
    return call(fetchImpl, link, 'POST', '/verify', null, { type: 'recovery', token_hash: link.tokenHash }).then(function (result) {
      if (!result.ok) return result;
      var token = result.data && result.data.access_token;
      return token ? { ok: true, accessToken: token } : { ok: false, error: { kind: 'message', message: TEXTS.unknown } };
    });
  }

  /** Setzt das neue Passwort (updateUser). */
  function savePassword(fetchImpl, link, accessToken, password) {
    return call(fetchImpl, link, 'PUT', '/user', accessToken, { password: password }).then(function (result) {
      return result.ok ? { ok: true } : result;
    });
  }

  /** Meldet die Sitzung dieser Seite wieder ab; andere Geräte bleiben angemeldet. Fehler egal. */
  function signOutHere(fetchImpl, link, accessToken) {
    return call(fetchImpl, link, 'POST', '/logout?scope=local', accessToken, null).then(function () {});
  }

  return {
    TEXTS: TEXTS,
    utf8Length: utf8Length,
    validatePasswords: validatePasswords,
    readRecoveryLink: readRecoveryLink,
    appSchemeOf: appSchemeOf,
    isMobile: isMobile,
    errorKind: errorKind,
    verifyRecovery: verifyRecovery,
    savePassword: savePassword,
    signOutHere: signOutHere,
  };
});

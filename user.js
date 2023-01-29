/** INDEX: 
 *  TITLE
 *  STARTUP
 *  Permissions
 *  Telemetry
 *  GEOLOCATION
 *  Pocket
 *  DNS / DoH / PROXY / SOCKS / IPv6
 *  HTTPS (SSL/TLS / OCSP / CERTS / HPKP)
 *  NETWORK(HTTP) / SECURITY
 *  PLUGINS / MEDIA / WEBRTC
 *  PASSWORD / SIGNIN
 *  FONTS
 *  DOWNLOADS
 *  EXTENSIONS
 *  TAB CONTAINERS
 *  UI
 *  STUDIES
 *  CRASH REPORTS
 *  LOCATION BAR / SEARCH BAR / FORM
 *  DISK CACHE
 *  PRIVACY PREFRENCES
 *  MISCELLANEOUS
 *  ETP (ENHANCED TRACKING PROTECTION)
 *  RFP (RESIST FINGERPRINTING)
 *  DOM (DOCUMENT OBJECT MODEL)
 *  HEADERS / REFERERS
 *  FINGERPRINTING
 *  OPTIONAL HARDENING
 * **/

/** STARTUP **/
// change startup page
user_pref("browser.startup.page", 0); // 0=blank, 1=home, 2=last visited page, 3=resume previous session
user_pref("browser.startup.homepage", "about:blank"); // or you can change it to about:home or custom URL
user_pref("browser.newtabpage.enabled", false); // true=Firefox Home (default), false=blank page
// user_pref("browser.newtab.preload", "");
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("app.update.auto", false);
// Disable Firefox account(For those who want to completely disable this feature)
user_pref("identity.fxaccounts.enabled", false);
user_pref("browser.toolbars.bookmarks.visibility", "never");
user_pref("browser.region.update.region", "CH");
user_pref("browser.search.region", "CH");
// set preferred language for displaying pages
user_pref("intl.accept_languages", "en-GB, en");
user_pref("javascript.use_us_english_locale", false); // can be true
//disable welcome notices 
user_pref("browser.startup.homepage_override.mstone", "ignore");
//disable What's New toolbar icon
user_pref("browser.messaging-system.whatsNewPanel.enabled", true); // you can change it to false

// disable favicons in shortcuts
// URL shortcuts use a cached randomly named .ico file which is stored in your
// profile/shortcutCache directory. The .ico remains after the shortcut is deleted
// If set to false then the shortcuts use a generic Firefox ico
user_pref("browser.shell.shortcutFavicons", false);
// disable about:config warning
user_pref("browser.aboutConfig.showWarning", false);
// disable topsites shortcuts in Firefox Home page
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
// disable firefox logo and search bar in Firefox Home page
user_pref("browser.newtabpage.activity-stream.showSearch", true);
// for just disable firefox logo use this
user_pref("browser.newtabpage.activity-stream.logowordmark.alwaysVisible", true);
// deactive more from mozilla in preferences
user_pref("browser.preferences.moreFromMozilla", false);
/************************* END OF TITLE *******************************/

/** Permissions **/
// 0=always ask (default), 1=allow, 2=block
user_pref("permissions.default.geo", 2);
user_pref("permissions.default.camera", 2);
user_pref("permissions.default.microphone", 2);
user_pref("permissions.default.desktop-notification", 2);
user_pref("permissions.default.xr", 2); // Virtual Reality

user_pref("pdfjs.migrationVersion", 2);
/************************* END OF TITLE *******************************/

/** TELEMETRY **/
// [SETTING] General>Browsing>Recommend extensions as you browse
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
// [SETTING] General>Browsing>Recommend features as you browse
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);
user_pref("toolkit.telemetry.pioneer-new-studies-available", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false); // disable Firefox Home (Activity Stream) telemetry
user_pref("browser.ping-centre.telemetry", false); // disable PingCentre telemetry (used in several System Add-ons)
user_pref("devtools.onboarding.telemetry.logged", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.server", "");
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.previousBuildID", "");
user_pref("toolkit.telemetry.cachedClientID", "");
// disable new data submission
user_pref("datareporting.policy.dataSubmissionEnabled", false);
// disable Health Reports
user_pref("datareporting.healthreport.uploadEnabled", false);
// Toolkit Telemetry
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false); 
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
// disable Telemetry Coverage
user_pref("toolkit.telemetry.coverage.opt-out", true);
user_pref("toolkit.coverage.opt-out", true);
user_pref("toolkit.coverage.endpoint.base", "");
/************************* END OF TITLE *******************************/

/** GEOLOCATION **/
// Disable geolocation support(This prevents websites from accessing your location information.)
user_pref("geo.enabled", false);
// use Mozilla geolocation service instead of Google(https://www.googleapis.com/geolocation/v1/geolocate?key=%GOOGLE_LOCATION_SERVICE_API_KEY%) if permission is granted
user_pref("geo.provider.network.url", "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%");
// Optionally enable logging to the console (defaults to false)
user_pref("geo.provider.network.logging.enabled", false); // HIDDEN PREF
// disable using the OS's geolocation service ***/
user_pref("geo.provider.ms-windows-location", false); // WINDOWS OS
user_pref("geo.provider.use_corelocation", false); // MAC OS
user_pref("geo.provider.use_gpsd", false); // LINUX OS
user_pref("geo.provider.use_geoclue", false); // LINUX OS & Firefox>102

user_pref("browser.region.network.url", ""); // defult address: https://location.services.mozilla.com/v1/country?key=%MOZILLA_API_KEY%
user_pref("browser.region.update.enabled", false);
/************************* END OF TITLE *******************************/

/** POCKET **/
user_pref("browser.newtabpage.activity-stream.feeds.discoverystreamfeed", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includePocket", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);
user_pref("extensions.pocket.enabled", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includePocket", false);
// disable Recommend by pocket (top stories) in Firefox Home page
user_pref("browser.newtabpage.activity-stream.feeds.system.topstories", false);
/************************* END OF TITLE *******************************/

/** DNS / DoH / PROXY / SOCKS / IPv6 **/
// disable IPv6
// IPv6 can be abused, especially with MAC addresses, and can leak with VPNs: assuming
// your ISP and/or router and/or website is IPv6 capable. Most sites will fall back to IPv4
// Firefox telemetry (Sept 2022) shows ~8% of successful connections are IPv6
// This is an application level fallback. Disabling IPv6 is best done at an
// OS/network level, and/or configured properly in VPN setups. If you are not masking your IP,
// then this won't make much difference. If you are masking your IP, then it can only help.
user_pref("network.dns.disableIPv6", true);
// set the proxy server to do any DNS lookups when using SOCKS
// in Tor, this stops your local DNS server from knowing your Tor destination
// as a remote Tor node will handle the DNS request
user_pref("network.proxy.socks_remote_dns", true);
// disable GIO as a potential proxy bypass vector
// Gvfs/GIO has a set of supported protocols like obex, network, archive, computer,
// dav, cdda, gphoto2, trash, etc. By default only sftp is accepted
user_pref("network.gio.supported-protocols", ""); //[Hidden PREF]
// disable proxy direct failover for system requests
// Default true is a security feature against malicious extensions
// user_pref("network.proxy.failover_direct", false); //default=true

// disable using UNC (Uniform Naming Convention) paths
user_pref("network.file.disable_unc_paths", true);

// disable proxy bypass for system request failures [FF95+]
// RemoteSettings, UpdateService, Telemetry [1]
// If false, this will break the fallback for some security features
// If you use a proxy and you understand the security impact
   // user_pref("network.proxy.allow_bypass", false); //default=true

// disable DNS-over-HTTPS (DoH) rollout (use oDoH or DoT)
user_pref("network.trr.mode", 3);// 0=off by default, 1=lets Firefox pick whichever is faster, 2=TRR (Trusted Recursive Resolver) first, 3=TRR only, 4=Runs the TRR resolves in parallel with the native for timing and measurements but uses only the native resolver results., 5=explicitly off
// user_pref("network.proxy.no_proxies_on", );
// user_pref("doh-rollout.home-region", "CH");
// user_pref("network.trr.uri", "");
user_pref("network.trr.default_provider_uri", "https://mozilla.cloudflare-dns.com/dns-query");
user_pref("network.trr.confirmation_telemetry_enabled", false);
// You can configure exceptions so that Firefox uses your OS resolver instead of DoH & Add domains, separated by commas
user_pref("network.trr.excluded-domains", "");

// Enable Oblivious DNS-over-HTTPS
// user_pref("network.trr.odoh.configs_uri", "");
// user_pref("network.trr.odoh.enabled", false);
// user_pref("network.trr.odoh.min_ttl", 60);
// user_pref("network.trr.odoh.proxy_uri", "");
// user_pref("network.trr.odoh.target_host", "");
// user_pref("network.trr.odoh.target_path", "");
/************************* END OF TITLE *******************************/

/** HTTPS (SSL/TLS / OCSP / CERTS / HPKP) **/
/** SSL/TLS */
// disable non-modern cipher suites
// because Passive fingerprinting. Minimal/non-existent threat of downgrade attacks
user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha", false);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha", false);
user_pref("security.ssl3.ecdhe_rsa_aes_256_sha", false);
user_pref("security.ssl3.rsa_aes_128_gcm_sha256", false); // no PFS
user_pref("security.ssl3.rsa_aes_256_gcm_sha384", false); // no PFS
user_pref("security.ssl3.rsa_aes_128_sha", false); // no PFS
user_pref("security.ssl3.rsa_aes_256_sha", false); // no PFS

// control TLS versions
// Passive fingerprinting and security
// user_pref("security.tls.version.min", 3);
// user_pref("security.tls.version.max", 4);

// disable SSL session IDs
// because Passive fingerprinting and perf costs. These are session-only
// and isolated with network partitioning and/or containers
user_pref("security.ssl.disable_session_identifiers", true);

// require safe negotiation (for check the connection is safe of we have MITM attack) [SSL_ERROR_UNSAFE_NEGOTIATION]
user_pref("security.ssl.require_safe_negotiation", true);

// disable TLS1.3 0-RTT (round-trip time)
// This data is not forward secret, as it is encrypted solely under keys derived using
// the offered PSK. There are no guarantees of non-replay between connections
user_pref("security.tls.enable_0rtt_data", false);

/** OCSP (Online Certificate Status Protocol) **/
// https://scotthelme.co.uk/revocation-is-broken/
// https://scotthelme.co.uk/ocsp-stapling-speeding-up-ssl/
// enforce OCSP fetching to confirm current validity of certificates
// 0=disabled, 1=enabled (default), 2=enabled for EV certificates only
user_pref("security.OCSP.enabled", 1);

// set OCSP fetch failures to hard-fail [SEC_ERROR_OCSP_SERVER_ERROR]
// When a CA cannot be reached to validate a cert, Firefox just continues the connection (=soft-fail)
// Setting this pref to true tells Firefox to instead terminate the connection (=hard-fail)
// It is pointless to soft-fail when an OCSP fetch fails: you cannot confirm a cert is still valid (it
// could have been revoked) and/or you could be under attack (e.g. malicious blocking of OCSP servers)
user_pref("security.OCSP.require", true);

/** CERTS / HPKP (HTTP Public Key Pinning) **/

//disable Windows 8.1's Microsoft Family Safety cert
// 0=disable detecting Family Safety mode and importing the root
// 1=only attempt to detect Family Safety mode (don't import the root)
// 2=detect Family Safety mode and import the root
user_pref("security.family_safety.mode", 0);

// enable strict PKP (Public Key Pinning)
// 0=disabled, 1=allow user MiTM (default; such as your antivirus), 2=strict
// MOZILLA_PKIX_ERROR_KEY_PINNING_FAILURE: If you rely on an AV (antivirus) to protect
// your web browsing by inspecting ALL your web traffic, then override to current default
user_pref("security.cert_pinning.enforcement_level", 2);

// enable CRLite
// 0 = disabled
// 1 = consult CRLite but only collect telemetry
// 2 = consult CRLite and enforce both "Revoked" and "Not Revoked" results
// 3 = consult CRLite and enforce "Not Revoked" results, but defer to OCSP for "Revoked"
user_pref("security.remote_settings.crlite_filters.enabled", true);
user_pref("security.pki.crlite_mode", 2);

/** MIXED CONTENT **/
// disable insecure passive content (such as images) on https pages
user_pref("security.mixed_content.block_display_content", true);

// enable HTTPS-Only mode in all windows
// user_pref("dom.security.https_only_mode", true);
// user_pref("dom.security.https_only_mode_pbm", true);
// enable HTTPS-Only mode for local resources
// user_pref("dom.security.https_only_mode.upgrade_local", true);

// disable HTTP background requests
// When attempting to upgrade, if the server doesn't respond within 3 seconds, Firefox sends
// a top-level HTTP request without path in order to check if the server supports HTTPS or not
// This is done to avoid waiting for a timeout which takes 90 seconds
user_pref("dom.security.https_only_mode_send_http_background_request", false);
/************************* END OF TITLE *******************************/

/** NETWORK(HTTP) / SECURITY **/
// Disable DNS prefetching
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);

// Disable link prefetching
user_pref("network.prefetch-next", false);
// disable predictor / prefetching
user_pref("network.predictor.enabled", false);
user_pref("network.predictor.enable-prefetch", false);
// disable link-mouseover opening connection to linked server
user_pref("network.http.speculative-parallel-limit", 0);
// disable mousedown speculative connections on bookmarks and history
user_pref("browser.places.speculativeConnect.enabled", false);
// enforce no "Hyperlink Auditing"
// user_pref("browser.send_pings", false); // DEFAULT: false

// disable HTTP2 - replaced by network.http.http2* prefs
// [WHY] Passive fingerprinting. ~50% of sites use HTTP2
user_pref("network.http.spdy.enabled", false);
user_pref("network.http.spdy.enabled.deps", false);
user_pref("network.http.spdy.enabled.http2", false);
user_pref("network.http.spdy.websockets", false); 

// Content Security Policy (CSP) is an added layer of
// security that helps to detect and mitigate certain 
// types of attacks, including Cross-Site Scripting (XSS) 
// and data injection attacks. These attacks are used for 
// everything from data theft, to site defacement, to malware distribution. 
user_pref("security.csp.enable", true);
user_pref("app.update.background.scheduling.enabled", false);
user_pref("extensions.screenshots.disabled", true);
user_pref("extensions.getAddons.cache.enabled", false); // disable extension metadata (extension detail tab)

// disable Captive Portal detection (Why ---> https://www.eff.org/deeplinks/2017/08/how-captive-portals-interfere-wireless-security-and-privacy)
user_pref("captivedetect.canonicalURL", "");//(http://detectportal.firefox.com/canonical.html)
user_pref("network.captive-portal-service.enabled", false);
// disable Network Connectivity checks
user_pref("network.connectivity-service.enabled", false);

user_pref("network.cookie.cookieBehavior", 1); // 0=All cookies are allowed. (Default), 1=Only cookies from the originating server are allowed. 2=No cookies are allowed. 3=Third-party cookies are allowed only if that site has stored cookies already from a previous visit (Firefox 22.0 and SeaMonkey 2.19 and later) (obsolete) Cookies are allowed based on the cookie P3P policy 
user_pref("network.cookie.lifetimePolicy", 2); // 0=keep until they expire (default), 1=The user is prompted for the cookie's lifetime. ,2=keep until you close Firefox ,3=The cookie lasts for the number of days specified by network.cookie.lifetime.days.
user_pref("network.cookie.lifetime.days", 1);


//disable SB (Safe Browsing)
// Do this at your own risk! These are the master switches
// Privacy & Security>Security>... Block dangerous and deceptive content ***/
   // user_pref("browser.safebrowsing.malware.enabled", false);
   // user_pref("browser.safebrowsing.phishing.enabled", false);
// disable SB checks for downloads (both local lookups + remote)
// This is the master switch for the safebrowsing.downloads* prefs (0403, 0404)
// Privacy & Security>Security>... "Block dangerous downloads" ***/
   // user_pref("browser.safebrowsing.downloads.enabled", false);
// disable SafeBrowsing checks for downloads
// To verify the safety of certain executable files, Firefox may submit some information about the
// file, including the name, origin, size and a cryptographic hash of the contents, to the Google
// Safe Browsing service which helps Firefox determine whether or not the file should be blocked
// If you do not understand this, or you want this protection, then override this ***/
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
   // user_pref("browser.safebrowsing.downloads.remote.url", ""); // Defense-in-depth
// disable SafeBrowsing checks for unwanted software
// Privacy & Security>Security>... "Warn you about unwanted and uncommon software" ***/
   // user_pref("browser.safebrowsing.downloads.remote.block_potentially_unwanted", false);
   // user_pref("browser.safebrowsing.downloads.remote.block_uncommon", false);
// disable "ignore this warning" on SafeBrowsing warnings
// If clicked, it bypasses the block for that session. This is a means for admins to enforce SB
   // user_pref("browser.safebrowsing.allowOverride", false);
/************************* END OF TITLE *******************************/

/** PLUGINS / MEDIA / WEBRTC / WEBGL **/
// webRTC disable
// Firefox desktop uses mDNS hostname obfuscation and the private IP is never exposed until
// To disable RTCPeerConnection and protect IP addresses leakage
user_pref("media.peerconnection.enabled", false);
// To disable Media Devices
user_pref("media.navigator.enabled", false);
// force WebRTC inside the proxy 
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);
// force a single network interface for ICE candidates generation
// When using a system-wide proxy, it uses the proxy interface
user_pref("media.peerconnection.ice.default_address_only", true);
// force exclusion of private IPs from ICE candidates
// This will protect your private IP even in TRUSTED scenarios after you
// grant device access, but often results in breakage on video-conferencing platforms
user_pref("media.peerconnection.ice.no_host", true);

// webgl disable
user_pref("webgl.disabled", true);
// disable webgl version 2
user_pref("webgl.enable-webgl2", false);

// disable GMP (Gecko Media Plugins)
user_pref("media.gmp-provider.enabled", false);

// disable all DRM content (EME: Encryption Media Extension)
// optionally hide the setting which also disables the DRM prompt
// e.g. Netflix, Amazon Prime, Hulu, HBO, Disney+, Showtime, Starz, DirectTV
user_pref("media.eme.enabled", false);
user_pref("browser.eme.ui.enabled", false);
// disable widevine CDM (Content Decryption Module)
user_pref("media.gmp-widevinecdm.enabled", false);
user_pref("media.gmp-widevinecdm.visible", false);
/************************* END OF TITLE *******************************/

/** PASSWORD / SIGNIN / AUTHENTICATION **/
user_pref("signon.management.page.breach-alerts.enabled", false);
// disable saving passwords
user_pref("signon.rememberSignons", false);

// disable auto-filling username & password form fields
user_pref("signon.autofillForms", false); // can leak in cross-site forms *and* be spoofed
// disable formless login capture for Password Manager
user_pref("signon.formlessCapture.enabled", false);

// limit (or disable) HTTP authentication credentials dialogs triggered by sub-resources [FF41+]
// hardens against potential credentials phishing
// 0 = don't allow sub-resources to open HTTP authentication credentials dialogs
// 1 = don't allow cross-origin sub-resources to open HTTP authentication credentials dialogs
// 2 = allow sub-resources to open HTTP authentication credentials dialogs (default)
user_pref("network.auth.subresource-http-auth-allow", 1);

// enforce no automatic authentication on Microsoft sites
user_pref("network.http.windows-sso.enabled", false);
/************************* END OF TITLE *******************************/

/** FONTS **/
// disable rendering of SVG OpenType fonts
user_pref("gfx.font_rendering.opentype_svg.enabled", false);
// limit font visibility (Windows, Mac, some Linux)
// 1=only base system fonts, 2=also fonts from optional language packs, 3=also user-installed fonts
  // user_pref("layout.css.font-visibility.private", 1);
  // user_pref("layout.css.font-visibility.standard", 1);
  // user_pref("layout.css.font-visibility.trackingprotection", 1);
/************************* END OF TITLE *******************************/

/** DOWNLOADS **/
// enable user interaction for security by always asking where to download
user_pref("browser.download.useDownloadDir", false);
// disable downloads panel opening on every download
user_pref("browser.download.alwaysOpenPanel", false);
// disable adding downloads to the system's "recent documents" list
user_pref("browser.download.manager.addToRecentDocs", false);
// enable user interaction for security by always asking how to handle new mimetypes
user_pref("browser.download.always_ask_before_handling_new_types", true);
/************************* END OF TITLE *******************************/

/** EXTENSIONS **/
// lock down allowed extension directories
// This will break extensions, language packs, themes and any other
// XPI files which are installed outside of profile and application directories
// https://mike.kaply.com/2012/02/21/understanding-add-on-scopes/
// https://archive.is/DYjAM (archived)
user_pref("extensions.enabledScopes", 5);
user_pref("extensions.autoDisableScopes", 15);
// disable bypassing 3rd party extension install prompts
user_pref("extensions.postDownloadThirdPartyPrompt", false);

// disable webextension restrictions on certain mozilla domains
// https://bugzilla.mozilla.org/buglist.cgi?bug_id=1384330,1406795,1415644,1453988 ***/
// user_pref("extensions.webextensions.restrictedDomains", ""); //(defult: accounts-static.cdn.mozilla.net,accounts.firefox.com,addons.cdn.mozilla.net,addons.mozilla.org,api.accounts.firefox.com,content.cdn.mozilla.net,discovery.addons.mozilla.org,install.mozilla.org,oauth.accounts.firefox.com,profile.accounts.firefox.com,support.mozilla.org,sync.services.mozilla.com)

// disable System Add-on updates
// It can compromise security. System addons ship with prefs, use those
// user_pref("extensions.systemAddon.update.enabled", false);
// user_pref("extensions.systemAddon.update.url", "");
/************************* END OF TITLE *******************************/

/** TAB CONTAINERS **/
// enable Container Tabs and its UI setting
user_pref("privacy.userContext.enabled", true);
user_pref("privacy.userContext.ui.enabled", true);

//set behavior on "+ Tab" button to display container menu on left click
user_pref("privacy.userContext.newTabContainerOnLeftClick.enabled", false);
/************************* END OF TITLE *******************************/

/** UI **/
// use userChrome.css file in firefox to change UI
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true);

// control "Add Security Exception" dialog on SSL warnings
// 0=do neither, 1=pre-populate url, 2=pre-populate url + pre-fetch cert (default)
user_pref("browser.ssl_override_behavior", 1);

// display advanced information on Insecure Connection warning pages
// only works when it's possible to add an exception
// it doesn't work for HSTS discrepancies
user_pref("browser.xul.error_pages.expert_bad_cert", true);

// display warning on the padlock for "broken security" (if require_safe_negotiation is false)
// Bug: warning padlock not indicated for subresources on a secure page!
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
/************************* END OF TITLE *******************************/

/** STUDIES ***/
// disable Studies
user_pref("app.shield.optoutstudies.enabled", false);

// disable Normandy/Shield
    // Shield is a telemetry system that can push and test "recipes"
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", ""); //(defult: https://normandy.cdn.mozilla.net/api/v1)
/************************* END OF TITLE *******************************/

/** CRASH REPORTS ***/
// disable Crash Reports
user_pref("breakpad.reportURL", ""); //(defult: https://crash-stats.mozilla.org/report/index/)
user_pref("browser.tabs.crashReporting.sendReport", false);
user_pref("browser.crashReports.unsubmittedCheck.enabled", false);
// enforce no submission of backlogged Crash Reports
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false); // DEFAULT: false
/************************* END OF TITLE *******************************/

/** LOCATION BAR / SEARCH BAR / FORM **/
// Don't leak URL typos to a search engine, give an error message instead
// Override this if you trust and use a privacy respecting search engine
user_pref("keyword.enabled", false);

// disable location bar domain guessing (can leak sensitive data)
user_pref("browser.fixup.alternate.enabled", false);

// disable live search suggestions (Both must be true for the location bar to work)
// Override these if you trust and use a privacy respecting search engine
user_pref("browser.urlbar.suggest.searches", false); 
user_pref("browser.search.suggest.enabled", false);

// disable location bar making speculative connections
user_pref("browser.urlbar.speculativeConnect.enabled", false);

// disable location bar leaking single words to a DNS provider **after searching**
// 0=never resolve, 1=use heuristics, 2=always resolve
user_pref("browser.urlbar.dnsResolveSingleWordsAfterSearch", 0);

// disable location bar contextual suggestions
user_pref("browser.urlbar.suggest.quicksuggest.nonsponsored", false);
user_pref("browser.urlbar.suggest.quicksuggest.sponsored", false);

// disable tab-to-search
user_pref("browser.urlbar.suggest.engines", false);

// disable search and form history
user_pref("browser.formfill.enable", false);

// disable Form Autofill
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.addresses.supported", "");
user_pref("extensions.formautofill.addresses.supportedCountries", "");
user_pref("extensions.formautofill.available", "off");
user_pref("extensions.formautofill.creditCards.available", false);
user_pref("extensions.formautofill.creditCards.supported", "");
user_pref("extensions.formautofill.creditCards.supportedCountries", "");
user_pref("extensions.formautofill.creditCards.enabled", false);
user_pref("extensions.formautofill.heuristics.enabled", false);


// disable seach terms
// Search > SearchBar > Use the address bar for search and navigation > Show search terms instead of URL...
user_pref("browser.urlbar.showSearchTerms.enabled", false);

// disable coloring of visited links
user_pref("layout.css.visited_links_enabled", false);
/************************* END OF TITLE *******************************/

/** DISK CACHE **/
// disable disk cache
// If you think disk cache helps perf, then feel free to override this
// We also clear cache on exit
// user_pref("browser.cache.disk.enable", false);

// disable media cache from writing to disk in Private Browsing
// MSE (Media Source Extensions) are already stored in-memory in PB
user_pref("browser.privatebrowsing.forceMediaMemoryCache", true);
user_pref("media.memory_cache_max_size", 65536);

// disable storing extra session data
// define on which sites to save extra session data such as form content, cookies and POST data
// 0=everywhere, 1=unencrypted sites, 2=nowhere 
user_pref("browser.sessionstore.privacy_level", 2);

// disable automatic Firefox start and session restore after reboot
user_pref("toolkit.winRegisterApplicationRestart", false);
/************************* END OF TITLE *******************************/

/** PRIVACY PREFRENCES */
user_pref("pref.privacy.disable_button.cookie_exceptions", false);
user_pref("pref.privacy.disable_button.tracking_protection_exceptions", false);
user_pref("privacy.clearOnShutdown.offlineApps", true);
user_pref("privacy.clearOnShutdown.sessions", false);
user_pref("privacy.history.custom", true);
user_pref("privacy.purge_trackers.date_in_cookie_database", "0");
user_pref("privacy.globalprivacycontrol.enabled", true);
user_pref("privacy.globalprivacycontrol.functionality.enabled", true);
user_pref("privacy.globalprivacycontrol.was_ever_enabled", true);
/************************* END OF TITLE *******************************/

/** MISCELLANEOUS **/
// prevent accessibility services from accessing your browser
// https://support.mozilla.org/en-US/kb/accessibility-services
user_pref("accessibility.force_disabled", 1); // 0 == false, 1 == true
// disable sending additional analytics to web servers
user_pref("beacon.enabled", false);
// remove temp files opened with an external application
user_pref("browser.helperApps.deleteTempFileOnExit", true);
// disable page thumbnail collection
user_pref("browser.pagethumbnails.capturing_disabled", true);

// disable UITour backend so there is no chance that a remote page can use it
user_pref("browser.uitour.enabled", false);
user_pref("browser.uitour.url", ""); //(defult: https://www.mozilla.org/%LOCALE%/firefox/%VERSION%/tour/)

// disable various developer tools in browser context
// -->Devtools>Advanced Settings>Enable browser chrome and add-on debugging toolboxes
user_pref("devtools.chrome.enabled", false);

// reset remote debugging to disabled
user_pref("devtools.debugger.remote-enabled", false);

// disable middle mouse click opening links from clipboard
user_pref("middlemouse.contentLoadURL", false);

//disable websites overriding Firefox's keyboard shortcuts [FF58+]
// 0 (default) or 1=allow, 2=block
// to add site exceptions: Ctrl+I>Permissions>Override Keyboard Shortcuts
// user_pref("permissions.default.shortcuts", 2);

// remove special permissions for certain mozilla domains
user_pref("permissions.manager.defaultsUrl", ""); //defult: resource://app/defaults/permissions

// remove webchannel whitelist
user_pref("webchannel.allowObject.urlWhitelist", ""); // defult: https://content.cdn.mozilla.net https://support.mozilla.org https://install.mozilla.org

// use Punycode in Internationalized Domain Names to eliminate possible spoofing
user_pref("network.IDN_show_punycode", true);

// enforce PDFJS, disable PDFJS scripting
// General>Applications>Portable Document Format (PDF)
user_pref("pdfjs.disabled", false);
// Disable JavaScript in PDF(To disable JavaScript support in PDF)
user_pref("pdfjs.enableScripting", false); 

// disable links launching Windows Store on Windows 8/8.1/10 (search it by yourself in windows store)
user_pref("network.protocol-handler.external.ms-windows-store", false);

//disable permissions delegation
// Currently applies to cross-origin geolocation, camera, mic and screen-sharing
// permissions, and fullscreen requests. Disabling delegation means any prompts
// for these will show/use their correct 3rd party origin
user_pref("permissions.delegation.enabled", false);
/************************* END OF TITLE *******************************/

/** ETP (ENHANCED TRACKING PROTECTION) **/

// enable ETP Strict Mode
// ETP Strict Mode enables Total Cookie Protection (TCP)
// Adding site exceptions disables all ETP protections for that site and increases the risk of
// cross-site state tracking e.g. exceptions for SiteA and SiteB means PartyC on both sites is shared
user_pref("browser.contentblocking.category", "strict");

// disable ETP web compat features
// Includes skip lists, heuristics (SmartBlock) and automatic grants
// Opener and redirect heuristics are granted for 30 days, see
// user_pref("privacy.antitracking.enableWebcompat", false);

// enable state partitioning of service workers
user_pref("privacy.partition.serviceWorkers", true);
// disable service workers
// Already isolated with TCP
// user_pref("dom.serviceWorkers.enabled", false);

// enable APS (Always Partitioning Storage)
user_pref("privacy.partition.always_partition_third_party_non_cookie_storage", true); // Default : false
user_pref("privacy.partition.always_partition_third_party_non_cookie_storage.exempt_sessionstorage", false); // Default : true

// customize ETP settings
user_pref("network.cookie.cookieBehavior", 5);
user_pref("network.http.referer.disallowCrossSiteRelaxingDefault", true);
user_pref("network.http.referer.disallowCrossSiteRelaxingDefault.top_navigation", true);
user_pref("privacy.partition.network_state.ocsp_cache", true);
user_pref("privacy.query_stripping.enabled", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);

/** SANITIZE ON SHUTDOWN: IGNORES "ALLOW" SITE EXCEPTIONS **/
// set/enforce what items to clear on shutdown
user_pref("privacy.clearOnShutdown.cache", true);     // [DEFAULT: true]
user_pref("privacy.clearOnShutdown.downloads", true); // [DEFAULT: true]
user_pref("privacy.clearOnShutdown.formdata", true);  // [DEFAULT: true]
user_pref("privacy.clearOnShutdown.history", true);   // [DEFAULT: true]
user_pref("privacy.clearOnShutdown.sessions", true);  // [DEFAULT: true]
// user_pref("privacy.clearOnShutdown.siteSettings", false);
user_pref("privacy.clearOnShutdown.offlineApps", true); 
user_pref("privacy.clearOnShutdown.cookies", true); // Cookies

// set Session Restore to clear on shutdown
// Not needed if Session Restore is not used or it is already cleared with history
// If true, this prevents resuming from crashes
   // user_pref("privacy.clearOnShutdown.openWindows", true);

// set cache to clear on exit
// We already disable disk cache and clear on exit which is more robust
user_pref("privacy.clearsitedata.cache.enabled", true);

user_pref("privacy.cpd.cache", true);    // [DEFAULT: true]
user_pref("privacy.cpd.formdata", true); // [DEFAULT: true]
user_pref("privacy.cpd.history", true);  // [DEFAULT: true]
user_pref("privacy.cpd.sessions", true); // [DEFAULT: true]
user_pref("privacy.cpd.offlineApps", false); // [DEFAULT: false]
user_pref("privacy.cpd.cookies", false);
// user_pref("privacy.cpd.downloads", true);
// user_pref("privacy.cpd.openWindows", false); // Session Restore
// user_pref("privacy.cpd.passwords", false);
//user_pref("privacy.cpd.siteSettings", false);

// reset default "Time range to clear" for "Clear Recent History"
// Firefox remembers your last choice. This will reset the value when you start Firefox
// 0=everything, 1=last hour, 2=last two hours, 3=last four hours, 4=today
//  [NOTE] Values 5 (last 5 minutes) and 6 (last 24 hours) are not listed in the dropdown,
// which will display a blank value, and are not guaranteed to work ***/
user_pref("privacy.sanitize.timeSpan", 0);

// enable Firefox to clear items on shutdown
user_pref("privacy.sanitize.sanitizeOnShutdown", true);

// DON'T TOUCH This configs
// enforce Firefox blocklist
// It includes updates for "revoked certificates"
user_pref("extensions.blocklist.enabled", true); // [DEFAULT: true]

// enforce no referer spoofing
// Spoofing can affect CSRF (Cross-Site Request Forgery) protections
// true = send the target URL as the referrer
user_pref("network.http.referer.spoofSource", false); // [DEFAULT: false]

// enforce a security delay on some confirmation dialogs such as install, open/save
user_pref("security.dialog_enable_delay", 1000); // [DEFAULT: 1000]

// enforce SmartBlock shims
// these are listed in about:compat
user_pref("extensions.webcompat.enable_shims", true); // [DEFAULT: true]

// enforce/reset TLS 1.0/1.1 downgrades to session only
user_pref("security.tls.version.enable-deprecated", false);

// enforce disabling of Web Compatibility Reporter
// Web Compatibility Reporter adds a "Report Site Issue" button to send data to Mozilla
// To prevent wasting Mozilla's time with a custom setup
user_pref("extensions.webcompat-reporter.enabled", false); // [DEFAULT: false]

// disable APIs
// Location-Aware Browsing, Full Screen, offline cache (appCache), Virtual Reality
// The API state is easily fingerprintable. Geo and VR are behind prompts
// appCache storage capability was removed in FF90. Full screen requires user interaction
user_pref("full-screen-api.enabled", true);
// user_pref("browser.cache.offline.enable", false);
/************************* END OF TITLE *******************************/

/** RFP (RESIST FINGERPRINTING) **/
// disable mozAddonManager Web API
// To allow extensions to work on AMO, you also need extensions.webextensions.restrictedDomains
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true);

// enable RFP letterboxing
// Dynamically resizes the inner window by applying margins in stepped ranges
// If you use the dimension pref, then it will only apply those resolutions.
// The format is "width1xheight1, width2xheight2, ..." (e.g. "800x600, 1000x1000")
// This is independent of RFP (4501). If you're not using RFP, or you are but
// dislike the margins, then flip this pref, keeping in mind that it is effectively fingerprintable
// DO NOT USE: the dimension pref is only meant for testing
user_pref("privacy.resistFingerprinting.letterboxing", false); // [HIDDEN PREF] 
// user_pref("privacy.resistFingerprinting.letterboxing.dimensions", ""); // [HIDDEN PREF]

// experimental RFP
// DO NOT USE unless testing
// user_pref("privacy.resistFingerprinting.exemptedDomains", "*.example.invalid");
// user_pref("privacy.resistFingerprinting.testGranularityMask", 0);

// set RFP's font visibility level
user_pref("layout.css.font-visibility.resistFingerprinting", 1);

// disable showing about:blank as soon as possible during startup
// When default true this no longer masks the RFP chrome resizing activity
user_pref("browser.startup.blankWindow", false);

// disable using system colors
// General>Language and Appearance>Fonts and Colors>Colors>Use system colors
user_pref("browser.display.use_system_colors", false);

// enforce non-native widget theme
// Security: removes/reduces system API calls, e.g. win32k API
// Fingerprinting: provides a uniform look and feel across platforms
user_pref("widget.non-native-theme.enabled", true);

// enforce links targeting new windows to open in a new tab instead
// 1=most recent window or tab, 2=new window, 3=new tab
// Stops malicious window sizes and some screen resolution leaks.
user_pref("browser.link.open_newwindow", 3);

// set all open window methods to abide by "browser.link.open_newwindow"
// 0) All things that open windows should behave according to browser.link.open_newwindow.
// 1) No things that open windows should behave according to browser.link.open_newwindow
// (essentially rendering browser.link.open_newwindow inert).
// 2) Most things that open windows should behave according to browser.link.open_newwindow,
// _except_ for window.open calls with the "feature" parameter. This will open in a new
// window regardless of what browser.link.open_newwindow is set at. (default)
user_pref("browser.link.open_newwindow.restriction", 0);

// Resist browser fingerprinting(This feature can decrease advertisers’ and online trackers’ ability to identify you.)
user_pref("privacy.resistFingerprinting", true);
// Change cookie behaviors(Isolating cookies and other stored information to the first party domain prevents cross-site tracking.)
user_pref("privacy.firstparty.isolate", true);

// set new window size rounding max values
user_pref("privacy.window.maxInnerWidth", 1600); // Default : 1000
user_pref("privacy.window.maxInnerHeight", 900); // Default : 1000

/**
   RFP covers a wide range of ongoing fingerprinting solutions.
   It is an all-or-nothing buy in: you cannot pick and choose what parts you want

   [WARNING] DO NOT USE extensions to alter RFP protected metrics

    418986 - limit window.screen & CSS media queries
   1281949 - spoof screen orientation
   1281963 - hide the contents of navigator.plugins and navigator.mimeTypes
      FF53: fixes GetSupportedNames in nsMimeTypeArray and nsPluginArray
   1330890 - spoof timezone as UTC0
   1360039 - spoof navigator.hardwareConcurrency as 2
   1369303 - spoof/disable performance API
   1333651 - spoof User Agent & Navigator API
      version: spoofed as ESR (FF102+ this is limited to Android)
      OS: JS spoofed as Windows 10, OS 10.15, Android 10, or Linux | HTTP Headers spoofed as Windows or Android
   1369319 - disable device sensor API
   1369357 - disable site specific zoom
   1337161 - hide gamepads from content
   1372072 - spoof network information API as "unknown" when dom.netinfo.enabled = true
   1333641 - reduce fingerprinting in WebSpeech API
   1369309 - spoof media statistics
   1382499 - reduce screen co-ordinate fingerprinting in Touch API
   1217290 & 1409677 - enable some fingerprinting resistance for WebGL
   1382545 - reduce fingerprinting in Animation API
   1354633 - limit MediaError.message to a whitelist
    967895 - spoof canvas and enable site permission prompt
   1372073 - spoof/block fingerprinting in MediaDevices API
      Spoof: enumerate devices as one "Internal Camera" and one "Internal Microphone"
      Block: suppresses the ondevicechange event
   1039069 - warn when language prefs are not set to "en*"
   1222285 & 1433592 - spoof keyboard events and suppress keyboard modifier events
      Spoofing mimics the content language of the document. Currently it only supports en-US.
      Modifier events suppressed are SHIFT and both ALT keys. Chrome is not affected.
   1337157 - disable WebGL debug renderer info
   1459089 - disable OS locale in HTTP Accept-Language headers (ANDROID)
   1479239 - return "no-preference" with prefers-reduced-motion
   1363508 - spoof/suppress Pointer Events
   1492766 - spoof pointerEvent.pointerid
   1485266 - disable exposure of system colors to CSS or canvas
   1494034 - return "light" with prefers-color-scheme
   1564422 - spoof audioContext outputLatency
   1595823 - return audioContext sampleRate as 44100
   1607316 - spoof pointer as coarse and hover as none (ANDROID)
   1621433 - randomize canvas (previously FF58+ returned an all-white canvas)
   1653987 - limit font visibility to bundled and "Base Fonts" (Windows, Mac, some Linux)
   1461454 - spoof smooth=true and powerEfficient=false for supported media in MediaCapabilities
    531915 - use fdlibm's sin, cos and tan in jsmath
   1756280 - enforce navigator.pdfViewerEnabled as true and plugins/mimeTypes as hard-coded values
   1692609 - reduce JS timing precision to 16.67ms
**/

/** OPTIONAL OPSEC (Disk avoidance, application data isolation, eyeballs...) **/
// start Firefox in PB (Private Browsing) mode
// user_pref("browser.privatebrowsing.autostart", true);

// disable memory cache
// capacity: -1=determine dynamically (default), 0=none, n=memory capacity in kibibytes
// user_pref("browser.cache.memory.enable", false);
// user_pref("browser.cache.memory.capacity", 0);

// disable permissions manager from writing to disk
// This means any permission changes are session only
user_pref("permissions.memory_only", true);

// disable intermediate certificate caching
// This affects login/cert/key dbs. The effect is all credentials are session-only.
// Saved logins and passwords are not available. Reset the pref and restart to return them
// user_pref("security.nocertdb", true); 

// disable favicons in history and bookmarks
// Stored as data blobs in favicons.sqlite, these don't reveal anything that your
// actual history (and bookmarks) already do. Your history is more detailed, so
// control that instead; e.g. disable history, clear history on exit, use PB mode
// favicons.sqlite is sanitized on Firefox close
// user_pref("browser.chrome.site_icons", false);

// exclude "Undo Closed Tabs" in Session Restore
// user_pref("browser.sessionstore.max_tabs_undo", 0);

// disable resuming session from crash
// for test use this command about:crashparent
// user_pref("browser.sessionstore.resume_from_crash", false);

// disable "open with" in download dialog
// Application data isolation
user_pref("browser.download.forbid_open_with", true);

/****************************** This options are up to you ************************************/
// disable location bar suggestion types
// Privacy & Security>Address Bar>When using the address bar, suggest
user_pref("browser.urlbar.suggest.history", true);
user_pref("browser.urlbar.suggest.bookmark", true);
user_pref("browser.urlbar.suggest.openpage", false);
user_pref("browser.urlbar.suggest.topsites", false);
user_pref("browser.urlbar.suggest.engines", false);
// disable location bar dropdown
// This value controls the total number of entries to appear in the location bar dropdown
user_pref("browser.urlbar.maxRichResults", 10);
// disable location bar autofill
// user_pref("browser.urlbar.autoFill", false);
// disable browsing and download history
// We also clear history and downloads on exit
// Privacy & Security>History>Custom Settings>Remember browsing and download history
user_pref("places.history.enabled", false);
// disable Windows jumplist
// user_pref("browser.taskbar.lists.enabled", false);
// user_pref("browser.taskbar.lists.frequent.enabled", false);
// user_pref("browser.taskbar.lists.recent.enabled", false);
// user_pref("browser.taskbar.lists.tasks.enabled", false);
// disable Windows taskbar preview
// user_pref("browser.taskbar.previews.enable", false); 
// discourage downloading to desktop
// 0=desktop, 1=downloads (default), 2=last used
// To set your default "downloads": General>Downloads>Save files to
user_pref("browser.download.folderList", 1);
/*******************************END*************************************/

/** DOM (DOCUMENT OBJECT MODEL) **/
// disable "Confirm you want to leave" dialog on page close
// Does not prevent JS leaks of the page close event
user_pref("dom.disable_beforeunload", false);

// prevent scripts from moving and resizing open windows
user_pref("dom.disable_window_move_resize", true);

// prevent websites to know history of your clipboard (disable Clipboard API)
// {https://www.ghacks.net/2022/08/27/websites-may-write-to-the-clipboard-in-chrome-without-user-permission/} , {https://webplatform.news/}
user_pref("dom.event.clipboardevents.enabled", false);
// disable website control over browser right-click context menu
// Just use Shift-Right-Click
user_pref("dom.event.contextmenu.enabled", true);

// block popup windows
// Privacy & Security>Permissions>Block pop-up windows
user_pref("dom.disable_open_during_load", true);
// limit events that can cause a popup (Defult: change click dblclick auxclick mousedown mouseup pointerdown pointerup notificationclick reset submit touchend contextmenu)
user_pref("dom.popup_allowed_events", "click dblclick mousedown pointerdown"); // (defult: change click dblclick auxclick mousedown mouseup pointerdown pointerup notificationclick reset submit touchend contextmenu)

// disable service workers
// user_pref("dom.serviceWorkers.enabled", false);

// disable Web Notifications (Web Notifications are behind a prompt)
// user_pref("dom.webnotifications.enabled", false);
// user_pref("dom.webnotifications.serviceworker.enabled", false);

// disable Push Notifications
// Push requires subscription
// To remove all subscriptions, reset "dom.push.userAgentID"
user_pref("dom.push.enabled", false);
user_pref("dom.push.userAgentID", "")

user_pref("dom.vr.enabled", false);
user_pref("dom.storage.next_gen", true);
/************************* END OF TITLE *******************************/

/** HEADERS / REFERERS **/
// controls whether or not to send a referrer across origins
//   0 = (default) send the referrer in all cases
//   1 = send a referrer only when the base domains are the same
//   2 = send a referrer only on same-origin
// Breakage: older modems/routers and some sites e.g banks, vimeo, icloud, instagram
// If "2" is too strict, then override to "0" and use Smart Referer extension (Strict mode + add exceptions)
user_pref("network.http.referer.XOriginPolicy", 2);
// control the amount of cross-origin information to send
// 0=send full URI (default), 1=scheme+host+port+path, 2=scheme+host+port
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

user_pref("browser.newtabpage.activity-stream.telemetry", false); // disable Firefox Home (Activity Stream) telemetry
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false); 
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.default.sites", ""); // This does not block you from adding your own

// disable recommendation pane in about:addons (uses Google Analytics)
user_pref("extensions.getAddons.showPane", false);
// disable recommendations in about:addons' Extensions and Themes panes
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
// disable personalized Extension Recommendations in about:addons and AMO
user_pref("browser.discovery.enabled", false);

//Only cross-origin referers need control
//  controls whether or not to send a referrer regardless of origin
//  0 = never send the header
//  1 = send the header only when clicking on links and similar elements
//  2 = (default) send on all requests (e.g. images, links, etc.)
user_pref("network.http.sendRefererHeader", 0);
//  controls how much referrer to send regardless of origin
//  0 = (default) send the full URL
//  1 = send the URL without its query string
//  2 = only send the origin
user_pref("network.http.referer.trimmingPolicy", 2);

// set the default referrer policy (which can be overriden by the site)
// 0=no-referer, 1=same-origin, 2=strict-origin-when-cross-origin, 3=no-referrer-when-downgrade
user_pref("network.http.referer.defaultPolicy", 2); // [DEFAULT: 2]
user_pref("network.http.referer.defaultPolicy.pbmode", 2); // [DEFAULT: 2]

// disable HTTP Alternative Services
// Already isolated with network partitioning
// alt-svc allows separation of transport routing from the origin host without using a proxy.
// AltSvc enables so-called opportunistic (unauthenticated) encryption
user_pref("network.http.altsvc.enabled", false);
user_pref("network.http.altsvc.oe", false); //{defult: false}

// enable the DNT (Do Not Track) HTTP header
user_pref("privacy.donottrackheader.enabled", true);
/************************* END OF TITLE *******************************/

/** FINGERPRINTING **/
// disable APIs
    user_pref("device.sensors.enabled", false);
   // user_pref("dom.enable_performance", false);
   // user_pref("dom.enable_resource_timing", false);
    user_pref("dom.gamepad.enabled", false);
    user_pref("dom.netinfo.enabled", false); 
    user_pref("dom.webaudio.enabled", false);
// disable other
   // user_pref("browser.display.use_document_fonts", 0);
    user_pref("browser.zoom.siteSpecific", false);
    user_pref("dom.w3c_touch_events.enabled", 0);
    user_pref("media.ondevicechange.enabled", false);
   // user_pref("media.video_stats.enabled", false);
    user_pref("media.webspeech.synth.enabled", false);
    user_pref("webgl.enable-debug-renderer-info", false);
// spoof
user_pref("dom.maxHardwareConcurrency", 2);
   // user_pref("font.system.whitelist", ""); // [HIDDEN PREF]
   // user_pref("general.appname.override", ""); // [HIDDEN PREF]
   // user_pref("general.appversion.override", ""); // [HIDDEN PREF]
   // user_pref("general.buildID.override", ""); // [HIDDEN PREF]
   // user_pref("general.oscpu.override", ""); // [HIDDEN PREF]
   // user_pref("general.platform.override", ""); // [HIDDEN PREF]
   // user_pref("general.useragent.override", ""); // [HIDDEN PREF]
   // user_pref("ui.use_standins_for_native_colors", true);
/************************* END OF TITLE *******************************/

/** OPTIONAL HARDENING **/
// Not recommended. Overriding these can cause breakage and performance issues,
// they are mostly fingerprintable, and the threat model is practically nonexistent

// disable MathML (Mathematical Markup Language)
// user_pref("mathml.disabled", true);
// disable in-content SVG (Scalable Vector Graphics)
// user_pref("svg.disabled", true);
// disable graphite
// user_pref("gfx.font_rendering.graphite.enabled", false);

// disable asm.js
// user_pref("javascript.options.asmjs", false);

// disable Ion and baseline JIT to harden against JS exploits
// When both Ion and JIT are disabled, and trustedprincipals
// is enabled, then Ion can still be used by extensions
// user_pref("javascript.options.ion", false);
// user_pref("javascript.options.baselinejit", false);
// user_pref("javascript.options.jit_trustedprincipals", true);

// disable WebAssembly
// user_pref("javascript.options.wasm", false);
// disable rendering of SVG OpenType fonts
// user_pref("gfx.font_rendering.opentype_svg.enabled", false);

//disable SHA-1 certificates
// user_pref("security.pki.sha1_enforcement_level", 1);

// disable icon fonts (glyphs) and local fallback rendering
// Breakage, font fallback is equivalency, also RFP
   // user_pref("gfx.downloadable_fonts.enabled", false);
   // user_pref("gfx.downloadable_fonts.fallback_delay", -1);
/************************* END OF TITLE *******************************/


/************************* END OF USER.JS FILE *******************************/

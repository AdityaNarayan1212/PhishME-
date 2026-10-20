/*
 * script.js - the Phishing Email Analyser.
 *
 * Privacy: this file only reads the text you paste. It never sends
 * anything anywhere, has no storage, and no tracking. The email text
 * is forgotten as soon as you close the tab.
 *
 * It is split into four parts:
 *   1. Helpers             (small tools)
 *   2. URL & header checks (reading addresses and headers as text)
 *   3. The analyser        (rules and scoring)
 *   4. The page            (buttons, samples, rendering)
 */
(function (root) {
  'use strict';

  /* ===================================================================
     1. HELPERS
     =================================================================== */

  // The most text we analyse. Anything longer is cut short.
  var MAX_INPUT = 40000;

  // Words that mean "this sentence says the opposite".
  var NEGATIONS = ['never', 'not', 'no', "don't", "doesn't", "didn't", 'will not', 'would not', 'do not', 'cannot', 'can not', 'should not', 'must not', 'avoid', 'refuse', 'protect'];

  // Words that often sit before the real word, as in "your password".
  var PRE_WORDS = ['your', 'the', 'our', 'my', 'a', 'an', 'their', 'current', 'new', 'account', 'user', 'login', 'email', 'mail', 'mailbox', 'online', 'web'];

  // A small wrapper around the browser's own text searching.
  function findAll(text, re, limit) {
    var out = [];
    var flags = re.flags.indexOf('g') === -1 ? re.flags + 'g' : re.flags;
    var r = new RegExp(re.source, flags);
    var m;
    while ((m = r.exec(text)) !== null) {
      if (m[0] === '') { r.lastIndex++; continue; }
      out.push({ text: m[0], start: m.index, end: m.index + m[0].length, groups: m.slice(1) });
      if (limit && out.length >= limit) break;
    }
    return out;
  }

  // Looks backwards from a match to see whether the sentence says the
  // opposite, for example "we will NEVER ask for your password".
  // Without this, a genuine security warning would be flagged as a
  // password request, which would be an embarrassing mistake.
  function hasNegation(text, start) {
    var w = text.slice(Math.max(0, start - 110), start).toLowerCase();
    for (var i = 0; i < NEGATIONS.length; i++) {
      var n = NEGATIONS[i];
      var re = new RegExp("(?:^|[^a-z])" + n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(?=[^a-z]|$)", "g");
      var m;
      while ((m = re.exec(w)) !== null) {
        if (w.length - m.index - m[0].length <= 60) return true;
      }
    }
    return false;
  }
  // text reads naturally when it is shown to you.
  function trimLeading(text) {
    var words = text.split(/\s+/);
    while (words.length > 1 && PRE_WORDS.indexOf(words[0].toLowerCase()) !== -1) words.shift();
    return words.join(' ');
  }
  // Builds one rule. Every rule has the same shape, which keeps the
  // code simple and the scoring table easy to read and easy to change.
  function mkRule(id, group, points, name, patterns, why, rec, opts) {
    opts = opts || {};
    return {
      id: id,
      group: group,
      points: points,
      name: name,
      patterns: patterns,
      why: why,
      rec: rec,
      ignoreNegation: opts.ignoreNegation === true,
      method: opts.method || 'Wording in the email'
    };
  }

  /* ===================================================================
     THE RULES
     Each rule says what to look for, how much it is worth, why it
     matters and what you should do about it. The point values are
     teaching defaults - they can be changed safely later.
     =================================================================== */

  var RULES = [
    mkRule('password', 'credentials', 25, 'Requests your password',
      [new RegExp('(?:send|give|share|reply with|provide|supply|enter|type|confirm|verify|submit)(?:\s+[a-z]{2,12}){0,3}\s+(?:your|the|our|my|account|login|email)\s+passwords?\b', 'i'),
       new RegExp('(?:your|the|account|login)\s+passwords?\s+(?:is|are|was|were|required|needed|required\s+to\s+verify)', 'i')],
      'Organisations do not ask for your password by email. Anyone who has it can sign in as you.',
      'Do not send your password. If you are worried, sign in yourself by typing the official address, and change your password there.'),

    mkRule('otp', 'credentials', 25, 'Requests an MFA, OTP or verification code',
      [new RegExp('(?:send|give|share|reply with|provide|supply|enter|type|read|confirm|verify)(?:\s+[a-z]{2,12}){0,3}\s+(?:your|the|our|my|this|a)\s+(?:one[ -]?time\s+)?(?:passcode|one[ -]?time[ -]code|verification[ -]code|mfa[ -]code|2fa[ -]code|sms[ -]code|security[ -]code|access[ -]code|otp|token)', 'i'),
       /\b(?:otp|mfa|2fa|two[ -]?factor|verification|security|access|authentication)\s+codes?\b/i,
       /\b(?:approve|authori[sz]e)\s+(?:the\s+)?(?:sign[ -]?in|mfa|login)\s+requests?\b/i],
      'A one-time code is the second key to your account. Sharing it lets an attacker sign in as you, even if they do not have your password.',
      'Never send a one-time code to anyone, even someone claiming to be from IT or your bank. Real staff will never ask for it.'),

    mkRule('suspension', 'pressure', 15, 'Threatens suspension, closure or termination',
      [new RegExp('(?:your|the)\s+(?:account|mailbox|email|profile|subscription|access)\b(?:\s+[a-z]{2,12}){0,3}\s+(?:will|shall|is|are|has|have)\s+(?:be\s+)?(?:suspend\w*|clos\w*|deactivat\w*|terminat\w*|block\w*|delet\w*|lock\w*|disabl\w*|restrict\w*)', 'i'),
       new RegExp('(?:suspend|clos|deactivat|terminat|block|delet|disabl)(?:\s+[a-z]{2,12}){0,3}\s+(?:your|the)\s+(?:account|mailbox|email|profile|access|subscription)', 'i')],
      'Fear of losing access pushes people into acting before they think. Real warnings give you time and never ask for secrets.',
      'Do not click the link. Open the service yourself in a new tab and check your account there.'),

    mkRule('giftcard', 'money', 20, 'Asks for gift cards or unusual payment',
      [new RegExp('(?:buy|purchase|get|grab|pay)(?:\s+[a-z0-9]{1,10}){0,4}\s+(?:gift\s*cards?|itunes\s*card\w*|google\s*play\s*card|steam\s*card|amazon\s*card|paysafecard|bitcoin|btc|ethereum|crypto\s*currency|western\s*union|moneygram|wire\s*transfer)', 'i')],
      'Gift cards, cryptocurrency and wire transfers are almost impossible to reverse. No legitimate organisation asks for payment this way.',
      'Do not buy or send anything. Stop and contact the organisation using a number or website you already trust.'),

    mkRule('invoice', 'money', 12, 'Unexpected invoice or payment pressure',
      [new RegExp('(?:an\s+)?invoice(?:\s+\d+)?\s+(?:is\s+)?due|invoice\s+(?:is\s+)?attached|unexpected\s+invoice|overdue\s+(?:invoice|payment)|payment\s+is\s+due', 'i')],
      'Fake invoices are a common way into a business. The rush to pay is what stops people checking the details.',
      'Check the invoice in your normal system, and confirm any change of details by phone using a number you already know.'),

    mkRule('bankchange', 'money', 15, 'Asks to change bank account details',
      [new RegExp('new\s+(?:bank|account)\s+(?:details|number|info|information)|bank\s+details?\s+(?:have|has)\s+chang|account\s+details?\s+(?:have|has)\s+chang|changed?\s+bank\s+(?:details|account)|update\s+(?:the|our|their)\s+(?:bank|account|payment)\s+(?:details|info)', 'i'),
       new RegExp('(?:sort\s+code|iban|swift|bic|routing\s+number|account\s+number)\s*:', 'i')],
      'Changing payment details is a favourite of business email compromise. One wrong payment can be very hard to recover.',
      'Verify the change by calling the supplier on a phone number you already have, not the one in the email. Never pay on the strength of an email alone.'),

    mkRule('urgency', 'pressure', 10, 'Strong urgency or pressure',
      [new RegExp('(?:act|respond|reply|confirm|verify|pay|complete)\s+(?:now|immediately|right\s+away|at\s+once|promptly|as\s+soon\s+as\s+possible)|\b(?:urgent|urgently|time[ -]sensitive|final\s+notice|last\s+chance|do\s+not\s+delay|failure\s+to\s+(?:comply|act|respond)|within\s+\d{1,3}\s*(?:hours?|minutes?|days?)|immediate\s+attention)\b', 'i')],
      'Pressure is used to stop you thinking. Real notices give you reasonable time and a calm way to resolve things.',
      'Slow down. A genuine message will still make sense tomorrow. Check independently rather than reacting inside the deadline.'),

    mkRule('macro', 'attachment', 20, 'Asks you to enable macros',
      [new RegExp('(?:enable|turn\s+on|allow|run|switch\s+on)(?:\s+[a-z]{2,12}){0,3}\s+(?:macros?\b|editing\b|content\b|active\s+content)', 'i')],
      'Macros are tiny programs inside a document. Enabling them is a common way for attacks to run on your machine.',
      'Do not enable macros in a document you did not expect. If you already did, tell your IT team straight away.'),

    mkRule('disablesec', 'attachment', 18, 'Asks you to disable security protection',
      [new RegExp('(?:disable|turn\s+off|switch\s+off|deactivate|allow|add\s+an\s+exception\s+for)(?:\s+[a-z]{2,12}){0,3}\s+(?:your\s+|the\s+)?(?:antivirus\b|firewall\b|windows\s+defender\b|protected\s+view\b|smart\s+screen\b|security\s+warnings?\b)', 'i')],
      'Turning off protection is what an attacker needs you to do before the real damage happens.',
      'Do not disable your protection. Report the message to your IT or security team.'),

    mkRule('harvest', 'credentials', 12, 'Credential-harvesting language',
      [new RegExp('(?:verify|confirm|validate|re-?verify|check)(?:\s+[a-z]{2,12}){0,2}\s+(?:your\s+)?(?:[a-z]{2,12}\s+){0,2}(?:account|identity|sign[ -]?in|login|details|credentials)', 'i'),
       new RegExp('(?:unusual|suspicious|unusual-looking)\s+(?:sign[ -]?in|login|activity|access)\b', 'i'),
       new RegExp('click\s+(?:on\s+)?the\s+link\s+to\s+(?:verify|confirm|validate|restore|reactivate|access)', 'i'),
       new RegExp('sign\s+in\s+(?:again\s+)?to\s+(?:avoid|prevent|verify|confirm)', 'i'),
       new RegExp('restore\s+(?:your|the)\s+(?:account|access|mailbox)', 'i'),
       new RegExp('confirm\s+(?:your\s+)?(?:mailbox|delivery|account|identity)\s+(?:access|details|information)', 'i')],
      'This is the language of a fake sign-in page. It creates a problem, then offers a convenient link that steals your login.',
      'Do not use the link. Open the service yourself from a bookmark or by typing the address, then check your account and recent activity.'),

    mkRule('impersonate', 'pressure', 8, 'Uses common impersonation language',
      [new RegExp('(?:it\\s+(?:team|department|help[ -]?desk|support)\\b|help[ -]?desk\\b|service\\s+desk\\b|system\\s+administrator\\b|system\\s+admin\\b|it\\s+administrator\\b|technical\\s+support\\b|customer\\s+care\\b|customer\\s+(?:service|support)\\b|billing\\s+(?:team|department|office)\\b|accounts\\s+department\\b|human\\s+resources\\b|hr\\s+department\\b|finance\\s+department\\b|payroll\\s+team\\b|fraud\\s+(?:team|department)\\b|compliance\\s+team\\b|managing\\s+director\\b|chief\\s+executive\\b|delivery\\s+team\\b|courier\\s+company\\b|postal\\s+service\\b|tax\\s+(?:office|refunds?\\b|department)\\b)', 'i')],
      'Attackers borrow the names of trusted teams to make a message feel official and urgent.',
      'Treat the title as decoration. Check the message through a channel you trust, such as the official website or an internal portal.'),

    mkRule('bypass', 'pressure', 12, 'Asks you to bypass normal procedures',
      [new RegExp('(?:no\s+need\s+for\s+the\s+usual\b|without\s+(?:the\s+)?usual\s+(?:approval|process|procedure|checks?)\b|skip\s+(?:the\s+)?(?:usual\s+)?(?:approval|process|procedure|checks?|verification)\b|bypass\s+(?:the\s+)?(?:usual\s+)?(?:approval|process|procedure|checks?|controls?)\b)', 'i')],
      'Asking you to skip a process is a strong sign that the process would have caught the request.',
      'Do not skip the process. Follow your organisation\'s normal approval steps, and tell your manager what was asked.'),

    mkRule('secrecy', 'pressure', 12, 'Asks you to keep the message secret',
      [new RegExp('(?:keep\s+(?:this|it)\s+(?:confidential|secret|between)\b|do\s+not\s+tell\s+(?:anyone|anybody|anyone\s+else)\b|between\s+(?:us|you\s+and\s+me)\b|do\s+not\s+mention\s+(?:this|it)\s+to\b|tell\s+no\s+one\b)', 'i')],
      'Secrecy keeps the request away from the people who would spot it straight away, such as your manager or finance team.',
      'Tell someone else about the request. Genuine business requests survive being checked.',
      { ignoreNegation: true })
  ];
  /* ===================================================================
     2. URL AND HEADER CHECKS
     These only read addresses and header lines as text. They never
     open, visit or download anything.
     =================================================================== */

  var URL_RE = /(?:https?:\/\/|hxxps?:\/\/|ftp:\/\/|www\.)[^\s<>"'()\]]+/gi;

  var SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rb.gy', 'lnkd.in', 'bl.ink', 's.id', 'v.gd', 'shorturl.at', 'short.example', 'short.example.net'];

  function extractUrls(text) {
    var out = [];
    var m;
    URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(text)) !== null) {
      out.push({ raw: m[0], index: m.index });
    }
    return out;
  }

  // Reads the important part of an address: the host, which may be a
  // normal name such as example.com, a long chain of subdomains, or a
  // bare number used instead of a name.
  function urlHost(raw) {
    var s = String(raw).replace(/[.,;:!?)]+$/, '');
    s = s.replace(/^hxxp/i, 'http');
    var m = s.match(/^(?:https?|ftp):\/\/([^\s/]+)/i);
    if (!m) m = s.match(/^www\.([^\s/]+)/i);
    if (!m) return null;
    var host = m[1];
    var at = host.lastIndexOf('@');
    if (at !== -1) host = host.slice(at + 1);
    var colon = host.indexOf(':');
    if (colon !== -1) host = host.slice(0, colon);
    host = host.replace(/\.$/, '').toLowerCase();
    return host || null;
  }

  function isIpAddress(host) {
    if (!host) return false;
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return true;
    if (/^\d+$/.test(host)) return true;
    if (host.charAt(0) === '[') return true;
    return false;
  }

  // The last two parts of a name are the real owner: in
  // login.example.com the owner is example.com, not "login".
  function registrableDomain(host) {
    if (!host) return '';
    var parts = host.replace(/^www\./, '').split('.');
    if (parts.length <= 2) return parts.join('.');
    return parts.slice(-2).join('.');
  }

  /* Reads the lines at the top of a pasted email (the headers). If
     they are missing we say so, and we never treat missing
     information as a failure. */
  function parseHeaders(text) {
    var info = {
      hasHeaders: false,
      from: '', replyTo: '', fromDomain: '', replyDomain: '',
      auth: { spf: null, dkim: null, dmarc: null }
    };

    var lines = String(text || '').split(/\r?\n/);
    var seenHeaders = 0;
    var headerLines = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (line === '') break;
      if (/^(From|To|Subject|Date|Reply-To|Return-Path|Received|Authentication-Results|ARC-Authentication-Results|Received-SPF|DKIM-Signature|Message-ID|Content-Type|MIME-Version)\s*:/i.test(line)) {
        headerLines.push(line);
        seenHeaders++;
      }
    }
    if (seenHeaders >= 2) info.hasHeaders = true;

    function grab(name) {
      var re = new RegExp('^' + name + '\s*:\s*(.+)$', 'i');
      for (var j = 0; j < headerLines.length; j++) {
        var m = headerLines[j].match(re);
        if (m) return m[1].trim();
      }
      return '';
    }

    function domainOf(value) {
      var m = String(value || '').match(/<([^>]*@[^>]*)>/);
      if (m) value = m[1];
      var at = String(value || '').lastIndexOf('@');
      if (at === -1) return '';
      return String(value).slice(at + 1).trim().replace(/[>;\"]+$/, '').toLowerCase();
    }

    info.from = grab('From');
    info.replyTo = grab('Reply-To');
    info.fromDomain = domainOf(info.from);
    info.replyDomain = domainOf(info.replyTo);

    var authText = [];
    for (var k = 0; k < headerLines.length; k++) {
      if (/^(Authentication-Results|ARC-Authentication-Results|Received-SPF)\s*:/i.test(headerLines[k])) authText.push(headerLines[k]);
    }

    ['spf', 'dkim', 'dmarc'].forEach(function (name) {
      for (var a = 0; a < authText.length; a++) {
        var re2 = new RegExp(name + '\s*=\s*(pass|fail|none|neutral|softfail|permerror|temperror)', 'i');
        var m2 = authText[a].match(re2);
        if (m2) {
          info.auth[name] = { result: m2[1].toLowerCase(), raw: m2[0] };
          return;
        }
      }
    });

    return info;
  }
  /* ===================================================================
     3. THE ANALYSER
     Builds the score up from the rules. The same text always gives
     exactly the same result - there is no randomness.
     =================================================================== */

  var UNAVAILABLE = 'Authentication status unavailable - the supplied email does not contain enough information to assess this check.';

  function analyse(inputText) {
    var report = {
      score: 0, rawScore: 0, capped: false,
      classification: { name: 'Low Risk', tone: 'low' },
      findings: [], notes: [], auth: [],
      headersFound: false, truncated: false,
      inputLength: 0, analysedLength: 0
    };

    var text = String(inputText == null ? '' : inputText);
    report.inputLength = text.length;
    if (text.length > MAX_INPUT) {
      text = text.slice(0, MAX_INPUT);
      report.truncated = true;
      report.notes.push('Only the first ' + MAX_INPUT.toLocaleString() + ' characters were analysed, so the result may be incomplete.');
    }
    report.analysedLength = text.length;
    if (!text.trim()) return report;

    function addFinding(id, name, group, points, method, evidence, why, rec) {
      report.findings.push({
        id: id, name: name, group: group, points: points, method: method,
        evidence: evidence || [], why: why, rec: rec,
        fullPoints: points, reduced: false, reducedReason: ''
      });
    }

    // --- 1. Wording rules ---
    RULES.forEach(function (r) {
      var hits = [];
      r.patterns.forEach(function (p) {
        findAll(text, p, 25).forEach(function (m) {
          if (!r.ignoreNegation && hasNegation(text, m.start)) return;
          hits.push({ text: trimLeading(m.text), start: m.start, end: m.end });
        });
      });
      if (!hits.length) return;
      hits.sort(function (a, b) { return a.start - b.start; });
      var trimmed = [];
      hits.forEach(function (h) {
        if (trimmed.length && h.start < trimmed[trimmed.length - 1].end) return;
        trimmed.push(h);
      });
      addFinding(r.id, r.name, r.group, r.points, r.method, trimmed, r.why, r.rec);
    });

    // --- 2. URL rules ---
    var urls = extractUrls(text);
    var suspiciousHits = [], shortHits = [], ipHits = [], reasons = [];

    urls.forEach(function (u) {
      var host = urlHost(u.raw);
      var raw = u.raw.replace(/[.,;:!?)]+$/, '');
      if (isIpAddress(host)) {
        ipHits.push({ text: raw, start: u.index, end: u.index + raw.length });
        return;
      }
      SHORTENERS.forEach(function (s) {
        if (host === s || host.slice(-(s.length + 1)) === '.' + s) {
          shortHits.push({ text: raw, start: u.index, end: u.index + raw.length });
        }
      });
      var why = [];
      if (/@\s*[^\s/@]+\.[a-z]{2,}/i.test(raw)) why.push('it contains something before an @ sign, which hides the real destination');
      if (/hxxp:/i.test(raw)) why.push('it is written in a "defanged" style often used in scam reports');
      if (host && host.split('.').length >= 5) why.push('it uses a long chain of names, which can make a look-alike address look genuine at first glance');
      if (why.length) {
        suspiciousHits.push({ text: raw, start: u.index, end: u.index + raw.length });
        reasons.push(raw + ' - ' + why.join('; '));
      }
    });

    if (ipHits.length) {
      addFinding('rawipurl', 'Uses a raw IP address instead of a website name', 'url', 20, 'Examining links', ipHits,
        'Genuine organisations use readable addresses. A bare number is often a throwaway server used to avoid being traced.',
        'Do not open it. If you expected a message from that organisation, go to their website yourself.');
    }
    if (shortHits.length) {
      addFinding('shortenedurl', 'Uses a link shortening service', 'url', 8, 'Examining links', shortHits,
        'Shortened links hide where they really go, so you cannot judge the destination before clicking.',
        'Do not open it. Ask the sender, in a separate message, to send the full address.');
    }
    if (suspiciousHits.length) {
      addFinding('suspiciousurl', 'Suspicious URL pattern', 'url', 15, 'Examining links', suspiciousHits,
        'This address has features that scammers commonly use to disguise where a link leads. ' + reasons.join('; '),
        'Do not open it. Read the address from right to left: the last two parts before the first single slash are the real owner.');
    }

    // --- 3. Misleading link text, only when the evidence is clear ---
    var linkHits = [];
    findAll(text, /\[([^\]]{3,120})\]\((https?:\/\/[^)\s]+)\)/gi, 20).forEach(function (m) {
      var label = m.groups[0];
      var href = m.groups[1];
      var labelUrl = label.match(/(?:https?:\/\/|www\.)[^\s]+/i);
      if (!labelUrl) return;
      var lh = urlHost(labelUrl[0]);
      var hh = urlHost(href);
      if (lh && hh && lh !== hh) {
        linkHits.push({ text: m.text, start: m.start, end: m.end });
      }
    });
    if (linkHits.length) {
      addFinding('misleading', 'Link text does not match the real link', 'url', 15, 'Comparing link text with the real address', linkHits,
        'The words promise one website but the address points somewhere else. Plain-text email loses some of this information, so this is only reported when the pasted text is clear.',
        'Judge a link by its real address, never by its label. Do not click it - go to the website yourself.');
    }

    // --- 4. Attachment rules ---
    var exeHits = [];
    findAll(text, /\.(?:exe|scr|bat|cmd|msi|dll|vbs|vbe|jse|wsf|wsh|hta|ps1|psm1|reg|jar|apk|dmg|lnk)\b/gi, 25).forEach(function (m) {
      var before = text.slice(Math.max(0, m.start - 140), m.start);
      if (/(https?:\/\/|www\.)[^\s]*$/i.test(before)) return;
      exeHits.push({ text: trimLeading(m.text), start: m.start, end: m.end });
    });
    if (exeHits.length) {
      addFinding('exe', 'Executable attachment', 'attachment', 25, 'Examining attachment names', exeHits,
        'Programme files can run code on your computer. Attackers hide them inside innocent-sounding names to get you to double-click.',
        'Do not open or run it. Delete the message, or report it to your IT team if it came through work.');
    }

    var riskyHits = [];
    findAll(text, /\.(?:docm|dotm|xlsm|xltm|pptm|ppam|zip|rar|7z|iso|img|html?|hta)\b/gi, 25).forEach(function (m) {
      var before = text.slice(Math.max(0, m.start - 140), m.start);
      if (/(https?:\/\/|www\.)[^\s]*$/i.test(before)) return;
      riskyHits.push({ text: trimLeading(m.text), start: m.start, end: m.end });
    });
    if (riskyHits.length) {
      addFinding('riskytype', 'Potentially dangerous file type', 'attachment', 15, 'Examining attachment names', riskyHits,
        'These file types can hide instructions (macros) or other files, which makes them a favourite of attackers.',
        'Only open it if you were expecting it and you are sure of the sender. Ask your IT team if you are unsure.');
    }
    // --- 5. Header rules ---
    var headerInfo = parseHeaders(text);
    report.headersFound = !!headerInfo.hasHeaders;
    var authStatuses = {};

    if (!headerInfo.hasHeaders) {
      notes.push('Email headers not detected - sender and authentication checks were skipped. Paste the full headers (From, Reply-To, Authentication-Results) to enable those checks.');
    } else {
      if (headerInfo.from && headerInfo.replyTo) {
        var fromDomain = registrableDomain(headerInfo.fromDomain);
        var replyDomain = registrableDomain(headerInfo.replyDomain);
        if (fromDomain && replyDomain && fromDomain !== replyDomain) {
          addFinding('replytomismatch', 'Sender and Reply-To mismatch', 'headers', 15, 'Examining the pasted headers',
            [{ text: 'From: ' + headerInfo.from, start: 0, end: 0 }, { text: 'Reply-To: ' + headerInfo.replyTo, start: 0, end: 0 }],
            'If you press Reply, your answer goes to a different place than the message came from. This is a classic sign of a forged sender.',
            'Do not reply to this message. Contact the sender through a channel you already trust.');
        }
      }

      ['spf', 'dkim', 'dmarc'].forEach(function (name) {
        var res = headerInfo.auth[name];
        if (!res) {
          authStatuses[name] = { status: 'unavailable', text: UNAVAILABLE };
          return;
        }
        authStatuses[name] = { status: res.result, text: name.toUpperCase() + ' result: ' + res.result };
        if (res.result === 'fail') {
          addFinding(name + 'fail', name.toUpperCase() + ' authentication failure', 'headers', 10, 'Examining the pasted headers',
            [{ text: res.raw, start: 0, end: 0 }],
            name.toUpperCase() + ' is a check the receiving mail server performed on this message. A fail means the message did not pass the check that the real owner of the domain asked for.',
            'Treat the message as untrusted. Report it to your IT or security team and verify anything it asks you to do.');
        }
      });
    }
    report.authStatuses = authStatuses;
    report.auth = authStatuses;

    // --- 6. Group, cap and total ---
    // The second and later findings in the same category are worth
    // half. This stops one idea being counted twice at full strength,
    // and the note explains the reduction openly.
    report.findings.sort(function (a, b) { return b.points - a.points; });
    var groupsSeen = {};
    report.findings.forEach(function (f) {
      var n = (groupsSeen[f.group] || 0) + 1;
      groupsSeen[f.group] = n;
      if (n > 1) {
        f.points = Math.max(3, Math.round(f.points / 2));
        f.reduced = true;
        f.reducedReason = 'Reduced from ' + f.fullPoints + ' because it overlaps with another warning sign already counted in full.';
      }
    });

    var total = 0;
    report.findings.forEach(function (f) { total += f.points; });
    report.rawScore = total;
    if (total > 100) { total = 100; report.capped = true; }
    report.score = total;

    if (total >= 60) report.classification = { name: 'High Risk', tone: 'high' };
    else if (total >= 30) report.classification = { name: 'Suspicious', tone: 'mid' };
    else report.classification = { name: 'Low Risk', tone: 'low' };

    return report;
  }

  /* ===================================================================
     RECOMMENDATIONS
     Advice is chosen from the findings, so it is not identical for
     every result, and no advice is repeated.
     =================================================================== */

  function recommendations(report) {
    var steps = [];
    var groups = {};
    report.findings.forEach(function (f) { groups[f.group] = true; });

    if (groups.credentials) {
      steps.push('Do not reply with a password, code or any other secret. If you already did, change your password immediately using the official app or website, and tell your IT or security team.');
    }
    if (groups.money) {
      steps.push('Do not send money, gift cards or cryptocurrency. Verify any payment or bank-detail change by calling a known number - never one given in the message.');
    }
    if (groups.attachment) {
      steps.push('Do not open unexpected attachments, and never enable macros or editing to view one.');
    }
    if (groups.url) {
      steps.push('Do not click the links. Navigate to the organisation\'s official website or application yourself by typing the address or using a bookmark.');
    }
    if (groups.headers) {
      steps.push('Because the headers show problems with the sender, treat the message as forged until proven otherwise.');
    }
    steps.push('Report the message to the appropriate IT or security team, or to your email provider\'s spam or phishing report option.');
    steps.push('If the message is important to you, verify it independently through an official website, application, or known contact information - not through the message itself.');
    return steps;
  }

  /* ===================================================================
     THE FULL SCORING TABLE
     Every indicator, what it looks for, and what it is worth. Rules
     that were not matched are marked as "not detected".
     =================================================================== */

  function scoringTable(report) {
    var rows = [];
    function build(list, method) {
      list.forEach(function (r) {
        var match = null;
        report.findings.forEach(function (f) { if (f.id === r.id) match = f; });
        rows.push({
          name: r.name,
          points: match ? match.points : r.points,
          basePoints: r.points,
          detects: r.method || method,
          why: r.why,
          rec: r.rec,
          detected: !!match,
          reduced: match ? !!match.reduced : false
        });
      });
    }
    build(RULES, 'Wording in the email');
    build(URL_RULES, 'Examining the web address');
    build(HEADER_RULES, 'Checking pasted email headers');
    return rows;
  }
  /* ===================================================================
     THE URL AND HEADER RULE TABLES
     Same shape as the wording rules, so the scoring table can list
     every indicator in one place.
     =================================================================== */

  var URL_RULES = [
    { id: 'suspiciousurl', name: 'Suspicious URL pattern', points: 15, method: 'Examining links',
      why: 'This address has features that scammers commonly use to disguise where a link leads.',
      rec: 'Do not open it. Read the address from right to left: the last two parts before the first single slash are the real owner.' },
    { id: 'shortenedurl', name: 'Uses a link shortening service', points: 8, method: 'Examining links',
      why: 'Shortened links hide where they really go, so you cannot judge the destination before clicking.',
      rec: 'Do not open it. Ask the sender, in a separate message, to send the full address.' },
    { id: 'rawipurl', name: 'Uses a raw IP address instead of a website name', points: 20, method: 'Examining links',
      why: 'Genuine organisations use readable addresses. A bare number is often a throwaway server used to avoid being traced.',
      rec: 'Do not open it. If you expected a message from that organisation, go to their website yourself.' },
    { id: 'misleading', name: 'Link text does not match the real link', points: 15, method: 'Comparing link text with the real address',
      why: 'The words promise one website but the address points somewhere else.',
      rec: 'Judge a link by its real address, never by its label. Do not click it - go to the website yourself.' }
  ];

  var HEADER_RULES = [
    { id: 'replytomismatch', name: 'Sender and Reply-To mismatch', points: 15, method: 'Examining the pasted headers',
      why: 'If you press Reply, your answer goes to a different place than the message came from. This is a classic sign of a forged sender.',
      rec: 'Do not reply to this message. Contact the sender through a channel you already trust.' },
    { id: 'spffail', name: 'SPF authentication failure', points: 10, method: 'Examining the pasted headers',
      why: 'A check the receiving mail server performed on this message did not pass.',
      rec: 'Treat the message as untrusted. Report it to your IT or security team.' },
    { id: 'dkimfail', name: 'DKIM authentication failure', points: 10, method: 'Examining the pasted headers',
      why: 'A check the receiving mail server performed on this message did not pass.',
      rec: 'Treat the message as untrusted. Report it to your IT or security team.' },
    { id: 'dmarcfail', name: 'DMARC authentication failure', points: 10, method: 'Examining the pasted headers',
      why: 'A check the receiving mail server performed on this message did not pass.',
      rec: 'Treat the message as untrusted. Report it to your IT or security team.' }
  ];

  /* ===================================================================
     4. THE PAGE
     =================================================================== */

  var input, analyseBtn, clearBtn, resultsEl, inputStatus, sampleList, sampleInfo;
  var lastReport = null;
  var lastText = '';

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function showStatus(msg, isError) {
    if (!inputStatus) return;
    inputStatus.textContent = msg || '';
    inputStatus.className = 'status' + (isError ? ' error' : '');
  }

  /* Draws the risk bar with a clear number and text labels, so the
     meaning never depends on colour alone. */
  function rulerSeg(cls, label, pct) {
    var d = el('div', 'ruler-seg ' + cls);
    d.style.width = pct + '%';
    d.appendChild(el('span', null, label));
    return d;
  }

  function drawRuler(score) {
    var box = el('div', 'ruler');
    var bar = el('div', 'ruler-bar');
    bar.appendChild(rulerSeg('low', 'Low 0-29', 30));
    bar.appendChild(rulerSeg('mid', 'Suspicious 30-59', 30));
    bar.appendChild(rulerSeg('high', 'High 60-100', 40));
    box.appendChild(bar);

    var row = el('div', 'ruler-marker-row');
    var marker = el('div', 'ruler-marker');
    marker.style.left = Math.min(96, Math.max(4, score)) + '%';
    marker.textContent = score + ' / 100';
    row.appendChild(marker);
    box.appendChild(row);

    var scale = el('div', 'ruler-scale');
    scale.appendChild(el('span', null, '0'));
    scale.appendChild(el('span', null, '50'));
    scale.appendChild(el('span', null, '100'));
    box.appendChild(scale);
    return box;
  }

  /* Explains the result in plain words, without ever claiming safety. */
  function explainResult(report) {
    if (!report.findings.length) {
      return 'No warning signs were found in the text supplied. That does not mean the email is safe - this tool only recognises the patterns it has been taught.';
    }
    var names = report.findings.slice(0, 3).map(function (f) { return f.name.toLowerCase(); }).join(', ');
    var base = 'The analysis found ' + report.findings.length + ' warning sign' + (report.findings.length === 1 ? '' : 's') + ': ' + names + '.';
    if (report.classification.name === 'High Risk') {
      return base + ' Treat this message as untrusted until you have checked it another way.';
    }
    if (report.classification.name === 'Suspicious') {
      return base + ' Several warning signs together are worth taking seriously.';
    }
    return base + ' These are worth a closer look, even though the total is still low.';
  }
  /* Highlights the exact text each rule matched, with numbered
     markers that match the numbered cards below. */
  function annotatedView(text, report) {
    var box = el('div', 'annotated');
    var spans = [];
    report.findings.forEach(function (f, i) {
      (f.evidence || []).slice(0, 20).forEach(function (e) {
        if (e.start === 0 && e.end === 0) return;
        spans.push({ start: e.start, end: e.end, n: i + 1 });
      });
    });
    if (!spans.length) {
      box.appendChild(document.createTextNode(text));
      return box;
    }
    spans.sort(function (a, b) { return a.start - b.start; });
    var merged = [];
    spans.forEach(function (s) {
      var last = merged[merged.length - 1];
      if (last && s.start <= last.end) {
        last.end = Math.max(last.end, s.end);
        if (last.ns.indexOf(s.n) === -1) last.ns.push(s.n);
      } else {
        merged.push({ start: s.start, end: s.end, ns: [s.n] });
      }
    });
    var pos = 0;
    merged.forEach(function (m) {
      if (m.start > pos) box.appendChild(document.createTextNode(text.slice(pos, m.start)));
      var mark = el('mark', 'hit');
      mark.appendChild(document.createTextNode(text.slice(m.start, m.end)));
      mark.appendChild(el('sup', null, m.ns.join(',')));
      box.appendChild(mark);
      pos = m.end;
    });
    if (pos < text.length) box.appendChild(document.createTextNode(text.slice(pos)));
    return box;
  }

  function render(report, text) {
    resultsEl.innerHTML = '';
    resultsEl.hidden = false;

    var h = el('h2', 'results-title', 'Analysis report');
    h.id = 'results-title';
    h.tabIndex = -1;
    resultsEl.appendChild(h);

    /* --- Risk overview --- */
    var card = el('section', 'score-card');
    var row = el('div', 'score-row');
    var num = el('div');
    num.appendChild(el('span', 'score-number', report.score));
    num.appendChild(el('span', 'score-out-of', ' / 100'));
    row.appendChild(num);
    row.appendChild(el('span', 'badge ' + report.classification.tone, report.classification.name));
    card.appendChild(row);
    card.appendChild(drawRuler(report.score));
    card.appendChild(el('p', 'score-explain', explainResult(report)));

    if (report.capped) {
      card.appendChild(el('p', 'score-explain', 'The evidence added up to ' + report.rawScore + ' points, which was capped at 100.'));
    }
    report.notes.forEach(function (n) { card.appendChild(el('p', 'score-explain', n)); });

    if (report.headersFound && report.authStatuses) {
      var authBox = el('div', 'auth-box');
      authBox.appendChild(el('p', 'triggered-label', 'Email authentication checks'));
      ['spf', 'dkim', 'dmarc'].forEach(function (name) {
        var a = report.authStatuses[name];
        authBox.appendChild(el('p', 'auth-line', name.toUpperCase() + ': ' + (a ? a.status : 'unavailable')));
      });
      card.appendChild(authBox);
    }
    resultsEl.appendChild(card);

    /* --- Warning signs --- */
    if (report.findings.length) {
      var fh = el('h3', 'section-title', 'Detected warning signs');
      fh.id = 'findings-title';
      resultsEl.appendChild(fh);
    }
    report.findings.forEach(function (f, i) {
      var c = el('article', 'finding');
      c.id = 'finding-' + (i + 1);
      c.tabIndex = -1;
      var head = el('div', 'finding-head');
      head.appendChild(el('span', 'finding-points', '+' + f.points));
      head.appendChild(el('h4', 'finding-name', (i + 1) + '. ' + f.name));
      c.appendChild(head);

      if (f.evidence && f.evidence.length) {
        c.appendChild(el('p', 'triggered-label', 'What the analyser found'));
        f.evidence.slice(0, 3).forEach(function (e) {
          var shown = e.text;
          if (shown.length > 160) shown = shown.slice(0, 160) + '...';
          c.appendChild(el('p', 'evidence', '\u201C' + shown + '\u201D'));
        });
        if (f.evidence.length > 3) {
          c.appendChild(el('p', 'count-note', 'and ' + (f.evidence.length - 3) + ' more places in the message'));
        }
      }

      c.appendChild(el('p', 'finding-why', 'Why this matters: ' + f.why));
      c.appendChild(el('p', 'finding-rec', 'What to do: ' + f.rec));
      var how = 'How it was spotted: ' + f.method;
      if (f.reduced) how += ' (points reduced to avoid double counting)';
      c.appendChild(el('p', 'count-note', how));
      resultsEl.appendChild(c);
    });

    if (!report.findings.length) {
      var none = el('article', 'finding');
      none.appendChild(el('h4', 'finding-name', 'No warning signs found'));
      none.appendChild(el('p', 'finding-why', 'The analyser did not match any of its rules against the text you supplied. That does not prove the email is safe.'));
      resultsEl.appendChild(none);
    }

    /* --- Recommended next steps --- */
    var sc = el('section', 'next-steps');
    sc.appendChild(el('h3', null, 'Recommended next steps'));
    var ul = el('ul');
    recommendations(report).forEach(function (s) { ul.appendChild(el('li', null, s)); });
    sc.appendChild(ul);
    resultsEl.appendChild(sc);

    /* --- Annotated copy of the email --- */
    var dh = el('h3', 'section-title', 'The email with the matched text highlighted');
    dh.id = 'annotated-title';
    resultsEl.appendChild(dh);
    resultsEl.appendChild(el('p', 'section-note', 'The yellow marks show exactly which words each rule matched. The numbers match the cards above.'));
    resultsEl.appendChild(annotatedView(text, report));

    /* --- Full scoring table --- */
    var th = el('h3', 'section-title', 'Full scoring table');
    th.id = 'scoring-title';
    resultsEl.appendChild(th);
    resultsEl.appendChild(el('p', 'section-note', 'Every indicator the analyser knows about. Only the ones marked as detected added points.'));
    var wrap = el('div', 'score-table-wrap');
    var table = el('table', 'score-table');
    var thead = el('thead');
    var trh = el('tr');
    ['Indicator', 'Detected?', 'Points', 'What it looks for', 'Why it matters', 'What to do'].forEach(function (t) { trh.appendChild(el('th', null, t)); });
    thead.appendChild(trh);
    table.appendChild(thead);
    var tbody = el('tbody');
    scoringTable(report).forEach(function (r) {
      var tr = el('tr', r.detected ? null : 'muted');
      tr.appendChild(el('td', null, r.name));
      tr.appendChild(el('td', null, r.detected ? 'Yes' : 'No'));
      tr.appendChild(el('td', 'points', r.detected ? '+' + r.points : '+' + r.basePoints));
      tr.appendChild(el('td', null, r.detects));
      tr.appendChild(el('td', null, r.why));
      tr.appendChild(el('td', null, r.rec));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    resultsEl.appendChild(wrap);
  }

  /* ===================================================================
     Buttons, sample emails and starting the page
     =================================================================== */

  function doAnalyse() {
    var text = input.value;
    if (!text.trim()) {
      showStatus('Please paste an email first, or choose a sample below.', true);
      resultsEl.hidden = true;
      resultsEl.innerHTML = '';
      input.focus();
      return;
    }
    lastText = text;
    lastReport = analyse(text);
    render(lastReport, lastText);
    showStatus('Analysis complete. ' + lastReport.classification.name + ' - ' + lastReport.score + ' out of 100.');
    var heading = $('results-title');
    if (heading) heading.scrollIntoView({ block: 'start' });
  }

  function doClear() {
    input.value = '';
    lastReport = null;
    lastText = '';
    resultsEl.innerHTML = '';
    resultsEl.hidden = true;
    showStatus('Cleared. The email text has been removed from the page.');
    input.focus();
  }

  function loadSamples() {
    var list = (typeof window !== 'undefined' && window.PEA_SAMPLES) ? window.PEA_SAMPLES : [];
    list.forEach(function (s) {
      var b = el('button', 'sample-btn');
      b.type = 'button';
      b.setAttribute('aria-pressed', 'false');
      b.appendChild(el('span', 's-title', s.title));
      b.appendChild(el('span', 's-tag', 'Click to load this sample'));
      b.addEventListener('click', function () {
        Array.prototype.forEach.call(sampleList.querySelectorAll('.sample-btn'), function (other) {
          other.setAttribute('aria-pressed', 'false');
        });
        b.setAttribute('aria-pressed', 'true');
        input.value = s.text;
        sampleInfo.innerHTML = '';
        sampleInfo.appendChild(el('strong', null, s.title + ' - '));
        sampleInfo.appendChild(document.createTextNode(s.teaches));
        showStatus('Sample loaded. Click Analyse Email to analyse it.');
        input.focus();
      });
      sampleList.appendChild(b);
    });
  }

  function init() {
    input = $('email-input');
    analyseBtn = $('analyse-btn');
    clearBtn = $('clear-btn');
    resultsEl = $('results');
    inputStatus = $('input-status');
    sampleList = $('sample-list');
    sampleInfo = $('sample-info');
    if (!input || !analyseBtn || !clearBtn || !resultsEl) return;
    analyseBtn.addEventListener('click', doAnalyse);
    clearBtn.addEventListener('click', doClear);
    loadSamples();
  }

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }

  /* Expose the engine so the test page can check it works. */
  var PEA = {
    analyse: analyse,
    recommendations: recommendations,
    scoringTable: scoringTable,
    rules: RULES,
    urlRules: URL_RULES,
    headerRules: HEADER_RULES,
    maxInput: MAX_INPUT
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = PEA;
  }
  if (root) {
    root.PEA = PEA;
  }

})();

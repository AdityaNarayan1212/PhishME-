# Phishing Email Analyser

An educational, privacy-first web tool that checks a pasted email for common phishing and social-engineering warning signs.

Built with plain HTML, CSS and JavaScript. No frameworks, no build tools, no backend, no database, no API keys.

## Privacy first

Your email is analysed locally in your browser. Its contents are not uploaded to a server or sent to an AI service by this application.

- No network requests are made while analysing.
- No cookies, local storage or session storage are used.
- No analytics, telemetry or tracking of any kind.
- The pasted text is held in memory only, and is cleared when you click Clear or close the tab.
- A Content Security Policy in index.html makes the browser refuse all outside connections as an extra safety net.

You should still avoid pasting sensitive personal information into any tool unless you understand the environment it is running in.

## How to use

1. Open index.html in any modern browser (double-click it). Nothing needs to be installed.
2. Paste the suspicious email (include the headers if you can).
3. Click Analyse Email.
4. Read the score, the detected warning signs and the recommended next steps.

Or choose one of the six fictional sample emails under Try Sample Emails.

## What it looks for

- Requests for passwords, MFA codes or verification codes
- Threats of account suspension, closure or termination
- Strong urgency and pressure language
- Gift-card, cryptocurrency or unusual payment requests
- Requests to change bank account details
- Unexpected invoice or payment pressure
- Credential-harvesting language (fake sign-in alerts)
- Suspicious, shortened or raw-IP web addresses
- Misleading link text (where the pasted text makes the mismatch clear)
- Executable or risky attachment types
- Requests to enable macros or disable security protection
- Requests to bypass normal procedures or keep the message secret
- Common impersonation language
- Sender and Reply-To mismatches (from pasted headers)
- SPF, DKIM and DMARC failures (only when explicitly present in pasted headers)

## Scoring

Every indicator has a fixed point value. The score is the sum of the detected indicators, capped at 100.

- 0-29: Low Risk
- 30-59: Suspicious
- 60-100: High Risk

Safeguards built into the scoring:

- Repeated matches of the same rule count once.
- Overlapping rules in the same category are reduced to half strength, and this is shown openly in the result.
- The score never exceeds 100.
- Missing information (for example, no headers) is never treated as a failure.
- The same input always produces the same result.

The full scoring table is shown in the results, including rules that were not detected.

## Limitations (please read)

- This is a rule-based tool. It matches patterns; it does not understand meaning. It can miss sophisticated attacks and it can flag honest emails.
- A Low Risk result does not mean an email is safe. A High Risk result does not prove it is malicious.
- URLs are never visited, resolved or checked against any service. They are only read as text.
- Pasted headers can be incomplete or forged. This tool does not independently authenticate an email's origin.
- Misleading link text can usually only be detected when the pasted content preserves both the link text and the real address.

This educational triage tool identifies patterns commonly associated with phishing and social engineering. It cannot prove that an email is malicious or safe. False positives and false negatives are possible. Verify important messages independently through official websites, applications, or known contact information.

Never click a suspicious link or open an attachment merely to test whether it is malicious.

## Files

- index.html - the page structure
- style.css - the visual design and responsive layout
- script.js - the analysis engine, scoring rules and page behaviour
- samples.js - six fictional demonstration emails

## Editing it

All the scoring rules live in script.js in a section called THE RULES. Each rule has a name, a point value, what it looks for, why it matters and what to do. You can change the numbers safely; the results page always shows the current values.

The sample emails live in samples.js. They use only reserved example domains and contain no working links.

## Hosting it for free

Because it is a static site, any free static host works. Upload the four files (or push this folder to GitHub and enable GitHub Pages on the main branch). Visitors never need an account and never send anything anywhere.
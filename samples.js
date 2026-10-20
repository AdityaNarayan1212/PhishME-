/*
 * samples.js
 * Six completely FICTIONAL demonstration emails for the Phishing Email Analyser.
 *
 * Safety rules for this file:
 *  - Only reserved example domains are used: example.com, example.net, example.org.
 *    These can never belong to a real organisation.
 *  - 192.0.2.x is a range reserved for documentation. It is not a real server.
 *  - short.example / short.example.net are invented shorteners used only for teaching.
 *  - No real company is used as a sender, and no link here works.
 *
 * Each sample has:  id, title, teaches, text
 *   title    - what appears on the sample button
 *   teaches  - the lesson shown under the sample buttons
 *   text     - the email loaded into the input box
 */
(function (root) {
  'use strict';

  var SAMPLES = [
    {
      id: 'obvious',
      title: '1. Obvious phishing',
      teaches: 'This email stacks every classic red flag at once: urgency, a suspension threat, a request for a password and a verification code, a gift-card demand, a raw IP address link, a dangerous attachment and a request for secrecy. It shows how the score caps at 100 and how repeated or overlapping rules are not double-counted.',
      text: 'From: "Mail Delivery Service" <deliver@notify-shipment.example.com>\n' +
        'Reply-To: claims-desk@secure-verify.example.net\n' +
        'Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=notify-shipment.example.com; dkim=fail header.d=notify-shipment.example.com; dmarc=fail header.from=notify-shipment.example.com\n' +
        'Subject: URGENT!!! Your account will be suspended\n' +
        '\n' +
        'Dear Customer,\n' +
        '\n' +
        'Your account has been suspended due to unusual sign-in activity. You must act now to avoid permanent closure of your account. Failure to comply within 24 hours will result in immediate suspension.\n' +
        '\n' +
        'To restore your account, please send us your password and the 6-digit verification code we sent to your phone so that we can verify your identity.\n' +
        '\n' +
        'You have also won a $500 gift card. To receive it, buy a $100 iTunes gift card and send us the codes by reply.\n' +
        '\n' +
        'Click here to verify your account: http://192.0.2.45/verify-login\n' +
        'Or use this shortcut: http://short.example/7h2K\n' +
        '\n' +
        'Open the attached form (invoice_scan.pdf.exe) and enable macros to view it.\n' +
        '\n' +
        'Keep this confidential and do not tell anyone, or your account will remain suspended.\n' +
        '\n' +
        'Security Team\n' +
        'Customer Care Department'
    },
    {
      id: 'sophisticated',
      title: '2. Sophisticated phishing',
      teaches: 'This one is polite and business-like, with no shouting, so simple urgency checks alone would miss it. Instead it hides its intent in the details: a failed DMARC and DKIM check, a Reply-To address on a different domain, link text that displays one address while the real link points elsewhere, a request to verify sign-in details, a changed bank account and a macro-enabled spreadsheet.',
      text: 'From: Dana Whitfield <dana.whitfield@northwind-partners.example.com>\n' +
        'Reply-To: Dana Whitfield <dana.whitfield@nw-partners-mail.example.net>\n' +
        'Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=northwind-partners.example.com; dkim=fail header.d=northwind-partners.example.com; dmarc=fail header.from=northwind-partners.example.com\n' +
        'Subject: Updated payment details and supplier agreement\n' +
        '\n' +
        'Hello,\n' +
        '\n' +
        'I hope you are well. Following our call last week, please see attached the updated payment details and the supplier agreement for your records.\n' +
        '\n' +
        'Please verify your sign-in details to access the agreement: [northwind-partners.example.com](https://secure-agreements.nw-partners.review.example.net)\n' +
        '\n' +
        'Also note that our bank details have changed with effect from this month. Please update your records and process the outstanding invoice using the new account below:\n' +
        '\n' +
        'Account name: Northwind Partners Ltd\n' +
        'New account number: 12345678\n' +
        'Sort code: 99-88-77\n' +
        '\n' +
        'The spreadsheet is attached as payment_details_Q3.xlsm. Please enable editing and content when you open it.\n' +
        '\n' +
        'Kind regards,\n' +
        '\n' +
        'Dana Whitfield\n' +
        'Accounts Department, Northwind Partners'
    }
    ,
    {
      id: 'm365',
      title: '3. Fake Microsoft 365 warning',
      teaches: 'A scary account warning with a deadline. Notice the sender domain and the link domain are unrelated look-alikes, that the message asks for a password, and that there are no authentication headers at all. A genuine security email would point you to sign in through the official site yourself rather than through a link in the message.',
      text: 'From: "Microsoft 365 Security" <security-notice@ms-account-secure.example.net>\n' +
        'Subject: Action required: unusual sign-in activity\n' +
        '\n' +
        'Dear User,\n' +
        '\n' +
        'We detected unusual sign-in activity on your Microsoft 365 account.\n' +
        '\n' +
        'Your account will be deactivated in 24 hours unless you confirm your identity.\n' +
        '\n' +
        'Please verify your account now: http://microsoft365-signin.verify-account.example.com/login\n' +
        '\n' +
        'Enter your password to confirm your identity and avoid suspension.\n' +
        '\n' +
        'Regards,\n' +
        'Microsoft 365 Security Team'
    },
    {
      id: 'parcel',
      title: '4. Fake parcel delivery',
      teaches: 'Parcel scams rely on urgency and a small fee, which makes people stop checking carefully. Look at the web address from right to left: the real domain is example.com, and the rest is decoration. The link is also not encrypted (http rather than https) and asks about payment details.',
      text: 'From: Parcel Delivery <delivery@parcel-tracking.example.com>\n' +
        'Subject: Delivery attempt failed - action needed\n' +
        '\n' +
        'Hello,\n' +
        '\n' +
        'We attempted to deliver your parcel but the address was incomplete. Your parcel will be returned to sender unless you confirm your delivery details within 24 hours.\n' +
        '\n' +
        'A small redelivery fee of 1.99 is required. Confirm your details and pay here:\n' +
        'http://parcel-redelivery.confirm-address.example.com/reschedule\n' +
        '\n' +
        'You can also track your parcel with this short link: http://short.example.net/pkQ7\n' +
        '\n' +
        'Act now to avoid a further delay.\n' +
        '\n' +
        'Delivery Team'
    }
    ,
    {
      id: 'bec',
      title: '5. Fake invoice / BEC-style',
      teaches: 'Business email compromise (BEC) often contains no links or attachments at all. It works on authority and pressure: a boss who cannot be reached, an invoice due today, changed bank details, a request to skip the usual approval and a request for secrecy. Always verify payment changes through a phone number you already know, never through the email.',
      text: 'From: "Morgan Ellis" <morgan.ellis@northwind-group.example.com>\n' +
        'Reply-To: morgan.ellis.office@gmail-style.example.net\n' +
        'Subject: Quick favour - urgent\n' +
        '\n' +
        'Hi Sam,\n' +
        '\n' +
        'Are you at your desk? This is Morgan, your Managing Director. I am heading into a board meeting and cannot take calls.\n' +
        '\n' +
        'One of our suppliers has changed their bank details and an invoice is due today. Please update the payee and process the payment immediately using the new account below:\n' +
        '\n' +
        'New account number: 87654321\n' +
        'Sort code: 12-34-56\n' +
        '\n' +
        'The invoice is attached as INV_4493.pdf. No need for the usual approval process on this one, and please keep this confidential until the board meeting finishes.\n' +
        '\n' +
        'Thanks,\n' +
        'Morgan'
    },
    {
      id: 'legit',
      title: '6. Legitimate email',
      teaches: 'Ordinary business emails can contain urgency, an attachment and even talk about passwords without being phishing. This one uses the word urgent, attaches a normal PDF, and reminds the reader never to share a password or code. Because that sentence warns against sharing rather than asking for anything, it should not raise the score. A low score still does not prove an email is safe.',
      text: 'From: Alex Chen <alex.chen@northwind.example.com>\n' +
        'Reply-To: Alex Chen <alex.chen@northwind.example.com>\n' +
        'Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=northwind.example.com; dkim=pass header.d=northwind.example.com; dmarc=pass header.from=northwind.example.com\n' +
        'Subject: Budget review on Friday - agenda attached\n' +
        '\n' +
        'Hi Priya,\n' +
        '\n' +
        'The budget review is on Friday at 10am in Meeting Room 2. It is quite urgent that we agree the numbers before the quarter closes, so please read the agenda attached (agenda_review.pdf) beforehand.\n' +
        '\n' +
        'As a reminder, we will never ask you to share your password or a verification code by email, so please do not send either to anyone.\n' +
        '\n' +
        'See you Friday,\n' +
        'Alex'
    }
  ];

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = SAMPLES;
  } else {
    root.PEA_SAMPLES = SAMPLES;
  }
})(typeof self !== 'undefined' ? self : this);

/**
 * @file classifier.ts
 * @description
 * Comprehensive domain classifier and SDK signature detector for RequestScope.
 *
 * - `DOMAIN_DATABASE` — ordered list of `[RegExp, name, category]` tuples covering
 *   150+ third-party services across analytics, advertising, CDN, payment,
 *   communication, monitoring, security, marketing, social, testing, video,
 *   authentication, consent, and hosting.
 * - `SDK_SIGNATURES` — regex patterns that detect SDK initialisation calls in
 *   raw JavaScript source (gtag, fbq, hj, Sentry.init, etc.).
 * - `classifyDomain()` — resolves a hostname to `{ category, name }`.
 * - `detectSdks()` — scans JS source and returns matched SDKs.
 * - `assessPiiRisk()` — heuristic for whether a category typically exfiltrates PII.
 * - `isKnownDomain()` — quick membership check.
 *
 * Matching is case-insensitive and works on the full hostname so that subdomain
 * patterns (e.g. `*.cloudflare.com`) are handled naturally.
 */

import { getDomain as tldtsGetDomain } from "tldts";

/* -------------------------------------------------------------------------- */
/* Types                                                                       */
/* -------------------------------------------------------------------------- */

export type DomainCategory =
  | "functional"
  | "analytics"
  | "advertising"
  | "cdn"
  | "payment"
  | "communication"
  | "monitoring"
  | "security"
  | "marketing"
  | "social"
  | "testing"
  | "video"
  | "auth"
  | "consent"
  | "hosting"
  | "unknown";

export interface DomainMatch {
  category: DomainCategory;
  name: string | null;
}

export interface SdkMatch {
  name: string;
  domain: string;
  category: DomainCategory;
  match: string;
}

/* -------------------------------------------------------------------------- */
/* Domain database                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Ordered list of `[regex, serviceName, category]` tuples.
 * The first matching regex wins, so more specific patterns should come first.
 *
 * Patterns are tested against the full lowercased hostname (including subdomains).
 * Use `\.` to match literal dots and `\.` boundaries to avoid false positives.
 */
export const DOMAIN_DATABASE: Array<[RegExp, string, DomainCategory]> = [
  /* ----------------------------- Analytics -------------------------------- */
  [/google-analytics\.com$/i, "Google Analytics", "analytics"],
  [/googletagmanager\.com$/i, "Google Tag Manager", "analytics"],
  [/googletag\.services\.com$|googletagservices\.com$/i, "Google Tag Manager", "analytics"],
  [/hotjar\.com$/i, "Hotjar", "analytics"],
  [/mixpanel\.com$/i, "Mixpanel", "analytics"],
  [/amplitude\.com$/i, "Amplitude", "analytics"],
  [/segment\.(io|com)$/i, "Segment", "analytics"],
  [/posthog\.com$/i, "PostHog", "analytics"],
  [/plausible\.io$/i, "Plausible", "analytics"],
  [/clarity\.ms$/i, "Microsoft Clarity", "analytics"],
  [/(matomo|piwik)\./i, "Matomo/Piwik", "analytics"],
  [/chartbeat\.com$/i, "Chartbeat", "analytics"],
  [/newrelic\.com$|nr-data\.net$|browser-agent\.newrelic\.com$/i, "New Relic Browser", "analytics"],
  [/fullstory\.com$|fullstory\.net$/i, "FullStory", "analytics"],
  [/logrocket\.com$|lr-?cdn\.com$/i, "LogRocket", "analytics"],
  [/heap\.io$|heapanalytics\.com$/i, "Heap", "analytics"],
  [/mouseflow\.com$/i, "Mouseflow", "analytics"],
  [/luckyorange\.com$|luckyorange\.net$/i, "Lucky Orange", "analytics"],
  [/kissmetrics\.com$|kissmetrics\.io$/i, "Kissmetrics", "analytics"],
  [/woopra\.com$|woopra-ns\.com$/i, "Woopra", "analytics"],
  [/statcounter\.com$/i, "Statcounter", "analytics"],
  [/clicky\.com$/i, "Clicky", "analytics"],
  [/snowplowanalytics\.com$|snowplow\.com$/i, "Snowplow", "analytics"],
  [/akamai\.net$|akamaized\.net$|mpulse\.net$/i, "Akamai mPulse", "analytics"],
  [/contentsquare\.net$|contentsquare\.com$/i, "ContentSquare", "analytics"],
  [/adjust\.com$|adjust\.net$|app\.adjust\./i, "Adjust", "analytics"],
  [/appsflyer\.com$|appsflyersdk\.com$/i, "AppsFlyer", "analytics"],
  [/branch\.io$|branchster\.com$/i, "Branch", "analytics"],
  [/tealium\.com$|tiqcdn\.com$/i, "Tealium", "analytics"],
  [/quantcast\.com$|quantserve\.com$/i, "Quantcast", "analytics"],
  [/scorecardresearch\.com$|comscore\.com$/i, "ScorecardResearch/comScore", "analytics"],
  [/crazyegg\.com$/i, "Crazy Egg", "analytics"],
  [/vwo\.com$/i, "VWO", "testing"],
  [/optimizely\.com$|optimizely\.net$/i, "Optimizely", "testing"],
  [/abtasty\.com$/i, "AB Tasty", "testing"],
  [/convert\.com$|convert\.api$/i, "Convert", "testing"],
  [/kameleoon\.com$|kameleoon\.eu$/i, "Kameleoon", "testing"],

  /* --------------------------- Advertising -------------------------------- */
  [/doubleclick\.net$|doubleclickbygoogle\.com$/i, "DoubleClick/Google Ads", "advertising"],
  [/googlesyndication\.com$|googleadservices\.com$|adservice\.google\./i, "Google Ads", "advertising"],
  [/googletagservices\.com$/i, "Google Ad Manager", "advertising"],
  [/connect\.facebook\.net$|facebook\.net$|facebook\.com\/tr/i, "Facebook/Meta Pixel", "advertising"],
  [/amazon-adsystem\.com$|aax\.amazon-adsystem\.com$/i, "Amazon Ads", "advertising"],
  [/criteo\.(com|net)$/i, "Criteo", "advertising"],
  [/taboola\.com$/i, "Taboola", "advertising"],
  [/outbrain\.com$/i, "Outbrain", "advertising"],
  [/rubiconproject\.com$|rubicon\.com$/i, "Rubicon Project", "advertising"],
  [/pubmatic\.com$/i, "PubMatic", "advertising"],
  [/openx\.net$|openx\.org$/i, "OpenX", "advertising"],
  [/moatads\.com$|moat\.com$/i, "Moat", "advertising"],
  [/yahoo\.com$|verizonmedia\.com$|oath\.com$|adtech\.com$/i, "Yahoo/Verizon Ads", "advertising"],
  [/bing\.com\/ads|bat\.bing\.com$/i, "Bing Ads", "advertising"],
  [/adroll\.com$|servedbyadroll\.com$/i, "AdRoll", "advertising"],
  [/bluekai\.com$|tags\.bluekai\.com$/i, "BlueKai (Oracle)", "advertising"],
  [/demdex\.net$|demdex\.com$/i, "Demdex (Adobe Audience)", "advertising"],
  [/flashtalking\.com$/i, "Flashtalking", "advertising"],
  [/mediavine\.com$|mediavine\.net$/i, "MediaVine", "advertising"],
  [/adthrive\.com$/i, "AdThrive", "advertising"],
  [/triplelift\.net$|triplelift\.com$/i, "TripleLift", "advertising"],
  [/casalemedia\.com$|indexexchange\.com$/i, "Index Exchange", "advertising"],
  [/prebid\.org$|bidswitch\.net$|rubicon\.com$/i, "Prebid", "advertising"],
  [/3lift\.com$|triplelift\.com$/i, "TripleLift", "advertising"],
  [/adsymptotic\.com$/i, "AdSymptotic", "advertising"],
  [/adnxs\.com$|appnexus\.com$/i, "AppNexus/Xandr", "advertising"],
  [/rlcdn\.com$/i, "LiveRamp", "advertising"],
  [/adsrvr\.org$/i, "The Trade Desk", "advertising"],
  [/quantserve\.com$/i, "Quantcast Ad", "advertising"],
  [/eyeota\.net$/i, "Eyeota", "advertising"],
  [/media\.net$|medianet\.com$/i, "Media.net", "advertising"],

  /* ----------------------------- CDN/Hosting ------------------------------ */
  [/cloudflareinsights\.com$|cloudflare\.com\/cdn-cgi/i, "Cloudflare Insights", "cdn"],
  [/cdnjs\.cloudflare\.com$/i, "cdnjs (Cloudflare)", "cdn"],
  [/challenges\.cloudflare\.com$|turnstile\.site$/i, "Cloudflare Turnstile", "security"],
  [/cloudflare\.com$/i, "Cloudflare", "cdn"],
  [/jsdelivr\.net$/i, "jsDelivr", "cdn"],
  [/unpkg\.com$/i, "unpkg", "cdn"],
  [/bootstrapcdn\.com$/i, "BootstrapCDN", "cdn"],
  [/googleapis\.com$/i, "Google APIs", "cdn"],
  [/gstatic\.com$/i, "Google Static", "cdn"],
  [/googlevideo\.com$/i, "Google Video", "cdn"],
  [/gravatar\.com$/i, "Gravatar", "cdn"],
  [/fastly\.(net|cdn|com)$/i, "Fastly", "cdn"],
  [/akamai\.net$|akamaized\.net$|akamaihd\.net$|edgekey\.net$|edgesuite\.net$/i, "Akamai", "cdn"],
  [/cdn77\.(org|com)$/i, "CDN77", "cdn"],
  [/keycdn\.com$/i, "KeyCDN", "cdn"],
  [/bunny\.net$|bunnycdn\.com$/i, "Bunny.net", "cdn"],
  [/githubusercontent\.com$|github\.io$/i, "GitHub", "hosting"],
  [/raw\.githubusercontent\.com$/i, "GitHub raw", "hosting"],
  [/wordpress\.com$|wp\.com$|wordpress\.org$/i, "WordPress", "hosting"],
  [/netlify\.app$|netlifycdn\.com$/i, "Netlify", "hosting"],
  [/vercel\.app$|vercel\.com$|now\.sh$/i, "Vercel", "hosting"],
  [/github\.com$/i, "GitHub", "hosting"],
  [/gitlab\.io$|gitlab-static\.net$/i, "GitLab", "hosting"],
  [/cloudfront\.net$/i, "AWS CloudFront", "cdn"],
  [/cloudflarestream\.com$/i, "Cloudflare Stream", "cdn"],
  [/js\.delivr\.net$/i, "jsDelivr", "cdn"],
  [/bootstrapdocs\.com$/i, "BootstrapDocs", "cdn"],
  [/maxcdn\.bootstrapcdn\.com$/i, "BootstrapCDN", "cdn"],
  [/stackpath\.bootstrapcdn\.com$/i, "StackPath (BootstrapCDN)", "cdn"],
  [/stackpath\.net$|stackpathcdn\.com$/i, "StackPath", "cdn"],
  [/azureedge\.net$|azurefd\.net$|azure\.com$/i, "Azure CDN", "cdn"],
  [/msecnd\.net$/i, "Azure CDN (Verizon)", "cdn"],
  [/toran\.is$/i, "Toran", "cdn"],

  /* ------------------------------ Payment --------------------------------- */
  [/stripe\.com$|stripe\.network$|m\.stripe\.network$|js\.stripe\.com$/i, "Stripe", "payment"],
  [/paypal\.com$|paypalobjects\.com$|paypal\.io$/i, "PayPal", "payment"],
  [/squareup\.com$|squarecdn\.com$/i, "Square", "payment"],
  [/adyen\.com$|adyenpayments\.com$/i, "Adyen", "payment"],
  [/checkout\.com$|checkoutradio\.com$/i, "Checkout.com", "payment"],
  [/realexpayments\.com$|globalpay\.com$/i, "Realex/GlobalPay", "payment"],
  [/worldpay\.com$|secure\.worldpay$/i, "Worldpay", "payment"],
  [/sagepay\.com$|opayo\.com$|sage\.com\/payments/i, "SagePay/Opayo", "payment"],
  [/braintreegateway\.com$|braintree\.api$/i, "Braintree", "payment"],
  [/recurly\.com$/i, "Recurly", "payment"],
  [/chargebee\.com$/i, "Chargebee", "payment"],
  [/klarna\.com$|klarnacdn\.net$/i, "Klarna", "payment"],
  [/shopify\.com$|shopifycdn\.com$|shopifycs\.com$|myshopify\.com$/i, "Shopify", "payment"],
  [/mollie\.com$/i, "Mollie", "payment"],
  [/gocardless\.com$/i, "GoCardless", "payment"],
  [/sezzle\.com$/i, "Sezzle", "payment"],
  [/affirm\.com$/i, "Affirm", "payment"],
  [/afterpay\.com$/i, "Afterpay", "payment"],

  /* --------------------------- Communication ------------------------------ */
  [/pusher\.com$|pusher\.app$|pusherapp\.com$/i, "Pusher", "communication"],
  [/socket\.io$/i, "Socket.io", "communication"],
  [/ably\.io$|ably\.com$|ably\.net$/i, "Ably", "communication"],
  [/pubnub\.com$|pubnub\.net$/i, "PubNub", "communication"],
  [/firebaseio\.com$|firebase\.google\.com$/i, "Firebase", "communication"],
  [/deepstream\.io$|deepstreamhub\.com$/i, "Deepstream", "communication"],
  [/intercomcdn\.com$|intercom\.io$|intercom\.com$/i, "Intercom", "communication"],
  [/zendeskcdn\.com$|zendesk\.com$|zdassets\.com$|zopim\.com$/i, "Zendesk", "communication"],
  [/crisp\.chat$|clientcrisp\.com$/i, "Crisp", "communication"],
  [/drift\.com$|driftcdn\.com$/i, "Drift", "communication"],
  [/tawk\.to$/i, "Tawk.to", "communication"],
  [/olark\.com$/i, "Olark", "communication"],
  [/livechatinc\.com$/i, "LiveChat", "communication"],
  [/snapengage\.com$|snapengage\.net$/i, "SnapEngage", "communication"],
  [/userlike\.com$|userlike-cdn\.com$/i, "Userlike", "communication"],
  [/helpscout\.net$|helpscoutdocs\.com$/i, "HelpScout", "communication"],
  [/freshchat\.com$|freshchat\.io$/i, "Freshchat", "communication"],
  [/smartsuppchat\.com$|smartsupp\.net$/i, "Smartsupp", "communication"],
  [/hubspot\.com$|hsforms\.net$|hs-analytics\.net$|hs-scripts\.com$|hubspotusercontent\.com$/i, "HubSpot", "communication"],

  /* ----------------------------- Monitoring ------------------------------- */
  [/sentry\.io$|sentry\.cdn\.com$|sentry-cdn\.com$/i, "Sentry", "monitoring"],
  [/datadoghq\.com$|datad0g\.com$|dogsuppy\.com$/i, "Datadog", "monitoring"],
  [/rollbar\.com$/i, "Rollbar", "monitoring"],
  [/logflare\.app$|logflare\.net$/i, "Logflare", "monitoring"],
  [/bugsnag\.com$/i, "Bugsnag", "monitoring"],
  [/raygun\.com$|raygun\.io$/i, "Raygun", "monitoring"],
  [/trackjs\.com$/i, "TrackJS", "monitoring"],
  [/airbrake\.io$|airbrakeapp\.com$/i, "Airbrake", "monitoring"],
  [/atatus\.com$/i, "Atatus", "monitoring"],
  [/elastic\.co$|elastic-apm\.com$|elastic\.cloud$/i, "Elastic APM", "monitoring"],
  [/appdynamics\.com$|appdynamics\.net$/i, "AppDynamics", "monitoring"],
  [/newrelic\.com$|nr-data\.net$/i, "New Relic", "monitoring"],
  [/logrocket\.com$|lr-cdn\.com$/i, "LogRocket", "monitoring"],
  [/ honeycomb\.io$/i, "Honeycomb", "monitoring"],
  [/grafana\.net$|grafana\.com$|grafana\.org$/i, "Grafana", "monitoring"],
  [/pingdom\.net$|pingdom\.com$|pingdomcdn\.net$/i, "Pingdom", "monitoring"],
  [/uptimerobot\.com$/i, "UptimeRobot", "monitoring"],
  [/statuspage\.io$|statuspage\.com$/i, "StatusPage", "monitoring"],

  /* ------------------------------ Security -------------------------------- */
  [/recaptcha\.net$|recaptcha\.google\.com$|www\.google\.com\/recaptcha/i, "reCAPTCHA", "security"],
  [/hcaptcha\.com$|hcaptcha\.net$/i, "hCaptcha", "security"],
  [/cloudflare\.com\/cdn-cgi\/challenge/i, "Cloudflare Challenge", "security"],
  [/arc\.io$|arc\.io\/api$/i, "Arc.io", "security"],
  [/perimeterx\.net$|px-cdn\.net$|px-cloud\.net$|humansecurity\.com$|px-cdn\.net$/i, "PerimeterX/HUMAN", "security"],
  [/datadome\.co$|datadome\.net$|dd\.cdn$/i, "DataDome", "security"],
  [/imperva\.com$|incapsula\.com$|incapdns\.net$|impervadns\.net$/i, "Imperva/Incapsula", "security"],
  [/sucuri\.net$|sucuri\.com$/i, "Sucuri", "security"],
  [/akamai\.net\/hdrm|hdrm\.akamai\.net$/i, "Akamai Bot Manager", "security"],
  [/kasada\.io$|kasada\.net$/i, "Kasada", "security"],

  /* ----------------------------- Marketing/CRM ---------------------------- */
  [/hubspot\.com$|hsforms\.net$|hs-analytics\.net$|hs-scripts\.com$/i, "HubSpot", "marketing"],
  [/mailchimp\.com$|mc\.cdn\.net$|mailchimp\.net$|campaign-archive\.com$/i, "Mailchimp", "marketing"],
  [/marketo\.com$|marketo\.net$|mktoresp\.com$|mktoweb\.com$/i, "Marketo", "marketing"],
  [/pardot\.com$/i, "Pardot (Salesforce)", "marketing"],
  [/act-on\.net$|actonsoftware\.com$/i, "Act-On", "marketing"],
  [/salesforceliveagent\.com$|force\.com$|salesforce\.com$/i, "Salesforce", "marketing"],
  [/klaviyo\.com$|klaviyo\.net$|klaviyo-media\.com$/i, "Klaviyo", "marketing"],
  [/createsend\.com$|campaignmonitor\.com$|cmtags\.com$/i, "Campaign Monitor", "marketing"],
  [/sendgrid\.net$|sendgrid\.com$|sendgrid\.net$/i, "SendGrid", "marketing"],
  [/brevo\.com$|sendinblue\.com$|sib-api\.com$/i, "Brevo/Sendinblue", "marketing"],
  [/activecampaign\.com$|ac-email\.com$/i, "ActiveCampaign", "marketing"],
  [/mautic\.net$|mautic\.org$/i, "Mautic", "marketing"],
  [/mailgun\.org$|mailgun\.net$|mailgun\.message$/i, "Mailgun", "marketing"],
  [/postmarkapp\.com$/i, "Postmark", "marketing"],
  [/mailerlite\.com$/i, "MailerLite", "marketing"],
  [/omnisend\.com$/i, "Omnisend", "marketing"],
  [/moosend\.com$/i, "Moosend", "marketing"],

  /* ------------------------------- Social --------------------------------- */
  [/connect\.facebook\.net$|facebook\.net$|facebook\.com\/connect/i, "Facebook Connect", "social"],
  [/platform\.twitter\.com$|twitter\.com$|x\.com$|twimg\.com$/i, "Twitter/X", "social"],
  [/platform\.linkedin\.com$|linkedin\.com$|licdn\.com$/i, "LinkedIn", "social"],
  [/instagram\.com$|cdninstagram\.com$/i, "Instagram", "social"],
  [/pinterest\.com$|pinimg\.com$|widgets\.pinterest\.com$/i, "Pinterest", "social"],
  [/addthis\.com$|addthiscdn\.com$|s7\.addthis\.com$/i, "AddThis", "social"],
  [/sharethis\.com$|sharethiscdn\.com$/i, "ShareThis", "social"],
  [/addtoany\.com$/i, "AddToAny", "social"],
  [/tiktok\.com$|tiktokcdn\.com$|musical\.ly$/i, "TikTok", "social"],
  [/reddit\.com$|redditstatic\.com$|redditserved\.com$/i, "Reddit", "social"],
  [/disqus\.com$|disquscdn\.com$|disqusservice\.com$/i, "Disqus", "social"],

  /* --------------------------- Tag Management ----------------------------- */
  [/googletagmanager\.com$/i, "Google Tag Manager", "analytics"],
  [/segment\.(io|com)$/i, "Segment", "analytics"],
  [/tealium\.com$|tiqcdn\.com$/i, "Tealium", "analytics"],
  [/assets\.adobedtm\.com$|adobedtm\.com$/i, "Adobe DTM", "analytics"],
  [/ensighten\.com$|ensighten\.net$/i, "Ensighten", "analytics"],

  /* ------------------------------ Video/Media ----------------------------- */
  [/youtube\.com$|youtube-nocookie\.com$|ytimg\.com$/i, "YouTube", "video"],
  [/vimeo\.com$|vimeocdn\.com$|player\.vimeo\.com$/i, "Vimeo", "video"],
  [/wistia\.com$|wistia\.net$|fast\.wistia\.net$/i, "Wistia", "video"],
  [/jwplayer\.com$|jwpltx\.com$|jwpsrv\.com$|cdn\.jwplayer\.com$/i, "JW Player", "video"],
  [/brightcove\.com$|brightcove\.net$/i, "Brightcove", "video"],
  [/vidyard\.com$|vidyard\.net$/i, "Vidyard", "video"],
  [/dailymotion\.com$/i, "Dailymotion", "video"],
  [/twitch\.tv$|ttvnw\.net$|jtvnw\.net$/i, "Twitch", "video"],
  [/soundcloud\.com$|sndcdn\.com$/i, "SoundCloud", "video"],

  /* --------------------------- Authentication ----------------------------- */
  [/auth0\.com$|auth0cdn\.com$|tenant\.auth0\.com$/i, "Auth0", "auth"],
  [/okta\.com$|okta-evt\.com$|oktacdn\.com$/i, "Okta", "auth"],
  [/firebase\.google\.com$|firebaseapp\.com$/i, "Firebase Auth", "auth"],
  [/clerk\.com$|clerk\.dev$|clerkcdn\.com$/i, "Clerk", "auth"],
  [/onelogin\.com$|onelogin\.net$/i, "OneLogin", "auth"],
  [/duosecurity\.com$|duocdn\.com$/i, "Duo", "auth"],
  [/cognito-idp\..*\.amazonaws\.com$|amazoncognito\.com$/i, "AWS Cognito", "auth"],
  [/login\.microsoftonline\.com$|entra\.microsoft\.com$|login\.windows\.net$|login\.live\.com$|login\.microsoft\.com$/i, "Microsoft Entra/AAD", "auth"],
  [/accounts\.google\.com$/i, "Google Identity", "auth"],
  [/auth\.facebook\.com$|facebook\.com\/v.*\/auth/i, "Facebook Auth", "auth"],
  [/github\.com\/login\/oauth/i, "GitHub Auth", "auth"],
  [/stytch\.com$|stytch\.net$/i, "Stytch", "auth"],
  [/supabase\.co$|supabase\.net$/i, "Supabase Auth", "auth"],
  [/workos\.com$/i, "WorkOS", "auth"],

  /* ------------------------------ Consent --------------------------------- */
  [/cookiebot\.com$|cookiebot\.net$|cybot\.com$/i, "Cookiebot", "consent"],
  [/onetrust\.com$|cookielaw\.org$|onetrustcdn\.com$/i, "OneTrust", "consent"],
  [/trustarc\.com$|truste\.com$|truste-svc\.net$/i, "TrustArc", "consent"],
  [/cookieyes\.com$|cookieyes\.net$/i, "CookieYes", "consent"],
  [/quantcast\.com\/choice/i, "Quantcast Choice", "consent"],
  [/consent\.cmp\.oath\.com$|consent\.yahoo\.com$/i, "Yahoo Consent", "consent"],
  [/usercentrics\.eu$|usercentrics\.com$/i, "Usercentrics", "consent"],
  [/didomi\.io$|didomi\.net$/i, "Didomi", "consent"],
  [/consensu\.org$|quantcastconsent\.com$/i, "Quantcast Choice", "consent"],
  [/termly\.io$|termlycdn\.com$/i, "Termly", "consent"],
  [/iubenda\.com$|iubenda\.net$/i, "Iubenda", "consent"],
  [/consentmanager\.net$|consentmanager\.de$/i, "Consentmanager", "consent"],
  [/civiccomputing\.com$|civicuk\.com$/i, "Civic Cookie Control", "consent"],

  /* ----------------------------- Form/Calendly ---------------------------- */
  [/typeform\.com$|tf\.inq\.com$/i, "Typeform", "functional"],
  [/calendly\.com$|calendly\.net$|assets\.calendly\.com$/i, "Calendly", "functional"],
  [/cal\.com$|cal\.net$/i, "Cal.com", "functional"],
  [/hubspot\.com\/meetings/i, "HubSpot Meetings", "functional"],
  [/acuityscheduling\.com$/i, "Acuity Scheduling", "functional"],
  [/doodle\.com$|doodlecdn\.net$/i, "Doodle", "functional"],

  /* ----------------------- Irish/EU-relevant extras ---------------------- */
  [/irishlife\.ie$/i, "Irish Life", "unknown"],
  [/revenue\.ie$/i, "Revenue IE", "unknown"],
  [/gov\.ie$/i, "Irish Government", "unknown"],
  [/banksphere\.com$|aib\.ie$/i, "AIB", "payment"],
  [/bankofireland\.com$|boi\.com$/i, "Bank of Ireland", "payment"],
  [/ptsb\.ie$/i, "Permanent TSB", "payment"],
  [/avantmoney\.ie$/i, "Avant Money", "payment"],
  [/currencyfair\.com$/i, "CurrencyFair", "payment"],
];

/* -------------------------------------------------------------------------- */
/* SDK signatures (JS source detection)                                        */
/* -------------------------------------------------------------------------- */

export const SDK_SIGNATURES: Array<{
  regex: RegExp;
  domain: string;
  category: DomainCategory;
  name: string;
}> = [
  // --- Google Analytics / GTM ---
  { regex: /\bgtag\s*\(/, domain: "google-analytics.com", category: "analytics", name: "Google Analytics (gtag)" },
  { regex: /\bdataLayer\b/, domain: "googletagmanager.com", category: "analytics", name: "Google Tag Manager (dataLayer)" },
  { regex: /\bgoogletag\.cmd\.push\s*\(/, domain: "googlesyndication.com", category: "advertising", name: "Google Ad Manager (googletag)" },
  { regex: /\bgoogletag\.defineSlot\s*\(/, domain: "googlesyndication.com", category: "advertising", name: "Google Ad Manager (defineSlot)" },

  // --- Facebook / Meta Pixel ---
  { regex: /\bfbq\s*\(/, domain: "connect.facebook.net", category: "advertising", name: "Facebook Pixel (fbq)" },

  // --- Hotjar ---
  { regex: /\bhj\s*\(/, domain: "hotjar.com", category: "analytics", name: "Hotjar (hj)" },
  { regex: /\b_hjSettings\b/, domain: "hotjar.com", category: "analytics", name: "Hotjar (_hjSettings)" },

  // --- Mixpanel ---
  { regex: /\bmixpanel\.track\s*\(/, domain: "mixpanel.com", category: "analytics", name: "Mixpanel (track)" },
  { regex: /\bmixpanel\.init\s*\(/, domain: "mixpanel.com", category: "analytics", name: "Mixpanel (init)" },

  // --- Amplitude ---
  { regex: /\bamplitude\.getInstance\s*\(/, domain: "amplitude.com", category: "analytics", name: "Amplitude (getInstance)" },
  { regex: /\bamplitude\.logEvent\s*\(/, domain: "amplitude.com", category: "analytics", name: "Amplitude (logEvent)" },

  // --- Segment ---
  { regex: /\banalytics\.track\s*\(/, domain: "segment.io", category: "analytics", name: "Segment (track)" },
  { regex: /\banalytics\.page\s*\(/, domain: "segment.io", category: "analytics", name: "Segment (page)" },
  { regex: /\banalytics\.identify\s*\(/, domain: "segment.io", category: "analytics", name: "Segment (identify)" },

  // --- Plausible ---
  { regex: /\bplausible\s*\(/, domain: "plausible.io", category: "analytics", name: "Plausible (plausible())" },

  // --- Microsoft Clarity ---
  { regex: /\bclarity\s*\(/, domain: "clarity.ms", category: "analytics", name: "Microsoft Clarity (clarity())" },

  // --- Intercom ---
  { regex: /\bIntercom\s*\(/, domain: "intercom.io", category: "communication", name: "Intercom (Intercom())" },
  { regex: /\bintercomSettings\b/, domain: "intercom.io", category: "communication", name: "Intercom (intercomSettings)" },

  // --- Pusher ---
  { regex: /\bnew\s+Pusher\s*\(/, domain: "pusher.com", category: "communication", name: "Pusher (new Pusher)" },
  { regex: /\bPusher\.subscribe\s*\(/, domain: "pusher.com", category: "communication", name: "Pusher (subscribe)" },

  // --- Ably ---
  { regex: /\bnew\s+Ably\.Realtime\s*\(/, domain: "ably.io", category: "communication", name: "Ably (new Realtime)" },

  // --- Stripe ---
  { regex: /\bStripe\s*\(/, domain: "js.stripe.com", category: "payment", name: "Stripe (Stripe())" },
  { regex: /\bstripe\.elements\s*\(/, domain: "js.stripe.com", category: "payment", name: "Stripe (elements)" },

  // --- Sentry ---
  { regex: /\bSentry\.init\s*\(/, domain: "sentry.io", category: "monitoring", name: "Sentry (init)" },
  { regex: /\bSentry\.captureException\s*\(/, domain: "sentry.io", category: "monitoring", name: "Sentry (captureException)" },

  // --- Datadog ---
  { regex: /\bDD_LOGS\b/, domain: "datadoghq.com", category: "monitoring", name: "Datadog Logs (DD_LOGS)" },
  { regex: /\bDD_RUM\b/, domain: "datadoghq.com", category: "monitoring", name: "Datadog RUM (DD_RUM)" },
  { regex: /\bdatadogRum\.init\s*\(/, domain: "datadoghq.com", category: "monitoring", name: "Datadog RUM (datadogRum.init)" },

  // --- LinkedIn Insight ---
  { regex: /\b_linkedin_partner_id\b/, domain: "snap.licdn.com", category: "marketing", name: "LinkedIn Insight (_linkedin_partner_id)" },
  { regex: /\blinetrk\s*\(/, domain: "snap.licdn.com", category: "marketing", name: "LinkedIn Insight (linetrk)" },

  // --- Pinterest Tag ---
  { regex: /\bpintrk\s*\(/, domain: "s.pinimg.com", category: "advertising", name: "Pinterest Tag (pintrk)" },

  // --- Twitter/X Pixel ---
  { regex: /\btwq\s*\(/, domain: "static.ads-twitter.com", category: "advertising", name: "Twitter/X Pixel (twq)" },

  // --- Heap ---
  { regex: /\bheap\.track\s*\(/, domain: "heapanalytics.com", category: "analytics", name: "Heap (track)" },
  { regex: /\bheap\.load\s*\(/, domain: "heapanalytics.com", category: "analytics", name: "Heap (load)" },

  // --- FullStory ---
  { regex: /\bFS\.start\s*\(/, domain: "fullstory.com", category: "analytics", name: "FullStory (FS.start)" },
  { regex: /\bFS\.identify\s*\(/, domain: "fullstory.com", category: "analytics", name: "FullStory (FS.identify)" },
  { regex: /\bFS\.setVars\s*\(/, domain: "fullstory.com", category: "analytics", name: "FullStory (FS.setVars)" },

  // --- LogRocket ---
  { regex: /\bLogRocket\.init\s*\(/, domain: "logrocket.com", category: "monitoring", name: "LogRocket (init)" },
  { regex: /\bLogRocket\.identify\s*\(/, domain: "logrocket.com", category: "monitoring", name: "LogRocket (identify)" },

  // --- Matomo/Piwik ---
  { regex: /\b_paq\.push\s*\(/, domain: "matomo.org", category: "analytics", name: "Matomo/Piwik (_paq.push)" },
  { regex: /\b_paq\.setTrackerUrl\b/, domain: "matomo.org", category: "analytics", name: "Matomo/Piwik (setTrackerUrl)" },

  // --- OneTrust (consent) ---
  { regex: /\botSDKStub\b/, domain: "cdn.cookielaw.org", category: "consent", name: "OneTrust (otSDKStub)" },
  { regex: /\bOptanonConsent\b/, domain: "cdn.cookielaw.org", category: "consent", name: "OneTrust (OptanonConsent)" },

  // --- Cookiebot (consent) ---
  { regex: /\bCookieConsent\b/, domain: "consent.cookiebot.com", category: "consent", name: "Cookiebot (CookieConsent)" },
  { regex: /\bCybotCookiebotDialog\b/, domain: "consent.cookiebot.com", category: "consent", name: "Cookiebot (CybotCookiebotDialog)" },

  // --- Quantcast Choice ---
  { regex: /\b__tcfapi\b/, domain: "quantcast.mgr.consensu.org", category: "consent", name: "Quantcast Choice (__tcfapi)" },

  // --- Usercentrics ---
  { regex: /\bUC_UI\b/, domain: "api.usercentrics.eu", category: "consent", name: "Usercentrics (UC_UI)" },

  // --- Bugsnag ---
  { regex: /\bBugsnag\.start\s*\(/, domain: "bugsnag.com", category: "monitoring", name: "Bugsnag (start)" },

  // --- Rollbar ---
  { regex: /\bRollbar\.init\s*\(/, domain: "rollbar.com", category: "monitoring", name: "Rollbar (init)" },

  // --- hCaptcha ---
  { regex: /\bhcaptcha\.render\s*\(/, domain: "hcaptcha.com", category: "security", name: "hCaptcha (render)" },

  // --- reCAPTCHA ---
  { regex: /\bgrecaptcha\.render\s*\(/, domain: "recaptcha.net", category: "security", name: "reCAPTCHA (render)" },
  { regex: /\bgrecaptcha\.execute\s*\(/, domain: "recaptcha.net", category: "security", name: "reCAPTCHA (execute)" },

  // --- Cloudflare Turnstile ---
  { regex: /\bturnstile\.render\s*\(/, domain: "challenges.cloudflare.com", category: "security", name: "Cloudflare Turnstile (render)" },

  // --- HubSpot ---
  { regex: /\bhbspt\.forms\.create\s*\(/, domain: "js.hsforms.net", category: "marketing", name: "HubSpot Forms (hbspt)" },

  // --- Mailchimp ---
  { regex: /\bmailchimp\.co\./, domain: "mailchimp.com", category: "marketing", name: "Mailchimp (mailchimp.co)" },

  // --- Klaviyo ---
  { regex: /\bklaviyo\.identify\s*\(/, domain: "klaviyo.com", category: "marketing", name: "Klaviyo (identify)" },
  { regex: /\b_klOnsite\b/, domain: "klaviyo.com", category: "marketing", name: "Klaviyo (_klOnsite)" },

  // --- Marketo ---
  { regex: /\bMunchkin\.init\s*\(/, domain: "munchkin.marketo.net", category: "marketing", name: "Marketo (Munchkin)" },

  // --- Drift ---
  { regex: /\bdrift\.on\s*\(/, domain: "js.driftt.com", category: "communication", name: "Drift (drift.on)" },
  { regex: /\bdrift\.load\s*\(/, domain: "js.driftt.com", category: "communication", name: "Drift (drift.load)" },

  // --- Tawk.to ---
  { regex: /\bTawk_API\b/, domain: "tawk.to", category: "communication", name: "Tawk.to (Tawk_API)" },

  // --- Optimizely ---
  { regex: /\boptimizely\.push\s*\(/, domain: "optimizely.com", category: "testing", name: "Optimizely (push)" },
  { regex: /\boptimizely\.init\s*\(/, domain: "optimizely.com", category: "testing", name: "Optimizely (init)" },

  // --- VWO ---
  { regex: /\b_vwo_code\b/, domain: "vwo.com", category: "testing", name: "VWO (_vwo_code)" },
  { regex: /\bVWO\.push\s*\(/, domain: "vwo.com", category: "testing", name: "VWO (push)" },

  // --- Mouseflow ---
  { regex: /\bmouseflow\b/i, domain: "mouseflow.com", category: "analytics", name: "Mouseflow (mouseflow)" },

  // --- Lucky Orange ---
  { regex: /\b__lo\b/, domain: "luckyorange.com", category: "analytics", name: "Lucky Orange (__lo)" },

  // --- Chartbeat ---
  { regex: /\b_chartbeat\b/, domain: "chartbeat.com", category: "analytics", name: "Chartbeat (_chartbeat)" },
  { regex: /\bpSUPERFLY\b/, domain: "chartbeat.com", category: "analytics", name: "Chartbeat (pSUPERFLY)" },

  // --- Crazy Egg ---
  { regex: /\bCE2\b/, domain: "crazyegg.com", category: "analytics", name: "Crazy Egg (CE2)" },

  // --- Statcounter ---
  { regex: /\bsc_tracker\b/, domain: "statcounter.com", category: "analytics", name: "Statcounter (sc_tracker)" },
];

/* -------------------------------------------------------------------------- */
/* PII-risk categories                                                         */
/* -------------------------------------------------------------------------- */

const PII_CATEGORIES: ReadonlySet<DomainCategory> = new Set([
  "analytics",
  "advertising",
  "payment",
  "communication",
  "marketing",
]);

/* -------------------------------------------------------------------------- */
/* Classifier functions                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Domain patterns compiled to require a hostname label boundary at the start
 * of every match: a pattern may only match from the start of the hostname or
 * immediately after a dot. Without this, suffix alternatives such as `x\.com$`
 * also match the tail of unrelated hosts like `netflix.com` or `box.com`.
 */
const LABEL_BOUNDARY = "(?:^|\\.)";
const ANCHORED_DOMAIN_PATTERNS: Array<[RegExp, string, DomainCategory]> = DOMAIN_DATABASE.map(
  ([pattern, name, category]) => [
    new RegExp(`${LABEL_BOUNDARY}(?:${pattern.source.trim()})`, pattern.flags.replace(/[gy]/g, "")),
    name,
    category,
  ],
);

/**
 * Classify a hostname into a category and identify the service.
 * Matching is case-insensitive against the full hostname and can only begin
 * on a label boundary.
 */
export function classifyDomain(domain: string): DomainMatch {
  const lower = domain.toLowerCase().trim();
  for (const [pattern, name, category] of ANCHORED_DOMAIN_PATTERNS) {
    if (pattern.test(lower)) {
      return { category, name };
    }
  }
  return { category: "unknown", name: null };
}

/**
 * Detect SDK initialisation calls in raw JavaScript source.
 * Returns an array of matched SDKs (de-duplicated by name).
 */
export function detectSdks(jsSource: string): SdkMatch[] {
  const found = new Map<string, SdkMatch>();
  for (const sig of SDK_SIGNATURES) {
    if (sig.regex.test(jsSource)) {
      if (!found.has(sig.name)) {
        found.set(sig.name, {
          name: sig.name,
          domain: sig.domain,
          category: sig.category,
          match: sig.regex.source,
        });
      }
    }
  }
  return [...found.values()];
}

/**
 * Assess whether a domain+category is likely to transmit PII.
 * Categories like analytics, advertising, payment, communication,
 * and marketing typically collect and transmit user data.
 */
export function assessPiiRisk(domain: string, category: DomainCategory): boolean {
  // Always trust category-based assessment first
  if (PII_CATEGORIES.has(category)) return true;
  // Fall back to exact token matches for edge cases (e.g. an "unknown"
  // category host whose labels name a known data-collecting pattern).
  const tokens = domain.toLowerCase().split(".").flatMap((label) => label.split(/[-_]+/));
  return tokens.some((token) => PII_FALLBACK_TOKENS.has(token));
}

/** Exact-label tokens that indicate a possible data-collecting service.
 * Substring matching was rejected: it flagged innocuous hosts such as
 * `trackandfield.ie` or `soundtrack-cdn.example.com`. */
const PII_FALLBACK_TOKENS: ReadonlySet<string> = new Set([
  "analytics",
  "tracker",
  "tracking",
  "telemetry",
  "beacon",
  "pixel",
]);

/**
 * Quick membership check — does this hostname match anything in the database?
 */
export function isKnownDomain(domain: string): boolean {
  const lower = domain.toLowerCase().trim();
  for (const [pattern] of ANCHORED_DOMAIN_PATTERNS) {
    if (pattern.test(lower)) return true;
  }
  return false;
}

/**
 * Extract the registrable domain (eTLD+1) from a hostname using tldts.
 * Falls back to the original hostname if tldts can't parse it.
 */
export function registrableDomain(hostname: string): string {
  const result = tldtsGetDomain(hostname, { allowPrivateDomains: true });
  return result || hostname;
}

/**
 * Resolve a hostname to its registrable domain before classification.
 * Useful for subdomains like `www.google-analytics.com` or
 * `connect.facebook.net` where the registrable domain is sufficient.
 */
export function classifyHostname(hostname: string): DomainMatch {
  const lower = hostname.toLowerCase().trim();
  // First try matching on the full hostname (catches subdomain patterns)
  const direct = classifyDomain(lower);
  if (direct.category !== "unknown") return direct;
  // Then try the registrable domain
  const reg = registrableDomain(lower);
  if (reg !== lower) {
    return classifyDomain(reg);
  }
  return { category: "unknown", name: null };
}

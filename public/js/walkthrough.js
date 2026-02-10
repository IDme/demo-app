/**
 * ID.me Demo Walkthrough — Client-side Logic
 * Handles: step navigation, API inspector, popup auth, dynamic policy loading
 */

(function () {
  'use strict';

  const TOTAL_STEPS = 8;
  const STEP_TITLES = [
    'Welcome',
    'How It Works',
    'Configuration',
    'Choose Protocol',
    'Select Policy',
    'Live Demo',
    'Running Flow',
    'Results'
  ];

  // Protocol-specific configuration
  const PROTOCOL_CONFIG = {
    oauth: {
      label: 'OAuth 2.0',
      authEndpoint: '/oauth/authorize',
      authMethod: 'GET',
      callbackType: 'Authorization code via redirect',
      tokenEndpoint: '/oauth/token',
      dataEndpoint: '/api/public/v3/attributes',
      dataLabel: 'User Attributes',
      flowSteps: [
        'Redirect to /oauth/authorize',
        'User completes verification at ID.me',
        'Callback with authorization code',
        'POST /oauth/token — exchange code for access token',
        'GET /api/public/v3/attributes — fetch user data'
      ],
      resultTabs: [
        { id: 'token-exchange', label: 'Token Exchange', method: 'POST', endpoint: '/oauth/token' },
        { id: 'user-data', label: 'User Attributes', method: 'GET', endpoint: '/api/public/v3/attributes' }
      ],
      buildAuthParams: function(clientId, redirectUri, policyHandle) {
        return {
          client_id: clientId || '{client_id}',
          redirect_uri: redirectUri,
          response_type: 'code',
          scope: policyHandle
        };
      }
    },
    oidc: {
      label: 'OpenID Connect',
      authEndpoint: '/oauth/authorize',
      authMethod: 'GET',
      callbackType: 'Authorization code via redirect',
      tokenEndpoint: '/oauth/token',
      dataEndpoint: '/api/public/v3/userinfo',
      dataLabel: 'UserInfo (JWT)',
      flowSteps: [
        'Redirect to /oauth/authorize with openid scope',
        'User completes verification at ID.me',
        'Callback with authorization code',
        'POST /oauth/token — exchange code for access token',
        'GET /api/public/v3/userinfo — fetch JWT claims'
      ],
      resultTabs: [
        { id: 'token-exchange', label: 'Token Exchange', method: 'POST', endpoint: '/oauth/token' },
        { id: 'user-data', label: 'UserInfo (JWT)', method: 'GET', endpoint: '/api/public/v3/userinfo' }
      ],
      buildAuthParams: function(clientId, redirectUri, policyHandle) {
        return {
          client_id: clientId || '{client_id}',
          redirect_uri: redirectUri,
          response_type: 'code',
          scope: 'openid ' + policyHandle
        };
      }
    },
    saml: {
      label: 'SAML 2.0',
      authEndpoint: '/saml/SingleSignOnService',
      authMethod: 'GET',
      callbackType: 'SAML Assertion via POST to ACS URL',
      tokenEndpoint: null,
      dataEndpoint: null,
      dataLabel: 'SAML Assertion Attributes',
      flowSteps: [
        'Redirect to /saml/SingleSignOnService',
        'User completes verification at ID.me',
        'ID.me POSTs SAML Response to ACS URL',
        'Server parses XML assertion',
        'Extract verified attributes from assertion'
      ],
      resultTabs: [
        { id: 'saml-assertion', label: 'SAML Assertion', method: 'POST', endpoint: 'ACS Callback (POST)' }
      ],
      buildAuthParams: function(clientId, redirectUri, policyHandle) {
        return {
          EntityID: 'demo.idme.solutions',
          AuthnContext: policyHandle || '{policy_handle}',
          NameIDPolicy: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
          RelayState: 'popup'
        };
      }
    }
  };

  // State
  let currentStep = 1;
  let selectedProtocol = 'oauth';
  let selectedPolicy = null;
  let selectedEnv = 'sandbox';
  let policies = [];
  let authPopup = null;
  let authData = null;

  // DOM refs
  const btnBack = document.getElementById('btnBack');
  const btnNext = document.getElementById('btnNext');
  const stepIndicator = document.getElementById('stepIndicator');
  const stepTitle = document.getElementById('stepTitle');
  const progressFill = document.getElementById('progressFill');

  function getProtocolConfig() {
    return PROTOCOL_CONFIG[selectedProtocol] || PROTOCOL_CONFIG.oauth;
  }

  // Learn More toggle (event delegation)
  document.addEventListener('click', function(e) {
    const toggle = e.target.closest('.learn-more-toggle');
    if (toggle) {
      toggle.closest('.learn-more').classList.toggle('open');
    }
  });

  // Initialize
  function init() {
    btnBack.addEventListener('click', goBack);
    btnNext.onclick = goNext;

    // Protocol selection cards
    document.querySelectorAll('.selection-card[data-protocol]').forEach(card => {
      card.addEventListener('click', () => {
        document.querySelectorAll('.selection-card[data-protocol]').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        selectedProtocol = card.dataset.protocol;
      });
    });

    // Environment toggle
    document.querySelectorAll('.env-toggle-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.env-toggle-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        selectedEnv = btn.dataset.env;
        updateConfigDisplay();
      });
    });

    // Verify button
    const btnVerify = document.getElementById('btnVerify');
    if (btnVerify) {
      btnVerify.addEventListener('click', startAuthFlow);
    }

    // Listen for popup callback
    window.addEventListener('message', handlePopupMessage);

    updateStep();
  }

  // Navigation
  function goBack() {
    if (currentStep > 1) {
      currentStep--;
      updateStep();
    }
  }

  function goNext() {
    if (currentStep < TOTAL_STEPS) {
      currentStep++;
      updateStep();
    }
  }

  function updateStep() {
    stepIndicator.textContent = `Step ${currentStep} / ${TOTAL_STEPS}`;
    stepTitle.textContent = STEP_TITLES[currentStep - 1];
    progressFill.style.width = `${(currentStep / TOTAL_STEPS) * 100}%`;

    btnBack.disabled = currentStep === 1;

    // Hide Next on Step 6 — user must click "Verify with ID.me"
    if (currentStep === 6) {
      btnNext.style.display = 'none';
    } else {
      btnNext.style.display = '';
    }

    if (currentStep === TOTAL_STEPS) {
      btnNext.innerHTML = 'Restart <svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 4v4h4M15 12V8h-4"/><path d="M13.5 5.5A6 6 0 0 0 3 4.3L1 8m14 0l-2 3.7a6 6 0 0 1-10.5-1.2"/></svg>';
      btnNext.onclick = () => {
        currentStep = 1;
        authData = null;
        updateStep();
      };
    } else {
      btnNext.innerHTML = 'Next <svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 4l4 4-4 4"/></svg>';
      btnNext.onclick = goNext;
    }

    // Show/hide step sections
    document.querySelectorAll('.step-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll(`[data-step="${currentStep}"]`).forEach(s => s.classList.add('active'));

    // Step-specific hooks
    if (currentStep === 5) loadPolicies();
    if (currentStep === 6) renderStep6();
    if (currentStep === 7) renderStep7();
    if (currentStep === 8) renderStep8();
  }

  // --- Step 6: Live Demo (protocol-aware) ---
  function renderStep6() {
    const cfg = getProtocolConfig();
    const container = document.getElementById('step6RightContent');
    if (!container) return;

    const host = window.location.host;
    const clientId = selectedEnv === 'sandbox' ? window.__CONFIG__.sandboxClientId : window.__CONFIG__.prodClientId;
    const policyHandle = selectedPolicy ? selectedPolicy.handle : '{policy_handle}';
    const redirectUri = `${window.location.protocol}//${host}/callback/${selectedEnv}/${selectedProtocol}`;
    const authParams = cfg.buildAuthParams(clientId, redirectUri, policyHandle);

    const samlNotice = '';

    container.innerHTML = `
      <h1 class="step-heading">Live Demo — ${escapeHtml(cfg.label)}</h1>
      <p class="step-description">
        Click <strong>"Verify with ID.me"</strong> in the mock browser to start a real ${escapeHtml(cfg.label)} authentication flow. A popup window will open with the ID.me login page.
      </p>
      ${samlNotice}
      <div class="api-inspector" style="margin-top: 24px;">
        <div class="api-inspector-tabs" id="step6Tabs">
          <button class="api-tab active" data-tab="s6-intro">Auth Request</button>
          <button class="api-tab" data-tab="s6-flow">Flow Steps</button>
        </div>
        <div class="api-tab-content active" data-tab-content="s6-intro">
          <div class="api-call">
            <div class="api-call-header" onclick="this.nextElementSibling.classList.toggle('open')">
              <span class="api-method get">${escapeHtml(cfg.authMethod)}</span>
              <span class="api-endpoint">${escapeHtml(cfg.authEndpoint)}</span>
              <span class="api-status">Redirect</span>
            </div>
            <div class="api-call-body">
              <div class="json-viewer">${formatJson(authParams)}</div>
            </div>
          </div>
        </div>
        <div class="api-tab-content" data-tab-content="s6-flow">
          <div class="flow-status">
            ${cfg.flowSteps.map((s, i) => `
              <div class="flow-step pending">
                <div class="flow-step-icon">${i + 1}</div>
                <span>${escapeHtml(s)}</span>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
      ${buildStep6LearnMore()}
    `;

    // Re-bind tab clicks
    bindInspectorTabs(container);
  }

  function buildStep6LearnMore() {
    const proto = selectedProtocol;
    let title, body;

    if (proto === 'saml') {
      title = 'Learn More: SAML Authentication Request';
      body = `
        <h4>SAML SSO Initiation</h4>
        <p>Unlike OAuth/OIDC where your app builds a URL with query parameters, SAML uses a different model. Your app redirects the user to the Identity Provider's <strong>SingleSignOnService</strong> endpoint with SAML-specific parameters.</p>
        <h4>Key Parameters</h4>
        <ul>
          <li><strong><code>EntityID</code></strong> &mdash; Your Service Provider's unique identifier, registered with ID.me. This tells ID.me which SP configuration to use.</li>
          <li><strong><code>AuthnContext</code></strong> &mdash; The verification policy to apply (equivalent to OAuth scopes). Maps to a SAML AuthnContextClassRef.</li>
          <li><strong><code>NameIDPolicy</code></strong> &mdash; Specifies the format of the user identifier in the assertion (e.g. unspecified, email, persistent).</li>
          <li><strong><code>RelayState</code></strong> &mdash; An opaque value passed through the SAML flow. Useful for maintaining state (like returning to the right page after auth).</li>
        </ul>
        <h4>SP Metadata</h4>
        <p>Your Service Provider must publish an XML metadata document containing your ACS URL, EntityID, and signing certificate. ID.me uses this to validate requests and know where to send the SAML assertion.</p>
        <div class="lm-tip">
          <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 10.5a.75.75 0 110-1.5.75.75 0 010 1.5zM8.75 8a.75.75 0 01-1.5 0V5a.75.75 0 011.5 0v3z"/></svg>
          SAML assertions are signed XML. Always validate the signature against ID.me's public certificate before trusting the data.
        </div>
      `;
    } else if (proto === 'oidc') {
      title = 'Learn More: OpenID Connect Auth Request';
      body = `
        <h4>The <code>openid</code> Scope</h4>
        <p>Adding <code>openid</code> to the scope tells ID.me to treat this as an OIDC request. In addition to the access token, you'll receive an <strong>ID token</strong> &mdash; a signed JWT containing user claims. The scope combines <code>openid</code> with the policy handle.</p>
        <h4>Auth Request Parameters</h4>
        <ul>
          <li><strong><code>client_id</code></strong> &mdash; Your application's identifier issued by ID.me.</li>
          <li><strong><code>redirect_uri</code></strong> &mdash; Must exactly match a pre-registered callback URL. ID.me sends the auth code here.</li>
          <li><strong><code>response_type=code</code></strong> &mdash; Requests the authorization code flow (recommended for server-side apps).</li>
          <li><strong><code>scope</code></strong> &mdash; Space-separated list: <code>openid</code> + policy handle. Controls what claims appear in the ID token.</li>
          <li><strong><code>nonce</code></strong> (recommended) &mdash; A random value embedded in the ID token to prevent replay attacks.</li>
          <li><strong><code>state</code></strong> (recommended) &mdash; CSRF protection. Must be validated on callback.</li>
        </ul>
        <h4>OIDC Discovery</h4>
        <p>ID.me publishes an OpenID Connect discovery document at <code>/.well-known/openid-configuration</code>. This contains all the endpoint URLs, supported scopes, signing algorithms, and JWKS URI for token verification.</p>
        <div class="lm-tip">
          <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 10.5a.75.75 0 110-1.5.75.75 0 010 1.5zM8.75 8a.75.75 0 01-1.5 0V5a.75.75 0 011.5 0v3z"/></svg>
          Always verify the ID token's signature using ID.me's JWKS endpoint. Never trust the token payload without signature validation.
        </div>
      `;
    } else {
      title = 'Learn More: OAuth 2.0 Authorization Request';
      body = `
        <h4>Authorization Code Grant</h4>
        <p>The authorization code grant is the most secure OAuth flow for server-side apps. Your app redirects the user to ID.me, the user authenticates, and ID.me redirects back with a one-time <strong>authorization code</strong>. Your server then exchanges this code for an access token.</p>
        <h4>Auth Request Parameters</h4>
        <ul>
          <li><strong><code>client_id</code></strong> &mdash; Your application's public identifier issued by ID.me.</li>
          <li><strong><code>redirect_uri</code></strong> &mdash; The callback URL where ID.me sends the authorization code. Must exactly match a pre-registered URI.</li>
          <li><strong><code>response_type=code</code></strong> &mdash; Tells ID.me to return an authorization code (not an implicit token).</li>
          <li><strong><code>scope</code></strong> &mdash; The policy handle that determines what verification is required and what attributes are returned.</li>
          <li><strong><code>state</code></strong> (recommended) &mdash; A random string to prevent CSRF attacks. Verify it matches on callback.</li>
        </ul>
        <h4>Token Exchange</h4>
        <p>After receiving the code, your server makes a back-channel POST to <code>/oauth/token</code> with the code, client ID, client secret, and redirect URI. The response includes an <code>access_token</code> that you use to call the attributes API.</p>
        <div class="lm-tip">
          <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 10.5a.75.75 0 110-1.5.75.75 0 010 1.5zM8.75 8a.75.75 0 01-1.5 0V5a.75.75 0 011.5 0v3z"/></svg>
          Authorization codes are single-use and short-lived (typically 10 minutes). Exchange them promptly and never log them in production.
        </div>
      `;
    }

    return buildLearnMoreHtml(title, body);
  }

  // --- Step 7: Running Flow (protocol-aware) ---
  function renderStep7() {
    const cfg = getProtocolConfig();
    const container = document.getElementById('step7RightContent');
    if (!container) return;

    container.innerHTML = `
      <h1 class="step-heading">Running ${escapeHtml(cfg.label)} Flow</h1>
      <p class="step-description">
        The ID.me popup is open. Complete the verification flow in the popup window, then the results will appear here automatically.
      </p>
      <div class="flow-status" id="flowStatusLive">
        ${cfg.flowSteps.map((s, i) => {
          const cls = i === 0 ? 'complete' : (i === 1 ? 'active' : 'pending');
          const icon = i === 0 ? '\u2713' : String(i + 1);
          return `
            <div class="flow-step ${cls}">
              <div class="flow-step-icon">${icon}</div>
              <span>${i === 1 ? 'Waiting for user verification...' : escapeHtml(s)}</span>
            </div>
          `;
        }).join('')}
      </div>
      ${buildStep7LearnMore()}
    `;
  }

  function buildStep7LearnMore() {
    const proto = selectedProtocol;
    let title, body;

    if (proto === 'saml') {
      title = 'Learn More: SAML Flow Internals';
      body = `
        <h4>What Happens During the SAML Flow</h4>
        <p>When the user is redirected to ID.me's SingleSignOnService, they go through the verification process defined by your AuthnContext. Behind the scenes:</p>
        <ul>
          <li><strong>SP-Initiated SSO</strong> &mdash; Your app (the Service Provider) initiates the request. ID.me (the Identity Provider) authenticates the user and sends back an assertion.</li>
          <li><strong>HTTP POST Binding</strong> &mdash; After authentication, ID.me POSTs a signed SAML Response to your ACS URL. The response contains the assertion inside a base64-encoded <code>SAMLResponse</code> form field.</li>
          <li><strong>Assertion Contents</strong> &mdash; The XML assertion contains the NameID, attribute statements (verified user data), conditions (audience restriction, time validity), and a digital signature.</li>
        </ul>
        <h4>Signature Validation</h4>
        <p>The SAML assertion is signed with ID.me's private key. Your ACS endpoint must validate this signature using ID.me's public certificate (from their IdP metadata). This ensures the assertion wasn't tampered with in transit.</p>
        <h4>Assertion Conditions</h4>
        <p>Every assertion has time-based conditions: <code>NotBefore</code> and <code>NotOnOrAfter</code>. Your server must reject assertions outside this window. Additionally, the <code>Audience</code> restriction must match your EntityID.</p>
        <div class="lm-tip">
          <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 10.5a.75.75 0 110-1.5.75.75 0 010 1.5zM8.75 8a.75.75 0 01-1.5 0V5a.75.75 0 011.5 0v3z"/></svg>
          Never process a SAML assertion without validating the XML signature. An unvalidated assertion could be forged by an attacker.
        </div>
      `;
    } else if (proto === 'oidc') {
      title = 'Learn More: OIDC Flow Internals';
      body = `
        <h4>What Happens During the OIDC Flow</h4>
        <p>The OIDC authorization code flow extends OAuth 2.0 with identity-specific features:</p>
        <ul>
          <li><strong>User Authentication</strong> &mdash; ID.me authenticates the user and performs any required identity proofing based on the requested scope.</li>
          <li><strong>Code Callback</strong> &mdash; ID.me redirects to your callback URL with a <code>code</code> parameter (and your <code>state</code> if sent).</li>
          <li><strong>Token Exchange</strong> &mdash; Your server POSTs the code to <code>/oauth/token</code> and receives an <code>access_token</code>, an <code>id_token</code> (JWT), and optionally a <code>refresh_token</code>.</li>
          <li><strong>UserInfo (optional)</strong> &mdash; You can also call <code>/api/public/v3/userinfo</code> with the access token to get additional claims.</li>
        </ul>
        <h4>ID Token (JWT) Structure</h4>
        <p>The ID token is a signed JWT with three parts: header, payload, and signature. The payload contains claims like:</p>
        <ul>
          <li><code>iss</code> &mdash; Issuer (ID.me's identifier)</li>
          <li><code>sub</code> &mdash; Subject (user's unique ID)</li>
          <li><code>aud</code> &mdash; Audience (your client_id)</li>
          <li><code>exp</code> / <code>iat</code> &mdash; Expiration and issued-at timestamps</li>
          <li><code>nonce</code> &mdash; Must match the nonce you sent</li>
          <li>Identity claims (name, email, etc.) based on scope</li>
        </ul>
        <h4>Token Verification</h4>
        <p>Fetch ID.me's public keys from the JWKS URI (found in the discovery document). Verify the JWT's <code>alg</code>, signature, <code>iss</code>, <code>aud</code>, <code>exp</code>, and <code>nonce</code> before trusting the claims.</p>
        <div class="lm-tip">
          <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 10.5a.75.75 0 110-1.5.75.75 0 010 1.5zM8.75 8a.75.75 0 01-1.5 0V5a.75.75 0 011.5 0v3z"/></svg>
          ID tokens prove identity but don't grant API access. Use the access token for API calls and the ID token for user identification.
        </div>
      `;
    } else {
      title = 'Learn More: OAuth 2.0 Flow Internals';
      body = `
        <h4>What Happens During the OAuth Flow</h4>
        <p>The authorization code grant flow involves several behind-the-scenes steps:</p>
        <ul>
          <li><strong>User Authorization</strong> &mdash; ID.me authenticates the user and presents any required verification steps based on the requested scope (policy).</li>
          <li><strong>Code Callback</strong> &mdash; After the user consents, ID.me redirects to your callback URL with a <code>code</code> query parameter. This code is single-use and expires quickly.</li>
          <li><strong>Token Exchange</strong> &mdash; Your server sends a back-channel POST to <code>/oauth/token</code> including the code, client_id, client_secret, and redirect_uri. ID.me verifies everything and returns an access token.</li>
          <li><strong>Attribute Retrieval</strong> &mdash; Your server calls <code>/api/public/v3/attributes</code> with the access token in the Authorization header to get the verified user data.</li>
        </ul>
        <h4>Access Token Handling</h4>
        <p>The access token is a bearer token &mdash; anyone with the token can access the user's data. Best practices:</p>
        <ul>
          <li>Store tokens server-side only (never in client-side JS or cookies)</li>
          <li>Use tokens immediately and don't cache them longer than necessary</li>
          <li>Transport tokens only over HTTPS (in the <code>Authorization: Bearer</code> header)</li>
          <li>Implement token expiration handling and refresh logic</li>
        </ul>
        <h4>Error Handling</h4>
        <p>Common errors: <code>invalid_grant</code> (code expired or redirect_uri mismatch), <code>invalid_client</code> (wrong credentials), <code>access_denied</code> (user cancelled). Your app should handle these gracefully and show user-friendly messages.</p>
        <div class="lm-tip">
          <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 10.5a.75.75 0 110-1.5.75.75 0 010 1.5zM8.75 8a.75.75 0 01-1.5 0V5a.75.75 0 011.5 0v3z"/></svg>
          If you receive an <code>invalid_grant</code> error, the most common cause is a redirect_uri mismatch between your auth request and token exchange.
        </div>
      `;
    }

    return buildLearnMoreHtml(title, body);
  }

  // --- Step 8: Results (protocol-aware) ---
  function renderStep8() {
    const cfg = getProtocolConfig();
    const container = document.getElementById('step8RightContent');
    if (!container) return;

    const tabButtons = cfg.resultTabs.map((tab, i) =>
      `<button class="api-tab ${i === 0 ? 'active' : ''}" data-tab="r-${tab.id}">${escapeHtml(tab.label)}</button>`
    ).join('');

    const tabContents = cfg.resultTabs.map((tab, i) => `
      <div class="api-tab-content ${i === 0 ? 'active' : ''}" data-tab-content="r-${tab.id}">
        <div class="api-call">
          <div class="api-call-header" onclick="this.nextElementSibling.classList.toggle('open')">
            <span class="api-method ${tab.method.toLowerCase()}">${escapeHtml(tab.method)}</span>
            <span class="api-endpoint" id="resultEndpoint_${tab.id}">${escapeHtml(tab.endpoint)}</span>
            <span class="api-status" id="resultStatus_${tab.id}">Pending</span>
            <span class="api-timing" id="resultTiming_${tab.id}"></span>
          </div>
          <div class="api-call-body">
            <div class="json-viewer" id="resultJson_${tab.id}">
              <span class="text-muted">Waiting for auth flow...</span>
            </div>
          </div>
        </div>
      </div>
    `).join('');

    const hasData = authData !== null;
    const descriptionText = hasData
      ? 'Authentication complete! Below are the verified identity attributes returned from ID.me.'
      : `Complete the ${cfg.label} auth flow to see verified identity attributes returned from ID.me.`;

    container.innerHTML = `
      <h1 class="step-heading">Results — ${escapeHtml(cfg.label)}</h1>
      <p class="step-description" id="resultsDescription">${descriptionText}</p>

      <div class="api-inspector">
        <div class="api-inspector-tabs" id="step8Tabs">${tabButtons}</div>
        ${tabContents}
      </div>
      ${buildStep8LearnMore()}
    `;

    // Re-bind tab clicks
    bindInspectorTabs(container);

    // If we have data, populate it
    if (hasData) {
      populateResults(authData);
    }
  }

  function buildStep8LearnMore() {
    const proto = selectedProtocol;
    let title, body;

    if (proto === 'saml') {
      title = 'Learn More: Understanding SAML Response Data';
      body = `
        <h4>SAML Assertion Anatomy</h4>
        <p>The data shown above was extracted from a SAML assertion &mdash; a signed XML document. A full SAML Response contains:</p>
        <ul>
          <li><strong>Issuer</strong> &mdash; ID.me's entity ID, identifying who issued the assertion</li>
          <li><strong>NameID</strong> &mdash; The user's unique identifier in the format specified by your NameIDPolicy</li>
          <li><strong>Conditions</strong> &mdash; Time validity (<code>NotBefore</code>/<code>NotOnOrAfter</code>) and audience restriction (must match your EntityID)</li>
          <li><strong>AttributeStatement</strong> &mdash; The verified user attributes (name, email, UUID, etc.) as XML <code>&lt;Attribute&gt;</code> elements</li>
          <li><strong>Signature</strong> &mdash; An XML digital signature over the assertion (or the entire response)</li>
        </ul>
        <h4>Attribute Mapping</h4>
        <p>SAML attributes use URN-style names (e.g. <code>urn:oasis:names:tc:SAML:2.0:attrname-format:basic</code>). Your application needs to map these attribute names to your internal user model. Most ID.me attributes use simple names like <code>fname</code>, <code>lname</code>, <code>email</code>, <code>uuid</code>.</p>
        <h4>Session Management</h4>
        <p>After validating the assertion, create a local session for the user. Don't rely on the SAML assertion for ongoing session management &mdash; it's a one-time authentication event. Implement your own session timeout and re-authentication policies.</p>
        <div class="lm-tip">
          <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 10.5a.75.75 0 110-1.5.75.75 0 010 1.5zM8.75 8a.75.75 0 01-1.5 0V5a.75.75 0 011.5 0v3z"/></svg>
          Store the user's ID.me UUID as the primary identifier. Map it to your internal user ID to handle returning users across sessions.
        </div>
      `;
    } else if (proto === 'oidc') {
      title = 'Learn More: Understanding OIDC Response Data';
      body = `
        <h4>Token Response</h4>
        <p>The token exchange returns multiple values:</p>
        <ul>
          <li><strong><code>access_token</code></strong> &mdash; A bearer token for calling the UserInfo endpoint and other APIs</li>
          <li><strong><code>id_token</code></strong> &mdash; A signed JWT containing the user's identity claims</li>
          <li><strong><code>token_type</code></strong> &mdash; Always "Bearer"</li>
          <li><strong><code>expires_in</code></strong> &mdash; Token lifetime in seconds</li>
        </ul>
        <h4>JWT Claims Explained</h4>
        <p>The ID token payload includes standard OIDC claims plus ID.me-specific verified attributes:</p>
        <ul>
          <li><strong>Standard claims:</strong> <code>iss</code>, <code>sub</code>, <code>aud</code>, <code>exp</code>, <code>iat</code>, <code>nonce</code></li>
          <li><strong>Identity claims:</strong> <code>email</code>, <code>given_name</code>, <code>family_name</code>, etc.</li>
          <li><strong>Verification claims:</strong> ID.me-specific fields indicating verification level and status</li>
        </ul>
        <h4>Using the Data</h4>
        <p>After verifying the ID token signature and claims, extract the <code>sub</code> claim as the user's stable identifier. Map it to your internal user accounts. The ID token is self-contained &mdash; you don't need to call ID.me again to verify identity.</p>
        <div class="lm-tip">
          <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 10.5a.75.75 0 110-1.5.75.75 0 010 1.5zM8.75 8a.75.75 0 01-1.5 0V5a.75.75 0 011.5 0v3z"/></svg>
          The <code>sub</code> claim is a stable, unique identifier for the user. Use it as the primary key when linking to your user database.
        </div>
      `;
    } else {
      title = 'Learn More: Understanding OAuth Response Data';
      body = `
        <h4>Token Exchange Response</h4>
        <p>The <code>/oauth/token</code> endpoint returns:</p>
        <ul>
          <li><strong><code>access_token</code></strong> &mdash; A bearer token used to call ID.me's APIs on behalf of the user</li>
          <li><strong><code>token_type</code></strong> &mdash; Always "Bearer"</li>
          <li><strong><code>expires_in</code></strong> &mdash; How long the token is valid (in seconds)</li>
        </ul>
        <h4>User Attributes Response</h4>
        <p>The <code>/api/public/v3/attributes</code> endpoint returns verified user data as JSON. Common fields include:</p>
        <ul>
          <li><strong><code>uuid</code></strong> &mdash; The user's unique ID.me identifier (stable across sessions)</li>
          <li><strong><code>fname</code> / <code>lname</code></strong> &mdash; First and last name</li>
          <li><strong><code>email</code></strong> &mdash; Verified email address</li>
          <li><strong><code>zip</code></strong> &mdash; ZIP code (if in scope)</li>
          <li><strong><code>group</code></strong> &mdash; Verified group affiliation (if applicable)</li>
          <li><strong><code>verified</code></strong> &mdash; Whether the user passed identity proofing</li>
        </ul>
        <h4>Linking Users</h4>
        <p>Use the <code>uuid</code> field as the primary identifier when linking ID.me verification to your user accounts. This value is consistent across sessions and won't change even if the user updates their name or email.</p>
        <h4>Data Minimization</h4>
        <p>Only store the attributes your application actually needs. Avoid caching raw API responses. If you only need to confirm group membership, don't store the user's full name and address.</p>
        <div class="lm-tip">
          <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm0 10.5a.75.75 0 110-1.5.75.75 0 010 1.5zM8.75 8a.75.75 0 01-1.5 0V5a.75.75 0 011.5 0v3z"/></svg>
          Re-verify users periodically for sensitive operations. A one-time verification may not be sufficient for ongoing high-assurance access.
        </div>
      `;
    }

    return buildLearnMoreHtml(title, body);
  }

  function buildLearnMoreHtml(title, body) {
    return `
      <div class="learn-more">
        <button class="learn-more-toggle">
          ${escapeHtml(title)}
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6l4 4 4-4"/></svg>
        </button>
        <div class="learn-more-body">
          ${body}
        </div>
      </div>
    `;
  }

  function bindInspectorTabs(root) {
    root.querySelectorAll('.api-inspector-tabs').forEach(tabBar => {
      tabBar.querySelectorAll('.api-tab').forEach(tab => {
        tab.addEventListener('click', () => {
          const inspector = tabBar.closest('.api-inspector');
          inspector.querySelectorAll('.api-tab').forEach(t => t.classList.remove('active'));
          inspector.querySelectorAll('.api-tab-content').forEach(c => c.classList.remove('active'));
          tab.classList.add('active');
          const content = inspector.querySelector(`[data-tab-content="${tab.dataset.tab}"]`);
          if (content) content.classList.add('active');
        });
      });
    });
  }

  function updateConfigDisplay() {
    const domain = selectedEnv === 'sandbox' ? 'api.idmelabs.com' : 'api.id.me';
    const clientId = selectedEnv === 'sandbox'
      ? window.__CONFIG__.sandboxClientId
      : window.__CONFIG__.prodClientId;

    document.getElementById('configDomain').textContent = domain;
    document.getElementById('configClientId').textContent = clientId
      ? clientId.substring(0, 8) + '...'
      : 'Not configured';
  }

  // Policy Loading
  async function loadPolicies() {
    const container = document.getElementById('policyContainer');
    container.innerHTML = '<div class="policy-loading"><div class="spinner"></div><div>Loading policies...</div></div>';

    try {
      const res = await fetch(`/api/policies/${selectedEnv}`);
      if (!res.ok) throw new Error('Failed to fetch policies');
      policies = await res.json();
      renderPolicies();
    } catch (err) {
      container.innerHTML = '<div class="policy-loading">Failed to load policies. Check your configuration.</div>';
    }
  }

  function renderPolicies() {
    const container = document.getElementById('policyContainer');
    if (!policies.length) {
      container.innerHTML = '<div class="policy-loading">No policies found.</div>';
      return;
    }

    const grid = document.createElement('div');
    grid.className = 'policy-grid';

    policies.forEach(policy => {
      const card = document.createElement('div');
      card.className = 'policy-card';
      if (selectedPolicy && selectedPolicy.handle === policy.handle) {
        card.classList.add('selected');
      }
      card.innerHTML = `
        <div class="policy-card-name">${escapeHtml(policy.name || policy.handle)}</div>
        <div class="policy-card-handle">${escapeHtml(policy.handle)}</div>
      `;
      card.addEventListener('click', () => {
        container.querySelectorAll('.policy-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        selectedPolicy = policy;
      });
      grid.appendChild(card);
    });

    container.innerHTML = '';
    container.appendChild(grid);
  }

  // Auth Flow
  function startAuthFlow() {
    if (!selectedPolicy && policies.length > 0) {
      selectedPolicy = policies[0];
    }

    if (!selectedPolicy) {
      alert('Please go back and select a policy first.');
      return;
    }

    const host = window.location.host;
    const envConfig = selectedEnv === 'sandbox'
      ? { domain: 'https://api.idmelabs.com', clientId: window.__CONFIG__.sandboxClientId }
      : { domain: 'https://api.id.me', clientId: window.__CONFIG__.prodClientId };

    const redirectUri = `${window.location.protocol}//${host}/callback/${selectedEnv}/${selectedProtocol}?popup=1`;

    let authUrl;
    if (selectedProtocol === 'saml') {
      authUrl = `${envConfig.domain}/saml/SingleSignOnService?EntityID=demo.idme.solutions&AuthnContext=${encodeURIComponent(selectedPolicy.handle)}&NameIDPolicy=urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified&RelayState=popup`;
    } else if (selectedProtocol === 'oidc') {
      authUrl = `${envConfig.domain}/oauth/authorize?client_id=${envConfig.clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid ${encodeURIComponent(selectedPolicy.handle)}`;
    } else {
      authUrl = `${envConfig.domain}/oauth/authorize?client_id=${envConfig.clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent(selectedPolicy.handle)}`;
    }

    // Open popup
    authPopup = window.open(authUrl, 'idme_auth', 'width=500,height=700,scrollbars=yes');

    if (!authPopup || authPopup.closed) {
      alert('Popup was blocked. Please allow popups for this site and try again.');
      return;
    }

    // Advance to step 7 (running flow)
    currentStep = 7;
    updateStep();
  }

  function handlePopupMessage(event) {
    if (!event.data || event.data.type !== 'idme_callback') return;

    authData = event.data.data;

    // Mark all flow steps complete
    const steps = document.querySelectorAll('#flowStatusLive .flow-step');
    steps.forEach(step => {
      step.className = 'flow-step complete';
      step.querySelector('.flow-step-icon').textContent = '\u2713';
    });

    // Advance to results step
    currentStep = 8;
    updateStep();
  }

  function populateResults(data) {
    if (!data) return;

    const cfg = getProtocolConfig();
    const displayData = data.userData || data;

    // Results table
    const tbody = document.getElementById('resultsBody');
    if (tbody) {
      tbody.innerHTML = '';
      Object.entries(displayData).forEach(([key, value]) => {
        const tr = document.createElement('tr');
        const displayValue = typeof value === 'object' ? JSON.stringify(value) : String(value);
        tr.innerHTML = `<td>${escapeHtml(key)}</td><td>${escapeHtml(displayValue)}</td>`;
        tbody.appendChild(tr);
      });
    }

    // Update description
    const desc = document.getElementById('resultsDescription');
    if (desc) desc.textContent = 'Authentication complete! Below are the verified identity attributes returned from ID.me.';

    // Populate result tabs based on protocol
    if (selectedProtocol === 'saml') {
      // SAML: single tab with assertion attributes
      const jsonEl = document.getElementById('resultJson_saml-assertion');
      const statusEl = document.getElementById('resultStatus_saml-assertion');
      if (jsonEl) jsonEl.innerHTML = formatJson(displayData);
      if (statusEl) {
        statusEl.textContent = '200 OK';
        statusEl.style.background = '#e8f5e9';
        statusEl.style.color = '#28a745';
      }
    } else {
      // OAuth / OIDC: token exchange + user data tabs
      const clientId = selectedEnv === 'sandbox' ? window.__CONFIG__.sandboxClientId : window.__CONFIG__.prodClientId;

      const tokenJsonEl = document.getElementById('resultJson_token-exchange');
      const tokenStatusEl = document.getElementById('resultStatus_token-exchange');
      if (tokenJsonEl) {
        tokenJsonEl.innerHTML = formatJson({
          grant_type: 'authorization_code',
          code: data.code || 'AUTHORIZATION_CODE',
          client_id: clientId,
          client_secret: '***REDACTED***',
          redirect_uri: `${window.location.protocol}//${window.location.host}/callback/${selectedEnv}/${selectedProtocol}`
        });
      }
      if (tokenStatusEl) {
        tokenStatusEl.textContent = '200 OK';
        tokenStatusEl.style.background = '#e8f5e9';
        tokenStatusEl.style.color = '#28a745';
      }

      const userJsonEl = document.getElementById('resultJson_user-data');
      const userStatusEl = document.getElementById('resultStatus_user-data');
      if (userJsonEl) userJsonEl.innerHTML = formatJson(data.payload || displayData);
      if (userStatusEl) {
        userStatusEl.textContent = '200 OK';
        userStatusEl.style.background = '#e8f5e9';
        userStatusEl.style.color = '#28a745';
      }
    }
  }

  // JSON Formatter
  function formatJson(obj) {
    const json = JSON.stringify(obj, null, 2);
    const lines = json.split('\n');
    return lines.map((line, i) => {
      const num = i + 1;
      const highlighted = syntaxHighlight(escapeHtml(line));
      return `<div class="json-line"><span class="json-line-number">${num}</span><span class="json-line-content">${highlighted}</span></div>`;
    }).join('');
  }

  function syntaxHighlight(str) {
    str = str.replace(/(&quot;)([\w\-./: @]+)(&quot;)\s*:/g,
      '<span class="json-key">$1$2$3</span>:');
    str = str.replace(/:\s*(&quot;)(.*?)(&quot;)/g,
      ': <span class="json-string">$1$2$3</span>');
    str = str.replace(/(&quot;)(.*?)(&quot;)/g,
      '<span class="json-string">$1$2$3</span>');
    str = str.replace(/:\s*(\d+\.?\d*)/g,
      ': <span class="json-number">$1</span>');
    str = str.replace(/:\s*(true|false)/g,
      ': <span class="json-boolean">$1</span>');
    str = str.replace(/:\s*(null)/g,
      ': <span class="json-null">$1</span>');
    return str;
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // Init on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

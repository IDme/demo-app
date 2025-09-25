import express, { json } from 'express'
import axios from 'axios'
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken'
import bodyParser from 'body-parser';
import { DOMParser } from 'xmldom';
import xpath from 'xpath'
import 'dotenv/config';

import xml from 'xml'

const app = express()
const port = process.env.PORT || 5001

app.use(express.static('public'));
app.use(json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

app.set('view engine', 'ejs');
app.set('views', './views');

const federatedProtocols = ['oauth', 'oidc', 'saml']
const envConig = {
  'prod': {
    'envDomain': `https://api.id.me`,
    'clientID': process.env.PRODUCTION_CLIENT_ID,
    'clientSecret': process.env.PRODUCTION_CLIENT_SECRET,
  },
  'sandbox': {
    'envDomain': `https://api.idmelabs.com`,
    'clientID': process.env.SANDBOX_CLIENT_ID,
    'clientSecret': process.env.SANDBOX_CLIENT_SECRET,
  }
}

const policiesEndpoint = (envDomain, clientID, clientSecret) => {
  return `${envDomain}/api/public/v3/policies.json?client_id=${clientID}&client_secret=${clientSecret}`
}
const apiEndpoint = (envDomain, dataEndpoint, accessToken) => {
  return `${envDomain}/api/public/v3/${dataEndpoint}.json?access_token=${accessToken}`
}

const isObject = (value) => {
  return value !== null && typeof value === 'object';
}

app.param('env', function(req, res, next){
  if (envConig[req.params.env]) {
    next();
  } else {
    next(res.status(404).send('failed to find environment'));
  }
});

app.param('protocol', function(req, res, next){
  if (federatedProtocols.includes(req.params.protocol)) {
    next();
  } else {
    next(res.status(404).send('failed to find protocol'));
  }
});

app.param('policy', async function(req, res, next){
  const { env, policy } = req.params 
  const { envDomain, clientID, clientSecret } = envConig[env]

  try {
    const apiResponse = await axios.get(policiesEndpoint(envDomain, clientID, clientSecret));
    const policies = apiResponse.data.map(policy => policy.handle)

    if (policies.includes(policy) || policy == 'groups') {
      next();
    } else {
      next(res.status(404).send('failed to find policy'));
    }
  } catch (error) {
    console.error('Error making API request:', error);
    res.status(500).send('An error occurred');
  } 
});

app.get('/', (req, res) => {
  try {
    res.render('index', { 
    });
  } catch (error) {
    console.error('Error making API request:', error);
    res.status(500).send('An error occurred');
  } 
});

app.get('/idme/:env', async (req, res) => {
  const { env } = req.params 

  try {
    res.render('env', { 
      env: env,
    });
  } catch (error) {
    console.error('Error making API request:', error);
    res.status(500).send('An error occurred');
  } 
});

app.get('/idme/:env/:protocol', async (req, res) => {
  const { env, protocol } = req.params 
  const { envDomain, clientID, clientSecret } = envConig[env]

  try {
    const apiResponse = await axios.get(policiesEndpoint(envDomain, clientID, clientSecret));
    const policies = apiResponse.data
    
    res.render('policies', { 
      policies: policies,
      env: env,
      protocol: protocol,
    });
  } catch (error) {
    console.error('Error making API request:', error);
    res.status(500).send('An error occurred');
  } 
});

app.get('/idme/:env/:protocol/:policy', function (req, res) {
  const { env, protocol, policy } = req.params
  const { envDomain, clientID } = envConig[env]
  const { state, eid, groups } = req.query
  const { host } = req.headers
  const isSAML = protocol == 'saml'
  const oauthEndpoint = policy == 'groups' ? `https://groups.id.me` : `${envDomain}/oauth/authorize`
  const authEndpoint = isSAML ? `${envDomain}/saml/SingleSignOnService` : oauthEndpoint

  const protocolPolicy = policy == 'groups' ? 'groups' : protocol

  let params = null

  switch (protocolPolicy) {
    case 'groups':
      params = `?client_id=${clientID}&redirect_uri=https://${host}/callback/${env}/${protocol}&response_type=code&scopes=${groups}&sandbox=${env == 'sandbox'}`
      break;
    case 'oauth':
      params = `?client_id=${clientID}&redirect_uri=https://${host}/callback/${env}/${protocol}&response_type=code&scope=${policy}`
      break;
    case 'oidc':
      params = `?client_id=${clientID}&redirect_uri=https://${host}/callback/${env}/${protocol}&response_type=code&scope=openid ${policy}`
      break;
    case 'saml':
      params = `?EntityID=demo.idme.solutions&AuthnContext=${policy}&NameIDPolicy=urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`
      break;
  }

  if (state) {params = `${params}&state=${state}`}
  if (eid) {params = `${params}&eid=${eid}`}

  res.redirect(`${authEndpoint}${params}`)
});

app.get('/callback/:env/:protocol', async function (req, res) {
  const authorizationCode = req.query.code;
  const { env, protocol } = req.params
  const { envDomain, clientID, clientSecret } = envConig[env]
  const { host } = req.headers
  const isOIDC = protocol == 'oidc'
  const dataEndpoint = isOIDC ? 'userinfo' : 'attributes'
  
  if (!authorizationCode) {
    return res.status(400).send('Authorization code not provided');
  }

  try {
    const tokenResponse = await axios.post(`${envDomain}/oauth/token`, {
      code: authorizationCode,
      client_id: clientID,
      client_secret: clientSecret,
      redirect_uri: `https://${host}/callback/${env}/${protocol}`,
      grant_type: 'authorization_code'
    });
    
    const accessToken = tokenResponse.data.access_token;
    const apiResponse = await axios.get(apiEndpoint(envDomain, dataEndpoint, accessToken));
    const data = isOIDC 
      ? jwt.decode(apiResponse.data) 
      : apiResponse.data.attributes.reduce((attributes, attribute) => {
          attributes[attribute.handle] = attribute.value;
          return attributes;
        }, {})

        
    res.clearCookie
    res.cookie('idmePayload', apiResponse.data, { expires: new Date(Date.now() + 60000) })
    res.cookie('idmeData', data, { expires: new Date(Date.now() + 60000) })
    res.redirect('/profile');
  } catch (error) {
    console.error('Error exchanging authorization code or making API request:', error);
    res.status(500).send('An error occurred');
  }
});

app.post('/callback/:env/:protocol', function (req, res) {
  const samlResponse = req.body.SAMLResponse;
  
  let decodedResponse = atob(samlResponse);

  const doc = new DOMParser().parseFromString(decodedResponse, 'text/xml');
  
  const assertion = xpath.select1("//*[local-name()='Assertion']", doc);

  if (assertion) {
    const attributes = xpath.select("//*[local-name()='Attribute']", assertion);

    let idmeData = {}
    
    attributes.forEach(attribute => {
      const name = attribute.getAttribute('Name');
      const values = xpath.select("./*[local-name()='AttributeValue']", attribute).map(valueNode => valueNode.textContent);

      values.forEach(value => idmeData[name] = value);
    });

    res.clearCookie
    res.cookie('idmePayload', String(attributes), { expires: new Date(Date.now() + 60000) })
    res.cookie('idmeData', idmeData, { expires: new Date(Date.now() + 60000) })
    res.redirect('/profile');
  } else {
    console.log('No Assertion found in the SAML response.');
    res.redirect('/');
  }
});

app.get('/profile', (req, res) => {
  const { idmePayload, idmeData } = req.cookies
  const { fname, lname, email, zip, uuid } = idmeData

  const formattedPayload = isObject(idmePayload) ? JSON.stringify(idmePayload, null, 4) : idmePayload

  if (idmeData){
    res.render('profile', { 
      payload: formattedPayload, 
      data: idmeData, 
      fname: fname, 
      lname: lname, 
      email: email,
      zip: zip,
      uuid: uuid 
    });
  } else {
    res.redirect('/')
  }
});

app.get('/sandbox/oidc/well-known', (req, res) => {
  const data = {
    "issuer": "https://api.idmelabs.com/oidc",
    "authorization_endpoint": "https://api.idmelabs.com/oauth/authorize",
    "token_endpoint": "https://api.idmelabs.com/oauth/token",
    "userinfo_endpoint": "https://api.idmelabs.com/api/public/v3/userinfo",
    "jwks_uri": "https://api.idmelabs.com/oidc/.well-known/jwks",
    "scopes_supported": [
      "openid",
      "profile",
      "email"
    ],
    "response_types_supported": [
      "code",
      "token",
      "id_token",
      "code id_token",
      "code token",
      "id_token token",
      "code id_token token"
    ],
    "grant_types_supported": [
      "authorization_code",
      "refresh_token"
    ],
    "subject_types_supported": [
      "public"
    ],
    "id_token_signing_alg_values_supported": [
      "RS256",
      "ES256"
    ],
    "id_token_encryption_alg_values_supported": [
      "RSA-OAEP"
    ],
    "id_token_encryption_enc_values_supported": [
      "A256CBC-HS512"
    ],
    "userinfo_signing_alg_values_supported": [
      "RS256",
      "ES256"
    ],
    "userinfo_encryption_alg_values_supported": [
      "RSA-OAEP"
    ],
    "userinfo_encryption_enc_values_supported": [
      "A256CBC-HS512"
    ],
    "token_endpoint_auth_methods_supported": [
      "client_secret_post",
      "client_secret_basic"
    ]
  };
  
  res.json(data);
});

app.get('/sandbox/oidc/entra/well-known', (req, res) => {
  const data = {
    "issuer": "https://api.idmelabs.com/oidc",
    "authorization_endpoint": "https://api.idmelabs.com/oauth/authorize",
    "token_endpoint": "https://api.idmelabs.com/oauth/token",
    "userinfo_endpoint": "https://api.idmelabs.com/api/public/v3/userinfo",
    "jwks_uri": "https://demo.idme.solutions/oidc/well-known/jwks",
    "scopes_supported": [
      "openid"
    ],
    "response_types_supported": [
      "code",
      "token",
      "id_token",
      "code id_token",
      "code token",
      "id_token token",
      "code id_token token"
    ],
    "grant_types_supported": [
      "authorization_code",
      "refresh_token"
    ],
    "subject_types_supported": [
      "public"
    ],
    "id_token_signing_alg_values_supported": [
      "RS256",
      "ES256"
    ],
    "id_token_encryption_alg_values_supported": [
      "RSA-OAEP"
    ],
    "id_token_encryption_enc_values_supported": [
      "A256CBC-HS512"
    ],
    "userinfo_signing_alg_values_supported": [
      "RS256",
      "ES256"
    ],
    "userinfo_encryption_alg_values_supported": [
      "RSA-OAEP"
    ],
    "userinfo_encryption_enc_values_supported": [
      "A256CBC-HS512"
    ],
    "token_endpoint_auth_methods_supported": [
      "client_secret_post",
      "client_secret_basic"
    ]
  };
  
  res.json(data);
});

app.get('/oidc/well-known/jwks', (req, res) => {
  const data = {
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "x": "uds0KYtD0gUSEtTlpTC4ipdzCF8HlYbKLCm2oro40Yg",
        "y": "UVPXhcITL2aMoYXFjTROh6MzeRf2O_Q6WjoXr1LT3XE",
        "kid": "CIzUOI6O4oxKxZkVtMpOer98Bw_JWwrooBenGWKAipE",
        "use": "sig",
        "alg": "ES256",
        "x5t#S256": "sY-3bM5GC0m-JQmGkp2lz5b4MhRo0vrkIGEkEITy4CI",
        "x5t": "M4_4oTbOmbF_Sb_DSkgDbmduSSY",
        "x5c": [
          "MIIFyTCCBU+gAwIBAgIQDYtZVM8VOq/WF/OKNOl62jAKBggqhkjOPQQDAzBWMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTAwLgYDVQQDEydEaWdpQ2VydCBUTFMgSHlicmlkIEVDQyBTSEEzODQgMjAyMCBDQTEwHhcNMjExMDAxMDAwMDAwWhcNMjIxMDAxMjM1OTU5WjCBwjEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEzARBgsrBgEEAYI3PAIBAxMCVVMxGTAXBgsrBgEEAYI3PAIBAhMIRGVsYXdhcmUxEDAOBgNVBAUTBzQ3ODQzMjcxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTEPMA0GA1UEBxMGTWNMZWFuMRQwEgYDVQQKEwtJRC5tZSwgSW5jLjEYMBYGA1UEAxMPc21hcnRjYXJkLmlkLm1lMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuds0KYtD0gUSEtTlpTC4ipdzCF8HlYbKLCm2oro40YhRU9eFwhMvZoyhhcWNNE6HozN5F/Y79DpaOhevUtPdcaOCA5AwggOMMB8GA1UdIwQYMBaAFAq8CCkXjKU5bXoOzjPHLrPt+8N6MB0GA1UdDgQWBBTci/A0X+wuPGkvXK7nFplEtz8RJTAaBgNVHREEEzARgg9zbWFydGNhcmQuaWQubWUwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCBmwYDVR0fBIGTMIGQMEagRKBChkBodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUTFNIeWJyaWRFQ0NTSEEzODQyMDIwQ0ExLTEuY3JsMEagRKBChkBodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRUTFNIeWJyaWRFQ0NTSEEzODQyMDIwQ0ExLTEuY3JsMEoGA1UdIARDMEEwCwYJYIZIAYb9bAIBMDIGBWeBDAEBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCBhQYIKwYBBQUHAQEEeTB3MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wTwYIKwYBBQUHMAKGQ2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRMU0h5YnJpZEVDQ1NIQTM4NDIwMjBDQTEtMS5jcnQwDAYDVR0TAQH/BAIwADCCAX0GCisGAQQB1nkCBAIEggFtBIIBaQFnAHYARqVV63X6kSAwtaKJafTzfREsQXS+/Um4havy/HD+bUcAAAF8PLoucgAABAMARzBFAiBT6rSD4c+XbSH+g5+p2HtUcbcWMEb+IYNphaOTly+ifQIhAL3E4v/cY5Q00u7mvznKw7Fe3zx+vzADijuzQJHUhRRnAHYAUaOw9f0BeZxWbbg3eI8MpHrMGyfL956IQpoN/tSLBeUAAAF8PLoufgAABAMARzBFAiEAvWRWWdkXXxbYgM2k/LHGTwH482AiGi58QbbY33cDLaICIGymEnshcDX9i8puLh5kT2x6dJw4viIxJ4jFrIs7raSgAHUAQcjKsd8iRkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvYAAAF8PLouOQAABAMARjBEAiAUZuGBC2/5NZ5jNa5Bwavxnn9npV2BMljNQObL3ZXb6gIgendtsMT/rabnQvqLDK2xaaI/yFVOYBXME5/sczoxlhowCgYIKoZIzj0EAwMDaAAwZQIxALNmeoXsOgYTe8nAKuqoFTqeih4Xr6Vr/zZ+cn/9GURHllVJOv+mvvQ9IswMKxALmAIwI+z6mrKEshBYziWmaOwyEhjSHVVtq3B4+mx3G+HAuvMbkmZxn2IyhJawBWqW+1NF"
        ]
      },
      {
        "kty": "RSA",
        "e": "AQAB",
        "n": "rz70i-ikqlO-MRx_0HDK_UVSGsc2YdoCtdobRFQ4AaaEoTaqOKpVk65dbrUVg45hw7m5zncVg1twX1Is8Xc3_kklvzxKmzeVsC_m03MN4yiZ6xEPReHHsucAUP8xRT-gGUMrWcSHWUdadczE52Gvdb_hr51IDuKFDeqfnxklluucbJk8IT15neuLQkLs5rOsn3BAubTDN2Xh9HEy5iSZ0WKJwlY418V1ccUN3QYvIfrUywF1UPNeIAFkl7UlSNkp1dyi_n_QaW6yyx9m3VoHCUtOlN1NxYeV_aeEm6agake2rbwwG2gfOSXz2lYfOGamgwMo9MhIKKq0zmc9EPiJ_Q",
        "kid": "9WSOx_eAXYDxiFou_suVIzGiNxBarsylEONVPbv1yTg",
        "use": "sig",
        "alg": "RS256",
        "x5t#S256": "vvRHJfZ9PZwHVDaVjwkaPWug50dTGuVLyhT3Bws4wnU",
        "x5t": "HmfnZCRKhmwa3t48Uzc9z54yaQM",
        "x5c": [
          "MIIG+zCCBeOgAwIBAgIQC8ERuaGDKbJtdhq+eN2FaTANBgkqhkiG9w0BAQsFADBEMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMR4wHAYDVQQDExVEaWdpQ2VydCBFViBSU0EgQ0EgRzIwHhcNMjQwOTI2MDAwMDAwWhcNMjUxMDI3MjM1OTU5WjCByzETMBEGCysGAQQBgjc8AgEDEwJVUzEZMBcGCysGAQQBgjc8AgECEwhEZWxhd2FyZTEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEDAOBgNVBAUTBzQ3ODQzMjcxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTEPMA0GA1UEBxMGTWNMZWFuMRQwEgYDVQQKEwtJRC5tZSwgSW5jLjEhMB8GA1UEAxMYc2lnbmluZy5hcGkuaWRtZWxhYnMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArz70i+ikqlO+MRx/0HDK/UVSGsc2YdoCtdobRFQ4AaaEoTaqOKpVk65dbrUVg45hw7m5zncVg1twX1Is8Xc3/kklvzxKmzeVsC/m03MN4yiZ6xEPReHHsucAUP8xRT+gGUMrWcSHWUdadczE52Gvdb/hr51IDuKFDeqfnxklluucbJk8IT15neuLQkLs5rOsn3BAubTDN2Xh9HEy5iSZ0WKJwlY418V1ccUN3QYvIfrUywF1UPNeIAFkl7UlSNkp1dyi/n/QaW6yyx9m3VoHCUtOlN1NxYeV/aeEm6agake2rbwwG2gfOSXz2lYfOGamgwMo9MhIKKq0zmc9EPiJ/QIDAQABo4IDXzCCA1swHwYDVR0jBBgwFoAUak5Qv5honVt7IHXUWQF5SGaSMgYwHQYDVR0OBBYEFDNWB1+jNAIEM0RS2eG3ZdpfSgraMCMGA1UdEQQcMBqCGHNpZ25pbmcuYXBpLmlkbWVsYWJzLmNvbTBKBgNVHSAEQzBBMAsGCWCGSAGG/WwCATAyBgVngQwBATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjB1BgNVHR8EbjBsMDSgMqAwhi5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRFVlJTQUNBRzIuY3JsMDSgMqAwhi5odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRFVlJTQUNBRzIuY3JsMHMGCCsGAQUFBwEBBGcwZTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMD0GCCsGAQUFBzAChjFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRFVlJTQUNBRzIuY3J0MAwGA1UdEwEB/wQCMAAwggF9BgorBgEEAdZ5AgQCBIIBbQSCAWkBZwB1ABLxTjS9U3JMhAYZw48/ehP457Vih4icbTAFhOvlhiY6AAABkivACSMAAAQDAEYwRAIgLrr97GTvwW6+G4N8miGrvAHX0ZiTofNlKExXDdcNmKACIFTIgi5022iwAi/UeYOZEv+qFvBVMvtHQLD5aIU5Les6AHYAfVkeEuF4KnscYWd8Xv340IdcFKBOlZ65Ay/ZDowuebgAAAGSK8AI6wAABAMARzBFAiB8DQfQBtgsWHOZsSVFMLM/glGi89zWCs7jR53xYFcQhQIhAIdFiW2dXuHzQBB0NrT1xRM1BnlME49GCAMNzVZ/twMPAHYA5tIxY0B3jMEQQQbXcbnOwdJA9paEhvu6hzId/R43jlAAAAGSK8AI3AAABAMARzBFAiEA9eSU20OCb0Fxe9v3MjGipM/m6kyjGGo14M94Q4SV2D4CIH0479P3J1OrYPWOMMZ0Y8OhYa/Lz9AyMYUHexEtrCepMA0GCSqGSIb3DQEBCwUAA4IBAQBj2ZxKiO3we6khLopK+4SOOCdpGmYzTLxKuNrVOc+3ON8tRFegbRPLgs2y9rDIRddm2swkTr03epZ6OfeMts7pLfGv7rlG6CJfz4UuoT8BQ78yRjSSMXQPAhO6mX7cyTr5oHWxMWAbI9VZ2GTmfpjSjd5uWlsIMO1pBw1WSq0zlW9FrXruQSVqQLp0t+tEuDjmkS3tIzFtkVNJFtQMCZbGJTsnhgXuTp5exZcsHV0Tfd6/mnMOvGNYJjG+F8nZlrICy8un2Zt5ZvP9jPl4j6cZHfOeAvrsCvhNhwnZDT5+4oHOVaAbRz5bhYo23BYhXFg2i2P6xx8ApKG0YIIqoSK8"
        ]
      },
      {
        "kty": "RSA",
        "e": "AQAB",
        "n": "sMMXsNexa_6J-n7gFDvrgzS7ZBzMUtCRiPefpPwhrzX7Ts51IfueXQmezy34hdJcmQ00RVhySVo89kwHJ3-kmsimnxyYLEr51u4M4ix35zD_BPytRSbXGjeeinmSnFPxNj3p22O2kyqwxxLcNJD6yJGoragEN3TnEKDtx573zMyUY9GJH-wWZvFKhpFWF0tgc-gFGEAy5q1uMDkkgOjKpOklHNeoMhD5b86vyc6p95lSXehOtv2JtehJegrJMXPmurjqYZq4uQSy-UwKDT7QV4FZj1pgsoqTG9Hk2ehqpd5gO1oOiDVuyZWrjJBoDzgYfabJmj3fiBTn4TI243tRlw",
        "kid": "V1GhtpPKDGeiV9c0Z6zu-K_AS5X0bO4F02-hVGOW_UE",
        "use": "enc",
        "alg": "RSA-OAEP",
        "x5t#S256": "_fepQr4y5o_gzi1oLUONShnmISIY2JdlaQdEBF3LAmE",
        "x5t": "ztMv9oR-U2VF9mF3_me4_WhbTXg",
        "x5c": [
          "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"
        ]
      }
    ]
  }
  
  res.json(data);
});

app.get('/sandbox/saml/entra/metadata', (req, res) => {
  const data = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://api.idmelabs.com" ID="_2bb8b48fd74e44f8bd89bf764e501f89" validUntil="2025-10-02T03:59:59Z">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  <ds:Reference URI="#_2bb8b48fd74e44f8bd89bf764e501f89">
  <ds:Transforms>
  <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
  <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  </ds:Transforms>
  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
  <ds:DigestValue>Pto04HTTcjNmETpxQVsZLoatd2r5ByPhDRv3wJm/omk=</ds:DigestValue>
  </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>c9kFApNFsMlywNgqN5rlkc7OwrjOOf5HyYLW/e6Tylh1CRS4Wk0HNrFDFHKJ0NVUy4yRnWyGnAXuU+CU5kJmr0Mj8ZO96Bp9YeIBiUmn30s1kw1/xuaawZeBNjpaMNY4XxOCwT2n1FYqRGd9unbDelyIUMlcKhp0cgAIBSyu8lHd4+IWrcUu8U/xp7n1mqrPNUfXCpA7oW0HG0tiiMyrU5uprGuTEyok2u71mLXDiICIyO4448QR4t/J8UqqifQW26CQ6xYOZVm88Y/xoMkty+beF8sTDIoRJRlvJINt6g6qwZGS3quZoT9kao/S061D0Nr5do/+yi5/onxwH1Y88HnFVkyfIyAb4pGaDD+EdN7Lp7ddaFOGpyqwUZHD1F2oL8Kue70jOXsZmH+AeHSx1hc350DxdopoOd3DCz6x7xhGYM3dcATq47A5+N/jtqR6ZK0+G2ktqGWAg5RZQ1SRKwOXQR0ZkMIRDGy+HlTJkROWLlNNj8mz6VY1rJY7LbLMJl6ToY0DSJmrNxv7q7VcKXCmTq+3UifDzupiN9hgeNN/tbIlStPdCaMWGm+0oEthcGtFATeN2WLscmnkOrc1Ua9Dl10W+FLYXypjc52Nb6FbpDT3OuxxyblO5zBa8DEzb0bxi0GgOEWBRWKenDovDw8LMpTcQMPXoPe4qlduV9A=</ds:SignatureValue>
  <ds:KeyInfo>
  <ds:X509Data>
  <ds:X509Certificate>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</ds:X509Certificate>
  </ds:X509Data>
  </ds:KeyInfo>
  </ds:Signature>
  <md:Extensions>
  <mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute">
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="urn:oasis:names:tc:SAML:attribute:assurance-certification" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
  <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">http://idmanagement.gov/ns/assurance/loa/1</saml:AttributeValue>
  <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">http://idmanagement.gov/ns/assurance/loa/2</saml:AttributeValue>
  <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">http://idmanagement.gov/ns/assurance/loa/3</saml:AttributeValue>
  </saml:Attribute>
  </mdattr:EntityAttributes>
  </md:Extensions>
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">
  <md:KeyDescriptor use="signing" active="true">
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:X509Data>
  <ds:X509Certificate>MIIG+zCCBeOgAwIBAgIQC8ERuaGDKbJtdhq+eN2FaTANBgkqhkiG9w0BAQsFADBEMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMR4wHAYDVQQDExVEaWdpQ2VydCBFViBSU0EgQ0EgRzIwHhcNMjQwOTI2MDAwMDAwWhcNMjUxMDI3MjM1OTU5WjCByzETMBEGCysGAQQBgjc8AgEDEwJVUzEZMBcGCysGAQQBgjc8AgECEwhEZWxhd2FyZTEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEDAOBgNVBAUTBzQ3ODQzMjcxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTEPMA0GA1UEBxMGTWNMZWFuMRQwEgYDVQQKEwtJRC5tZSwgSW5jLjEhMB8GA1UEAxMYc2lnbmluZy5hcGkuaWRtZWxhYnMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArz70i+ikqlO+MRx/0HDK/UVSGsc2YdoCtdobRFQ4AaaEoTaqOKpVk65dbrUVg45hw7m5zncVg1twX1Is8Xc3/kklvzxKmzeVsC/m03MN4yiZ6xEPReHHsucAUP8xRT+gGUMrWcSHWUdadczE52Gvdb/hr51IDuKFDeqfnxklluucbJk8IT15neuLQkLs5rOsn3BAubTDN2Xh9HEy5iSZ0WKJwlY418V1ccUN3QYvIfrUywF1UPNeIAFkl7UlSNkp1dyi/n/QaW6yyx9m3VoHCUtOlN1NxYeV/aeEm6agake2rbwwG2gfOSXz2lYfOGamgwMo9MhIKKq0zmc9EPiJ/QIDAQABo4IDXzCCA1swHwYDVR0jBBgwFoAUak5Qv5honVt7IHXUWQF5SGaSMgYwHQYDVR0OBBYEFDNWB1+jNAIEM0RS2eG3ZdpfSgraMCMGA1UdEQQcMBqCGHNpZ25pbmcuYXBpLmlkbWVsYWJzLmNvbTBKBgNVHSAEQzBBMAsGCWCGSAGG/WwCATAyBgVngQwBATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjB1BgNVHR8EbjBsMDSgMqAwhi5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRFVlJTQUNBRzIuY3JsMDSgMqAwhi5odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRFVlJTQUNBRzIuY3JsMHMGCCsGAQUFBwEBBGcwZTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMD0GCCsGAQUFBzAChjFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRFVlJTQUNBRzIuY3J0MAwGA1UdEwEB/wQCMAAwggF9BgorBgEEAdZ5AgQCBIIBbQSCAWkBZwB1ABLxTjS9U3JMhAYZw48/ehP457Vih4icbTAFhOvlhiY6AAABkivACSMAAAQDAEYwRAIgLrr97GTvwW6+G4N8miGrvAHX0ZiTofNlKExXDdcNmKACIFTIgi5022iwAi/UeYOZEv+qFvBVMvtHQLD5aIU5Les6AHYAfVkeEuF4KnscYWd8Xv340IdcFKBOlZ65Ay/ZDowuebgAAAGSK8AI6wAABAMARzBFAiB8DQfQBtgsWHOZsSVFMLM/glGi89zWCs7jR53xYFcQhQIhAIdFiW2dXuHzQBB0NrT1xRM1BnlME49GCAMNzVZ/twMPAHYA5tIxY0B3jMEQQQbXcbnOwdJA9paEhvu6hzId/R43jlAAAAGSK8AI3AAABAMARzBFAiEA9eSU20OCb0Fxe9v3MjGipM/m6kyjGGo14M94Q4SV2D4CIH0479P3J1OrYPWOMMZ0Y8OhYa/Lz9AyMYUHexEtrCepMA0GCSqGSIb3DQEBCwUAA4IBAQBj2ZxKiO3we6khLopK+4SOOCdpGmYzTLxKuNrVOc+3ON8tRFegbRPLgs2y9rDIRddm2swkTr03epZ6OfeMts7pLfGv7rlG6CJfz4UuoT8BQ78yRjSSMXQPAhO6mX7cyTr5oHWxMWAbI9VZ2GTmfpjSjd5uWlsIMO1pBw1WSq0zlW9FrXruQSVqQLp0t+tEuDjmkS3tIzFtkVNJFtQMCZbGJTsnhgXuTp5exZcsHV0Tfd6/mnMOvGNYJjG+F8nZlrICy8un2Zt5ZvP9jPl4j6cZHfOeAvrsCvhNhwnZDT5+4oHOVaAbRz5bhYo23BYhXFg2i2P6xx8ApKG0YIIqoSK8</ds:X509Certificate>
  </ds:X509Data>
  </ds:KeyInfo>
  </md:KeyDescriptor>
  <md:KeyDescriptor use="signing">
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:X509Data>
  <ds:X509Certificate>MIIG+zCCBeOgAwIBAgIQCo5hfHjNZtYY2sA76flakzANBgkqhkiG9w0BAQsFADBEMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMR4wHAYDVQQDExVEaWdpQ2VydCBFViBSU0EgQ0EgRzIwHhcNMjMwOTI1MDAwMDAwWhcNMjQxMDI1MjM1OTU5WjCByzETMBEGCysGAQQBgjc8AgEDEwJVUzEZMBcGCysGAQQBgjc8AgECEwhEZWxhd2FyZTEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEDAOBgNVBAUTBzQ3ODQzMjcxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhWaXJnaW5pYTEPMA0GA1UEBxMGTWNMZWFuMRQwEgYDVQQKEwtJRC5tZSwgSW5jLjEhMB8GA1UEAxMYc2lnbmluZy5hcGkuaWRtZWxhYnMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArz70i+ikqlO+MRx/0HDK/UVSGsc2YdoCtdobRFQ4AaaEoTaqOKpVk65dbrUVg45hw7m5zncVg1twX1Is8Xc3/kklvzxKmzeVsC/m03MN4yiZ6xEPReHHsucAUP8xRT+gGUMrWcSHWUdadczE52Gvdb/hr51IDuKFDeqfnxklluucbJk8IT15neuLQkLs5rOsn3BAubTDN2Xh9HEy5iSZ0WKJwlY418V1ccUN3QYvIfrUywF1UPNeIAFkl7UlSNkp1dyi/n/QaW6yyx9m3VoHCUtOlN1NxYeV/aeEm6agake2rbwwG2gfOSXz2lYfOGamgwMo9MhIKKq0zmc9EPiJ/QIDAQABo4IDXzCCA1swHwYDVR0jBBgwFoAUak5Qv5honVt7IHXUWQF5SGaSMgYwHQYDVR0OBBYEFDNWB1+jNAIEM0RS2eG3ZdpfSgraMCMGA1UdEQQcMBqCGHNpZ25pbmcuYXBpLmlkbWVsYWJzLmNvbTBKBgNVHSAEQzBBMAsGCWCGSAGG/WwCATAyBgVngQwBATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjB1BgNVHR8EbjBsMDSgMqAwhi5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRFVlJTQUNBRzIuY3JsMDSgMqAwhi5odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRFVlJTQUNBRzIuY3JsMHMGCCsGAQUFBwEBBGcwZTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMD0GCCsGAQUFBzAChjFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRFVlJTQUNBRzIuY3J0MAwGA1UdEwEB/wQCMAAwggF9BgorBgEEAdZ5AgQCBIIBbQSCAWkBZwB3AO7N0GTV2xrOxVy3nbTNE6Iyh0Z8vOzew1FIWUZxH7WbAAABis1nKr8AAAQDAEgwRgIhAK78Xih4iT/FcpdoXUD7FKs5ri5HV4XsVugcx2ru7GTAAiEA5+T/KQjN/pZvScGDR10tqaX6fY5IsFKk/vQ1HQPl23IAdQBIsONr2qZHNA/lagL6nTDrHFIBy1bdLIHZu7+rOdiEcwAAAYrNZyqCAAAEAwBGMEQCIH+Xx/JqqUR7zadwgElRl6cEuXGDpYw2PB73sj4oD5LdAiBbmcewCNzkiSj473mNKOIAdKiipnbv9NpKTFl/jJ8GuAB1ANq2v2s/tbYin5vCu1xr6HCRcWy7UYSFNL2kPTBI1/urAAABis1nKkYAAAQDAEYwRAIgFgENs7uCaTYCmnvHdh9DMhdH+mMhn2qZUOqjvXhKtEACIGVztd1QLsDOFGP5uHy2cvEkuIvSBvHJTa7KJ7B6LiUmMA0GCSqGSIb3DQEBCwUAA4IBAQCewjyDowXFRodoqvtSDccR4kbRGHPiTO721uy7s2nWczyIZqHXCiei2TMXktp+wqXk0FGA8TKJ49eYjKIXFPAUfwt0Lbn+ZnzJDace4NrG/F6thV3PVVzGs1BOVnfPysVrCAWzd79ZxYmW3L9AvL/fVekK7/3W/eke0WMaXTGG9qf5i57i73gM5DCLMddR4Nd45qjzcKzWvciRNX0WX4PReSPbOiR2R0Hl5S0OQw7oej8zvDNuOTlG7y7PIJY4imLgM1S0jO30LM9run1tvPYZkz0RbJEc1CnrpIoQDbtpdWqwFX3byjRCTVsyAnIj7Pr036u+m5rasQga2CAnTaQK</ds:X509Certificate>
  </ds:X509Data>
  </ds:KeyInfo>
  </md:KeyDescriptor>
  <md:KeyDescriptor use="encryption" active="true">
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:X509Data>
  <ds:X509Certificate>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</ds:X509Certificate>
  </ds:X509Data>
  </ds:KeyInfo>
  </md:KeyDescriptor>
  <md:KeyDescriptor use="encryption">
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:X509Data>
  <ds:X509Certificate>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</ds:X509Certificate>
  </ds:X509Data>
  </ds:KeyInfo>
  </md:KeyDescriptor>
  <md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://api.idmelabs.com/saml/ArtifactResolutionService" index="0" isDefault="false"/>
  <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://api.idmelabs.com/saml/SingleLogoutService"/>
  <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://api.idmelabs.com/saml/SingleLogoutService"/>
  <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
  <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
  <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress</md:NameIDFormat>
  <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
  <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
  <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://api.idmelabs.com/saml/SingleSignOnService"/>
  <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://api.idmelabs.com/saml/SingleSignOnService"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="addresses" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Addresses"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="age" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Age"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="birth_date" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Birth Date"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="city" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="City"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="country" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Country"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="delivery_type" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Delivery Type"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Email"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="fname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="First Name"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="itin" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Full ITIN"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="full_name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Full Name"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="social" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Full SSN"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="ssn_itin" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Full SSN/ITIN"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="gender" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Gender"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="itin_short" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Last 4 of ITIN"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="social_short" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Last 4 of SSN"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="ssn_itin_short" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Last 4 of SSN/ITIN"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="lname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Last Name"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="mname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Middle Name"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="passport_country_code" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Passport Country"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="passport_expiration_date" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Passport Expiration Date"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="passport_number" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Passport Number"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="phone" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Phone"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="zip" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Postal Code"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="previous_addresses" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Previous address(es) if available"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="address_city" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Primary City"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="address_country" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Primary Country"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="address_zip" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Primary Postal Code"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="address_province" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Primary Province"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="address_state" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Primary State"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="address_street" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Primary Street"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="address_street1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Primary Street1"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="address_street2" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Primary Street2"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="quantity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Quantity"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="resident_city" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Resident City"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="resident_state" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Resident State"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="resident_street" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Resident Street"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="resident_zip" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Resident Zip"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="social_verified" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Social Verified"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="ssn_validation_method" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="SSN Validation Method"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="state" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="State"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="street" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Street"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="street1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Street1"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="street2" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Street2"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="suffix" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Suffix"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="records_validated" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Validated in financial records"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="credentials" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Verified credentials"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="work_emails" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Work Emails"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="yubico_delivery_type" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Yubico Delivery Type"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="yubico_product_id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Yubico Product ID"/>
  <saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="yubico_quantity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" FriendlyName="Yubico Quantity"/>
  </md:IDPSSODescriptor>
  <md:Organization>
  <md:OrganizationName xml:lang="en">ID.me</md:OrganizationName>
  <md:OrganizationDisplayName xml:lang="en">ID.me</md:OrganizationDisplayName>
  <md:OrganizationURL xml:lang="en">https://www.id.me</md:OrganizationURL>
  </md:Organization>
  </md:EntityDescriptor>`;
  
  res.type('application/xml').send(data);
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
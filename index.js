import express, { json } from 'express'
import axios from 'axios'
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken'
import bodyParser from 'body-parser';
import { DOMParser } from 'xmldom';
import xpath from 'xpath'
import 'dotenv/config';

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
  const requestProtocol = req.protocol
  const isSAML = protocol == 'saml'
  const oauthEndpoint = policy == 'groups' ? `https://groups.id.me` : `${envDomain}/oauth/authorize`
  const authEndpoint = isSAML ? `${envDomain}/saml/SingleSignOnService` : oauthEndpoint

  const protocolPolicy = policy == 'groups' ? 'groups' : protocol

  let params = null

  switch (protocolPolicy) {
    case 'groups':
      params = `?client_id=${clientID}&redirect_uri=${requestProtocol}://${host}/callback/${env}/${protocol}&response_type=code&scopes=${groups}&sandbox=${env == 'sandbox'}`
      break;
    case 'oauth':
      params = `?client_id=${clientID}&redirect_uri=${requestProtocol}://${host}/callback/${env}/${protocol}&response_type=code&scope=${policy}`
      break;
    case 'oidc':
      params = `?client_id=${clientID}&redirect_uri=${requestProtocol}://${host}/callback/${env}/${protocol}&response_type=code&scope=openid ${policy}`
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
  const requestProtocol = req.protocol
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
      redirect_uri: `${requestProtocol}://${host}/callback/${env}/${protocol}`,
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

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
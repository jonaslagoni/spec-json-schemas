const assert = require('assert');
const path = require('path');
const Ajv = require("ajv");
const schemas = [
  'userPassword.json',
  'apiKey.json',
  'X509.json',
  'symmetricEncryption.json',
  'asymmetricEncryption.json',
  'HTTPSecurityScheme.json',
  'oauth2Flows.json',
  'openIdConnect.json',
  'specificationExtension.json',
  'oauth2Scopes.json',
  'NonBearerHTTPSecurityScheme.json',
  'BearerHTTPSecurityScheme.json',
  'APIKeyHTTPSecurityScheme.json',
  'oauth2Flow.json',
  'SaslPlainSecurityScheme.json',
  'SaslScramSecurityScheme.json',
  'SaslGssapiSecurityScheme.json',
]

describe("Should be able to validate securityRequirements", function () {
  const ajv = new Ajv({
    jsonPointers: true,
    allErrors: true,
    schemaId: '$id',
    logger: false,
    validateFormats: false,
    strict: false
  });

  schemas.map((pathToDoc) => {
    return path.resolve(__dirname, `../../../definitions/3.0.0/${pathToDoc}`)}
  ).forEach((pathToDoc) => {
    const document = require(pathToDoc);
    ajv.addSchema(document);
  });
  const schema = require(path.resolve(__dirname, `../../../definitions/3.0.0/SecurityScheme.json`));
  const validate = ajv.compile(schema);
  it('openIdConnect should be valid', () => {
    const valid = validate({
      type: 'openIdConnect',
      openIdConnectUrl: 'openIdConnectUrl',
      scopes: [
        'some:scope:1',
        'some:scope:2'
      ]
    });
    assert(valid === true, 'Should accurately validate openIdConnect');
  });
});
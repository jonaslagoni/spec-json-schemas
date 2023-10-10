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
  'serverVariables.json',
  'securityRequirements.json',
  'tag.json',
  'externalDocs.json',
  'serverBindingsObject.json',
  'Reference.json',
  'ReferenceObject.json',
  'serverVariable.json',
  'SecurityScheme.json'
];

describe("Should be able to validate server object", function () {
  const ajv = new Ajv({
    jsonPointers: true,
    allErrors: true,
    schemaId: '$id',
    logger: false,
    validateFormats: false,
    strict: false
  });

  schemas.forEach((pathToDoc) => {
    let document;
    if(pathToDoc === 'serverBindingsObject.json') {
      // Lets ignore binding for this test
      document = {"$schema": "http://json-schema.org/draft-07/schema#", "$id": "http://asyncapi.com/definitions/3.0.0/serverBindingsObject.json"};
    } else {
      const fullPath = path.resolve(__dirname, `../../../definitions/3.0.0/${pathToDoc}`);
      document = require(fullPath);
    }
    ajv.addSchema(document);
  });
  const schema = require(path.resolve(__dirname, `../../../definitions/3.0.0/server.json`));
  const validate = ajv.compile(schema)
  it('should validate multiple security schemas', () => {
    const valid = validate({
      "host": "api.streetlights.smartylighting.com:{port}",
      "protocol": "mqtt",
      "description": "Test broker",
      "variables": {
        "port": {
          "description": "Secure connection (TLS) is available through port 8883.",
          "default": "1883",
          "enum": [
            "1883",
            "8883"
          ]
        }
      },
      "security": [
        {
          "type": "apiKey",
          "in": "user",
          "description": "Provide your API key as the user and leave the password empty."
        },
        {
          "type": "oauth2",
          "flows": {
            "implicit": {
              "authorizationUrl": "https://example.com/api/oauth/dialog",
              "availableScopes": {
                "write:pets": "modify pets in your account",
                "read:pets": "read your pets"
              }
            }
          },
          "scopes": [
            "write:pets"
          ]
        },
        {
          "type": "openIdConnect",
          "openIdConnectUrl": "openIdConnectUrl",
          "scopes": [
            "some:scope:1",
            "some:scope:2"
          ]
        }
      ]
    });
    assert(valid === true, 'Should accurately validate server object');
  });
});
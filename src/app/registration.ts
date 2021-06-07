import express, { response } from "express";
import axios from "axios";
import encode from "nodejs-base64-encode";
const base64url = require("base64url");

// Metadata - simplewebauthn
import { MetadataService } from "@simplewebauthn/server";
import { MetadataStatement } from "@simplewebauthn/server/dist/metadata/metadataService";
import verifyAttestationWithMetadata = require("@simplewebauthn/server/dist/metadata/verifyAttestationWithMetadata");
import decodeAttestationObject = require("@simplewebauthn/server/dist/helpers/decodeAttestationObject");
import parseAuthenticatorData = require("@simplewebauthn/server/dist/helpers/parseAuthenticatorData");
import convertX509CertToPEM = require("@simplewebauthn/server/dist/helpers/convertX509CertToPEM");
import verifySignature = require("@simplewebauthn/server/dist/helpers/verifySignature");
import toHash = require("@simplewebauthn/server/dist/helpers/toHash");
import decodeCredentialPublicKey = require("@simplewebauthn/server/dist/helpers/decodeCredentialPublicKey");
import convertCOSEtoPKCS = require("@simplewebauthn/server/dist/helpers/convertCOSEtoPKCS");

const getCertificateInfo = require("@simplewebauthn/server/dist/helpers/getCertificateInfo");

let config = require("./../../config.json");

var challenge: any;
var auth: any;

export default ({ app }: { app: express.Application }) => {
  /**
   * Health Check endpoints
   */
  app.get("/status", (req, res) => {
    res.status(200).end("Connection Successful.");
  });
  app.head("/status", (req, res) => {
    res.status(200).end();
  });

  /**
   * Credential Creation Options.
   */
  const appId = `{'appId':'http://${toolHost}'}`;
  var requestId;

  app.post("/attestation/options", async (req, res) => {
    console.log(`Request @ /attestation/options`);

    var attestation = req.body.attestation;
    var authenticatorSelection = req.body.authenticatorSelection;
    var extensions = { "example.extension": true };
    var attestationLogic = req.body.attestation == "direct" ? "direct" : "none";

    // Set user data required to create a user in wso2is
    var userData = {
      familyName: req.body.displayName.split(" ")[1],
      givenName: req.body.displayName.split(" ")[0],
      userName: req.body.username,
      password: "password",
      homeEmail:
        req.body.displayName.split(" ")[0].toLowerCase() + `_home@gmail.com`,
      workEmail:
        req.body.displayName.split(" ")[0].toLowerCase() + `_work@gmail.com`,
      attestationClaim: req.body.attestation.toUpperCase(),
    };

    // Create user
    const user = await createUser(userData).catch((e) => {
      res.send({
        status: "failed",
        errorMessage: "Unable to create a user",
      });
    });

    auth = encode.encode(`${userData.userName}:${userData.password}`, "base64");

    if (
      req.body.authenticatorSelection &&
      req.body.authenticatorSelection.requireResidentKey == false
    ) {
      // start-registration
      await axios({
        method: "post",
        url: `https://${isHost}/api/users/v2/me/webauthn/start-registration`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${auth}`,
        },
        data: appId,
      })
        .then((usernamelessRegistrationResponse) => {
          requestId = usernamelessRegistrationResponse.data.requestId;

          // Response to the conformance tools
          var returnData = {
            status: "ok",
            errorMessage: "",
            rp:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.rp,
            user:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.user,
            challenge:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.challenge,
            pubKeyCredParams:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.pubKeyCredParams,
            timeout:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.timeout,
            excludeCredentials: [
              {
                type: "public-key",
                id: "rnInB99skrSHLwQJpAio3W2S5RMHGYGudqdobiUImDI",
              },
            ],
            authenticatorSelection:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.authenticatorSelection,
            attestation: attestationLogic,
            extensions: extensions,
          };

          challenge =
            usernamelessRegistrationResponse.data
              .publicKeyCredentialCreationOptions.challenge;

          res.send(returnData);
        })
        .catch((err) => {
          res.send({
            status: "failed",
            errorMessage: err.message,
          });
        });
    } else {
      // start-usernameless-registration
      await axios({
        method: "post",
        url: `https://${isHost}/api/users/v2/me/webauthn/start-usernameless-registration`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${auth}`,
        },
        data: appId,
      })
        .then((usernamelessRegistrationResponse) => {
          requestId = usernamelessRegistrationResponse.data.requestId;

          // Response to the conformance tools
          var returnData = {
            status: "ok",
            errorMessage: "",
            rp:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.rp,
            user:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.user,
            challenge:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.challenge,
            pubKeyCredParams:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.pubKeyCredParams,
            timeout:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.timeout,
            excludeCredentials:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.excludeCredentials,
            authenticatorSelection:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.authenticatorSelection,
            attestation:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.attestation,
            extensions:
              usernamelessRegistrationResponse.data
                .publicKeyCredentialCreationOptions.extensions,
          };

          challenge =
            usernamelessRegistrationResponse.data
              .publicKeyCredentialCreationOptions.challenge;

          res.send(returnData);
        })
        .catch((err) => {
          res.send({
            status: "failed",
            errorMessage: err.message,
          });
        });
    }
  });

  /**
   * Authenticator Attestation Response
   */
  app.post("/attestation/result", async (req, res) => {
    console.log(`Request @ /attestation/results`);

    // Arrange data to be sent to wso2is
    var data = {
      credential: {
        clientExtensionResults: {},
        id: req.body.id,
        response: req.body.response,
        type: req.body.type,
      },
      requestId: requestId,
    };

    // 1. Read AAGUID from the request
    try {
      const { id, rawId, response, type } = req.body;
      const { attestationObject, clientDataJSON } = response;
      const { fmt, attStmt, authData } = decodeAttestationObject.default(
        attestationObject
      );
      const { alg, sig, x5c } = attStmt;
      const {
        rpIdHash,
        aaguid,
        credentialPublicKey,
      } = parseAuthenticatorData.default(authData);

      let verified = false;

      const clientDataHash = toHash.default(
        base64url.default.toBuffer(response.clientDataJSON)
      );
      var signatureBase = Buffer.concat([authData, clientDataHash]);

      if (x5c) {
        var leafCert = convertX509CertToPEM.default(x5c[0]);

        var {
          subject,
          basicConstraintsCA,
          version,
          notBefore,
          notAfter,
        } = getCertificateInfo.default(leafCert);

        var { OU, CN, O, C } = subject;

        /**
         * For FIDO-U2F Attestation
         *
         */
        if (fmt == "fido-u2f") {
          const aaguidToHex = Number.parseInt(aaguid.toString("hex"), 16);
          if (aaguidToHex !== 0x00) {
            throw new Error(`AAGUID '${aaguidToHex}' was not expected value`);
          }
        }

        /**
         * For PACKED Attestation
         * METADATA validation
         */
        if (fmt == "packed") {
          if (OU !== "Authenticator Attestation") {
            throw new Error(`Certificate not good before 1 (Packed|Full)`);
          }
          if (!CN) {
            throw new Error(`Certificate not good before 2 (Packed|Full)`);
          }
          if (!O) {
            throw new Error(`Certificate not good before 3 (Packed|Full)`);
          }
          if (!C || C.length !== 2) {
            throw new Error(`Certificate not good before 4 (Packed|Full)`);
          }
          if (basicConstraintsCA) {
            throw new Error(`Certificate not good before 5 (Packed|Full)`);
          }
          if (version !== 3) {
            throw new Error(`Certificate not good before 6 (Packed|Full)`);
          }
          let now = new Date();
          if (notBefore > now) {
            throw new Error(`Certificate not good before 7 (Packed|Full)`);
          }
          now = new Date();
          if (notAfter < now) {
            throw new Error(`Certificate not good before 8 (Packed|Full)`);
          }

          var metadataStatement: MetadataStatement = await MetadataService.getStatement(
            aaguid
          );

          if (metadataStatement) {
            var verification: any = verifyAttestationWithMetadata.default(
              metadataStatement,
              alg,
              x5c
            );
          }
        }
        verifySignature.default(sig, signatureBase, leafCert);
      } else {
        const cosePublicKey = decodeCredentialPublicKey.default(
          credentialPublicKey
        );
        const kty = cosePublicKey.get(convertCOSEtoPKCS.COSEKEYS.kty);
        if (!kty) {
          throw new Error("COSE public key was missing kty (Packed|Self)");
        }
      }
    } catch (error) {
      res.send({
        status: "failed",
        errorMessage: error.message,
      });
    }

    // For metadata verification
    // Used Simplewebauthn
    var dataToVerification = {
      credential: {
        rawId: req.body.rawId,
        clientExtensionResults: {},
        id: req.body.id,
        response: req.body.response,
        type: req.body.type,
      },
      requestId: requestId,
    };

    // Finish registration request
    var x = await axios({
      method: "post",
      url: `https://${isHost}/api/users/v2/me/webauthn/finish-registration`,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${auth}`,
      },
      data: data,
    })
      .then((response) => {
        res.send({
          status: "ok",
          errorMessage: "",
        });
      })
      .catch((error) => {
        res.send({
          status: "failed",
          errorMessage: error.message,
        });
      });
  });
};

/**
 * Find availability of a user with SCIM2 API
 */
const searchUser = async (req) => {
  // Set filter for user search
  var filter = `userName sw ${req.body.username}`;

  var searchUserdata = {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
    attributes: ["name.familyName", "userName"],
    filter: filter,
    domain: "PRIMARY",
    startIndex: 1,
    count: 100,
  };

  return await axios({
    method: "post",

    url: `https://${isHost}/scim2/Users/.search`,
    headers: {
      "Content-Type": "application/scim+json",
      Authorization: "Basic YWRtaW46YWRtaW4=",
    },
    data: searchUserdata,
  });
};

/**
 * Create user with SCIM2 API
 */
const createUser = async (userData) => {
  var data = JSON.stringify({
    schemas: [],
    name: {
      // familyName: userData.familyName,
      // givenName: userData.givenName,
      formatted: userData.givenName + " " + userData.familyName,
    },
    userName: userData.userName,
    password: userData.password,
    emails: [
      { primary: true, value: userData.homeEmail, type: "home" },
      { value: userData.workEmail, type: "work" },
    ],
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
      customClaim: userData.attestationClaim,
    },
  });

  try {
    return await axios({
      method: "post",
      url: `https://${isHost}/scim2/Users`,
      headers: {
        "Content-Type": "application/json",
        Authorization: "Basic YWRtaW46YWRtaW4=",
      },
      data: data,
    });
  } catch (error) {
    console.error(error);
  }
};

/**
 * Create user claim
 */
const createClaim = async (claimData) => {
  var data = JSON.stringify({
    claimURI: "http://wso2.org/claims/a",
    description: "Some description about the claim.",
    displayOrder: 10,
    displayName: "Test",
    readOnly: false,
    required: false,
    supportedByDefault: true,
    attributeMapping: [{ mappedAttribute: "username", userstore: "PRIMARY" }],
    properties: [{ key: "string", value: "string" }],
  });

  try {
    return await axios({
      method: "post",
      url: `https://${isHost}/api/server/v1/claim-dialects/local/claims`,
      headers: {
        accept: "application/json",
        "Content-Type": "application/json",
        Authorization: "Basic YWRtaW46YWRtaW4=",
      },
      data: data,
    });
  } catch (error) {
    console.error(error);
  }
};

/**
 * Set user claim
 */
const setClaim = async (claimData) => {
  var data = JSON.stringify({
    claimURI: "http://wso2.org/claims/username",
    description: "Some description about the claim.",
    displayOrder: 10,
    displayName: "Username",
    readOnly: true,
    regEx: "^([a-zA-Z)$",
    required: true,
    supportedByDefault: true,
    attributeMapping: [{ mappedAttribute: "username", userstore: "SECONDARY" }],
    properties: [{ key: "string", value: "string" }],
  });

  try {
    return await axios({
      method: "put",
      url:
        "https://${isHost}/api/server/v1/claim-dialects/local/claims/test",
      headers: {
        accept: "application/json",
        "Content-Type": "application/json",
      },
      data: data,
    });
  } catch (error) {
    console.error(error);
  }
};

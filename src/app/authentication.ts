import express, { response } from "express";
import bodyParser from "body-parser";
import cors from "cors";
import axios from "axios";
import querystring from "querystring";
import encode from "nodejs-base64-encode";

let config = require("./../../config.json");
let requestId: any;
let sessionDataKey: any;
let host = "localhost";
let auth: any;
let isHost = config.isHost;

export default ({ app }: { app: express.Application }) => {
  /**
   * Health Check endpoints registration
   */
  app.get("/status/registration", (req, res) => {
    res.status(200).end("Registration Connection Successful.");
  });
  app.head("/status/registration", (req, res) => {
    res.status(200).end();
  });

  app.use(cors());
  app.use(bodyParser.json());

  app.post("/assertion/options", async (req, res) => {
    console.log(`Request @ /assertion/options`);
    var client_id = config.sampleAppId;  // Client Id of the sample app

    auth = encode.encode(`${req.body.username}:password`, "base64");

    var url = `https://${isHost}/oauth2/authorize?scope=openid&response_type=code&redirect_uri=${redirectURI}&client_id=$
    {client_id}`;

    // start-authentication
    return await axios({
      method: "get",
      url: url,
      headers: {
        Connection: "keep-alive",
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        Host: isHost,
        ContentType: "application/json",
        Authorization: `Basic ${auth}`,
      },
    })
      .then((response: any) => {
        var headers: any = response.request._header;

        var requestUrlfido2auth = headers.split("?")[0].split(" ")[1];
        sessionDataKey = headers.split("?")[1].split("&")[2].split("=")[1];
        var data = JSON.parse(
          unescape(
            headers.split("?")[1].split("&")[3].split(" ")[0].split("=")[1]
          )
        );

        requestId = data.requestId;

        var responseToAdapter = {
          status: "ok",
          errorMessage: "",
          challenge: data.publicKeyCredentialRequestOptions.challenge,
          timeout: 20000,
          rpId: data.publicKeyCredentialRequestOptions.rpId,
          allowCredentials: [],
          userVerification:
            data.publicKeyCredentialRequestOptions.userVerification,
        };

        res.header(response.headers);
        res.send(responseToAdapter);
      })
      .catch((error) => {
        res.send({
          status: "failed",
          errorMessage: "",
        });
      });
  });

  /**
   * Authenticator Assertion Response
   */
  app.post("/assertion/result", async (req, res) => {
    console.log(`Request @ /assertion/result`);

    delete req.body["rawId"];
    req.body["clientExtensionResults"] = {};

    var tr = JSON.stringify({ requestId: requestId, credential: req.body });

    var tokenResponse: any = JSON.parse(JSON.stringify(tr));

    var referer = `https://${isHost}/authenticationendpoint/fido2-auth
    .jsp?authenticators=FIDOAuthenticator%3ALOCAL&type=fido&sessionDataKey=${sessionDataKey}&data=${tr}`;

    axios
      .post(
        `https://${isHost}/commonauth`,
        querystring.stringify({
          sessionDataKey: sessionDataKey,
          tokenResponse: tr,
        }),
        {
          headers: {
            Connection: "keep-alive",
            Accept:
              "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization: `Basic ${auth}`,
            Referer: referer,
          },
        }
      )
      .then(async (response) => {
        if (response.request.path == "/pickup-dispatch/index.jsp") {
          res.send({
            status: "failed",
            errorMessage: "",
          });
        } else {
          res.send({
            status: "ok",
            errorMessage: "",
          });
        }
      })
      .catch((error) => {
        res.send({
          status: "failed",
          errorMessage: "",
        });
      });
  });
};

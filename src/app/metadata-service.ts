import express, { raw, response } from "express";
import bodyParser from "body-parser";
import cors from "cors";
import fs from "fs";
import { MetadataStatement } from "@simplewebauthn/server/dist/metadata/metadataService";
import fetch from "node-fetch";
const NodeCache = require("node-cache");
let config = require("./../../config.json");

export const statements: MetadataStatement[] = [];

import { MetadataService } from "@simplewebauthn/server";

const metaCache = new NodeCache();
const conformanceMetadataPath = config.conformanceMetadataPath;

export default async ({ app }: { app: express.Application }) => {
  /**
   * Health Check endpoints registration
   */
  app.get("/status/matadata-service", (req, res) => {
    res.status(200).end("Registration Connection Successful.");
  });
  app.head("/status/registration", (req, res) => {
    res.status(200).end();
  });

  app.use(cors());
  app.use(bodyParser.json());

  /**
   * Read the metadata statements
   */
  try {
    const conformanceMetadataFilenames = fs.readdirSync(
      conformanceMetadataPath
    );
    for (const statementPath of conformanceMetadataFilenames) {
      if (statementPath.endsWith(".json")) {
        const contents = fs.readFileSync(
        /**
        *ToDO address the OS based file path.
        */
          `${conformanceMetadataPath}/${statementPath}`,
          "utf-8"
        );
        statements.push(JSON.parse(contents));
      }
    }
    metaCache.set("statements", statements, 100000);
  } catch (error) {
    console.error(`${error.message}`);
  }

  /**
   * Initialize MetadataService with Conformance Testing-specific statements.
   * Only for Conformance testing.
   */
  fetch("https://mds.certinfra.fidoalliance.org/getEndpoints", {
    method: "POST",
    body: JSON.stringify({ endpoint: `https://localhost:4000` }),
    headers: { "Content-Type": "application/json" },
  })
    .then((resp) => resp.json())
    .then((json) => {
      const routes = json.result;
      const mdsServers = routes.map((url: string) => ({
        url,
        rootCertURL: "https://mds.certinfra.fidoalliance.org/pki/MDSROOT.crt",
        metadataURLSuffix: "",
      }));

      MetadataService.initialize({
        statements,
        mdsServers,
      });
    })
    .finally(() => {
      if (statements.length) {
        console.log(
          `Initializing metadata service with ${statements.length} local statements.`
        );
      }
      console.log("FIDO Conformance routes ready.");
    });
};
